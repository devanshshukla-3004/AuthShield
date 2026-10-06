from collections import defaultdict
from datetime import timedelta

from .models import AuthEvent, Finding
from .scorer import severity_for

WINDOW = timedelta(minutes=10)
SEQUENCE_WINDOW = timedelta(minutes=15)

def _finding(rule, score, source_ip, username, start, end, evidence):
    return Finding(rule, severity_for(score), score, source_ip, username, start, end, evidence)

def detect_bruteforce(events):
    grouped = defaultdict(list)
    for event in events:
        if event.event == "FAILURE":
            grouped[(event.source_ip, event.username)].append(event)

    findings = []
    for (ip, user), failures in grouped.items():
        for i, start in enumerate(failures):
            j = i
            while j + 1 < len(failures) and failures[j + 1].timestamp - start.timestamp <= WINDOW:
                j += 1
            count = j - i + 1
            if count >= 5:
                end = failures[j]
                findings.append(_finding(
                    "Brute-force burst", 75, ip, user, start.timestamp, end.timestamp,
                    f"{count} failures within {int((end.timestamp-start.timestamp).total_seconds()/60)} minutes"
                ))
                break
    return findings

def detect_password_spraying(events):
    grouped = defaultdict(list)
    for event in events:
        if event.event == "FAILURE":
            grouped[event.source_ip].append(event)

    findings = []
    for ip, failures in grouped.items():
        for i, start in enumerate(failures):
            users = {start.username}
            j = i + 1
            while j < len(failures) and failures[j].timestamp - start.timestamp <= WINDOW:
                users.add(failures[j].username)
                j += 1
            if len(users) >= 5:
                end = failures[j - 1]
                findings.append(_finding(
                    "Password spraying", 75, ip, None, start.timestamp, end.timestamp,
                    f"{len(users)} distinct accounts targeted within {int((end.timestamp-start.timestamp).total_seconds()/60)} minutes"
                ))
                break
    return findings

def detect_failure_success(events):
    grouped = defaultdict(list)
    for event in events:
        grouped[(event.source_ip, event.username)].append(event)

    findings = []
    for (ip, user), sequence in grouped.items():
        failures = []
        for event in sequence:
            if event.event == "FAILURE":
                failures.append(event)
            elif event.event == "SUCCESS":
                recent = [f for f in failures if event.timestamp - f.timestamp <= SEQUENCE_WINDOW]
                if len(recent) >= 3:
                    findings.append(_finding(
                        "Failure → success", 80, ip, user, recent[0].timestamp, event.timestamp,
                        f"{len(recent)} failures followed by a success within 15 minutes"
                    ))
                    break
    return findings

def detect_repeated_failures(events):
    grouped = defaultdict(list)
    for event in events:
        if event.event == "FAILURE":
            grouped[event.source_ip].append(event)

    findings = []
    for ip, failures in grouped.items():
        for i, start in enumerate(failures):
            recent = [f for f in failures[i:] if f.timestamp - start.timestamp <= WINDOW]
            if len(recent) >= 3:
                end = recent[-1]
                findings.append(_finding(
                    "Repeated failures", 40, ip, None, start.timestamp, end.timestamp,
                    f"{len(recent)} failures from one source within 10 minutes"
                ))
                break
    return findings

def detect_off_hours(events):
    findings = []
    for event in events:
        if event.timestamp.hour >= 23 or event.timestamp.hour < 6:
            findings.append(_finding(
                "Off-hours authentication", 15, event.source_ip, event.username,
                event.timestamp, event.timestamp,
                "Authentication occurred between 23:00 and 06:00 UTC"
            ))
    return findings

def detect_all(events):
    findings = (
        detect_bruteforce(events)
        + detect_password_spraying(events)
        + detect_failure_success(events)
        + detect_repeated_failures(events)
        + detect_off_hours(events)
    )
    return sorted(findings, key=lambda f: (-f.risk_score, f.first_seen, f.rule, f.source_ip, f.username or ""))

def summarize_findings(findings):
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        counts[finding.severity] += 1
    return {
        "total": len(findings),
        "high": counts["HIGH"],
        "medium": counts["MEDIUM"],
        "low": counts["LOW"],
        "average_risk": round(sum(f.risk_score for f in findings) / len(findings), 1) if findings else 0.0,
    }
