import json
from pathlib import Path

from .detector import summarize_findings

def build_report(events, findings):
    return {
        "tool": "AuthShield",
        "version": "1.0.0",
        "summary": {"events_analyzed": len(events), **summarize_findings(findings)},
        "findings": [finding.to_dict() for finding in findings],
    }

def write_json(report, path):
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")

def render_terminal(events, findings):
    summary = summarize_findings(findings)
    lines = [
        "AuthShield v1.0 | Authentication Security Analyzer", "",
        f"Events analyzed : {len(events)}",
        f"Findings        : {summary['total']}",
        f"High            : {summary['high']}",
        f"Medium          : {summary['medium']}",
        f"Low             : {summary['low']}",
        f"Average risk    : {summary['average_risk']} / 100", "",
    ]
    for f in findings:
        lines += [
            f"[{f.severity}] {f.rule}",
            f"Source          : {f.source_ip}",
            f"Account         : {f.username or 'multiple'}",
            f"Risk            : {f.risk_score}",
            f"Evidence        : {f.evidence}", "",
        ]
    return "\n".join(lines).rstrip()
