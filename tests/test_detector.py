from authshield.detector import (
    detect_all, detect_bruteforce, detect_failure_success,
    detect_password_spraying, detect_repeated_failures,
)
from authshield.parser import parse_auth_log

def test_bruteforce_detected():
    assert any(f.rule == "Brute-force burst" for f in detect_bruteforce(parse_auth_log("data/sample_auth.log")))

def test_password_spraying_detected():
    assert any(f.rule == "Password spraying" for f in detect_password_spraying(parse_auth_log("data/sample_auth.log")))

def test_failure_success_detected():
    assert any(f.rule == "Failure → success" for f in detect_failure_success(parse_auth_log("data/sample_auth.log")))

def test_repeated_failures_detected():
    assert any(f.rule == "Repeated failures" for f in detect_repeated_failures(parse_auth_log("data/sample_auth.log")))

def test_all_findings_have_explainable_evidence():
    findings = detect_all(parse_auth_log("data/sample_auth.log"))
    assert findings
    assert all(f.evidence for f in findings)
    assert all(0 <= f.risk_score <= 100 for f in findings)

def test_clean_dataset_has_no_findings(tmp_path):
    path = tmp_path / "clean.csv"
    path.write_text(
        "timestamp,username,source_ip,event\n"
        "2026-10-05T10:00:00Z,alice,10.0.0.1,SUCCESS\n"
        "2026-10-05T10:30:00Z,bob,10.0.0.2,SUCCESS\n",
        encoding="utf-8",
    )
    assert detect_all(parse_auth_log(path)) == []
