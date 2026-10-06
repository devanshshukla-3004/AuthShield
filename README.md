# 🔐 AuthShield

> **Day 05 / 100 — Authentication Security & Brute-Force Detection Engine**

AuthShield is a defensive Python CLI that analyzes authentication logs and identifies suspicious authentication behavior using transparent, explainable detection rules.

## 🎯 What it detects

- Brute-force bursts
- Password spraying
- Failure → success sequences
- Repeated authentication failures
- Suspicious off-hours authentication
- High-risk source IPs
- Account-targeting patterns

## ⚙️ Detection pipeline

```text
Authentication Logs
        ↓
Schema Validation
        ↓
Timestamp Normalization
        ↓
Authentication Event Analysis
        ↓
Pattern Detection
        ↓
Risk / Severity Scoring
        ↓
Explainable Findings
        ↓
JSON Report
```

## 🚀 Quick start

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Linux / Kali Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

AuthShield uses only the Python standard library at runtime. `pytest` is used for automated tests.

## ▶️ Analyze the sample logs

```bash
python authshield.py analyze data/sample_auth.log
```

Write a JSON report:

```bash
python authshield.py analyze data/sample_auth.log --json reports/authshield-report.json
```

Show help:

```bash
python authshield.py --help
```

## 🧪 Run tests

```bash
pytest -q
```

## 📄 Input format

CSV logs must contain:

```text
timestamp,username,source_ip,event
```

Supported events:

```text
FAILURE
SUCCESS
```

Example:

```csv
timestamp,username,source_ip,event
2026-10-05T21:00:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:01:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:02:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:03:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:04:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:05:00Z,alice,10.0.0.20,SUCCESS
```

## 🛡️ Detection rules

| Rule | Trigger | Severity | Base risk |
|---|---|---:|---:|
| Brute-force burst | 5+ failures from one IP against one account within 10 min | HIGH | 75 |
| Password spraying | 5+ distinct accounts targeted by one IP within 10 min | HIGH | 75 |
| Failure → success | 3+ failures followed by success for same account/IP within 15 min | HIGH | 80 |
| Repeated failures | 3+ failures from one IP within 10 min | MEDIUM | 40 |
| Off-hours authentication | Event between 23:00–06:00 UTC | LOW | 15 |

Every finding includes its rule, evidence, affected account/IP, time window, severity, and risk score.

## 🧠 Design principles

- **Explainable:** every alert contains the evidence that triggered it.
- **Deterministic:** identical input produces identical findings.
- **Offline-first:** no network access is required.
- **Defensive:** the tool analyzes logs; it does not perform authentication attacks.
- **Reproducible:** sample data and automated tests are included.

## ⚠️ Responsible use

Use AuthShield with authentication logs from systems you own or are authorized to monitor. The included dataset is synthetic.

AuthShield does not attempt passwords, authenticate to remote systems, or interact with source IP addresses.

## 📁 Project structure

```text
AuthShield/
├── authshield.py
├── authshield/
│   ├── __init__.py
│   ├── models.py
│   ├── parser.py
│   ├── detector.py
│   ├── scorer.py
│   └── reporter.py
├── data/
│   └── sample_auth.log
├── reports/
│   └── .gitkeep
├── tests/
│   ├── test_parser.py
│   └── test_detector.py
├── requirements.txt
├── .gitignore
└── README.md
```

**Day 05 complete. 95 projects to go. 🚀**
