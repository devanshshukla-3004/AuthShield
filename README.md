# 🔐 AuthShield

<p align="center">
  <strong>Authentication Security & Brute-Force Detection Engine</strong><br/>
  <em>Day 05 / 100 — 100 Days • 100 Cybersecurity Projects</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Day-05%2F100-111827?style=for-the-badge" alt="Day 05 of 100"/>
  <img src="https://img.shields.io/badge/Security-Defensive-0f766e?style=for-the-badge" alt="Defensive Security"/>
  <img src="https://img.shields.io/badge/Python-3.x-2563eb?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Tests-9%20passed-16a34a?style=for-the-badge" alt="9 tests passed"/>
</p>

AuthShield is a **defensive, offline-first Python CLI** for analyzing authentication logs and identifying suspicious login behavior through deterministic, transparent detection rules.

It works like a compact SOC-style analytics engine: **parse → detect → score → explain → report**.

---

## ✦ What It Detects

- 🔴 Brute-force bursts
- 🔴 Password spraying
- 🔴 Failure → success sequences
- 🟠 Repeated authentication failures
- 🟢 Suspicious off-hours authentication
- 🎯 Account-targeting patterns
- 🌐 High-risk source activity

---

## 🧭 Detection Pipeline

~~~text
┌─────────────────────┐
│ Authentication Logs │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│ Schema Validation   │
│ & Parsing           │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│ Event Normalization │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│ Pattern Detection   │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│ Risk & Severity     │
│ Scoring             │
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│ Explainable Findings│
└──────────┬──────────┘
           ↓
┌─────────────────────┐
│ JSON Security Report│
└─────────────────────┘
~~~

---

## 🛡️ Detection Rules

| Detection | Trigger | Severity | Risk |
|---|:---|:---:|---:|
| **Brute-force burst** | 5+ failures from one IP against one account within 10 min | 🔴 HIGH | 75 |
| **Password spraying** | 5+ distinct accounts targeted by one IP within 10 min | 🔴 HIGH | 75 |
| **Failure → success** | 3+ failures followed by success for the same account/IP within 15 min | 🔴 HIGH | 80 |
| **Repeated failures** | 3+ failures from one IP within 10 min | 🟠 MEDIUM | 40 |
| **Off-hours authentication** | Authentication between 23:00–06:00 UTC | 🟢 LOW | 15 |

Every finding includes the **rule, evidence, source IP, affected account, time window, severity, and risk score**.

---

## ⚡ Quick Start

### Windows PowerShell

~~~powershell
git clone https://github.com/devanshshukla-3004/AuthShield.git
cd AuthShield

py -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
~~~

If PowerShell blocks virtual-environment activation:

~~~powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
~~~

### Linux / Kali Linux / macOS

~~~bash
git clone https://github.com/devanshshukla-3004/AuthShield.git
cd AuthShield

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install -r requirements.txt
~~~

> **Runtime:** AuthShield uses only the Python standard library. Pytest is included for automated testing.

---

## ▶️ Analyze Authentication Logs

Run the included synthetic dataset:

~~~bash
python authshield.py analyze data/sample_auth.log
~~~

Export findings as JSON:

~~~bash
python authshield.py analyze data/sample_auth.log --json reports/authshield-report.json
~~~

Display CLI help:

~~~bash
python authshield.py --help
~~~

---

## 📊 Verified Run

The repository was **verified locally after cloning the GitHub repository**.

### Automated tests

~~~text
.........                                                                 [100%]
9 passed in 0.20s
~~~

### Sample analysis

~~~text
Events analyzed : 13
Findings        : 6
High            : 3
Medium          : 2
Low             : 1
Average risk    : 54.2 / 100
~~~

Detected:

~~~text
[HIGH]   Failure → success          Risk 80
[HIGH]   Brute-force burst          Risk 75
[HIGH]   Password spraying          Risk 75
[MEDIUM] Repeated failures          Risk 40
[MEDIUM] Repeated failures          Risk 40
[LOW]    Off-hours authentication   Risk 15
~~~

JSON report:

~~~text
reports/authshield-report.json
~~~

---

## 📄 Input Format

Authentication logs must contain:

~~~text
timestamp,username,source_ip,event
~~~

Supported events:

~~~text
FAILURE
SUCCESS
~~~

Example:

~~~csv
timestamp,username,source_ip,event
2026-10-05T21:00:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:01:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:02:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:03:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:04:00Z,alice,10.0.0.20,FAILURE
2026-10-05T21:05:00Z,alice,10.0.0.20,SUCCESS
~~~

---

## 🧪 Testing

Run the complete test suite:

~~~bash
python -m pytest -q
~~~

**Verified result: 9 tests passed.**

The tests cover authentication-log parsing and detection behavior.

---

## 🧠 Engineering Principles

| Principle | Implementation |
|---|---|
| **Explainable** | Every alert contains supporting evidence |
| **Deterministic** | Identical input produces identical findings |
| **Offline-first** | No internet, API, or database required |
| **Defensive** | No password attempts or remote authentication |
| **Machine-readable** | JSON output for downstream tooling |
| **Reproducible** | Synthetic data + automated tests included |

---

## 🏗️ Project Structure

~~~text
AuthShield/
│
├── authshield.py              # CLI entry point
│
├── authshield/
│   ├── __init__.py
│   ├── models.py              # Data models
│   ├── parser.py              # Log parsing & validation
│   ├── detector.py            # Detection rules
│   ├── scorer.py              # Risk / severity logic
│   └── reporter.py            # Human & JSON reporting
│
├── data/
│   └── sample_auth.log        # Synthetic authentication dataset
│
├── reports/
│   └── .gitkeep
│
├── tests/
│   ├── test_parser.py
│   └── test_detector.py
│
├── requirements.txt
├── .gitignore
└── README.md
~~~

---

## 🔍 Security Finding Model

Each finding is structured around:

~~~text
Rule
 ├── Detection type
 ├── Source IP
 ├── Account / target
 ├── Time window
 ├── Supporting evidence
 ├── Severity
 └── Risk score
~~~

This makes the output useful for **SOC investigation, authentication monitoring, security analytics, and detection-engineering practice**.

---

## 🔐 Responsible Use

Use AuthShield only with authentication telemetry from systems you **own or are explicitly authorized to monitor**.

The included dataset is synthetic.

AuthShield:

- does not attempt passwords
- does not authenticate to remote systems
- does not scan source IPs
- does not make network connections
- does not exploit authentication services

---

## 📚 Challenge Context

**AuthShield is Day 05 of my 100 Days • 100 Cybersecurity Projects challenge.**

The challenge progresses through:

**Security Foundations → Network Security → Identity → Application Security → Malware & Forensics → SOC → Cloud Security → Specialized Security → AI/ML Security → Flagship Cybersecurity Systems**

---

## 📌 Project Status

| Area | Status |
|---|:---:|
| Core analyzer | ✅ Complete |
| Detection rules | ✅ Complete |
| CLI | ✅ Complete |
| JSON reporting | ✅ Complete |
| Automated tests | ✅ 9/9 passed |
| Sample dataset | ✅ Included |
| Local verification | ✅ Verified |
| Network access required | ❌ No |

### Day 05 / 100 — Complete

**95 cybersecurity projects remaining.**

---

<p align="center">
  Built with Python • Defensive Security • Detection Engineering
</p>
