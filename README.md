#  SSH Brute-Force Detector (Log Analyzer)

##  Overview
This project simulates a basic SOC monitoring task by analyzing SSH authentication logs and detecting repeated failed login attempts that may indicate brute-force attacks.

It extracts IP addresses from log entries, counts failed attempts, flags suspicious IPs using a configurable threshold, and exports a CSV report.

---

##  Features
- Detects repeated SSH failed logins per IP
- Tracks successful logins per IP
- Configurable alert threshold
- Exports results to a CSV report

---

##  Tech Stack
- Python 3
- Regex log parsing
- CSV reporting

---

##  Project Structure
├── ssh_bruteforce_detector.py
├── sample_auth.log
└── README.md


---

##  How to Run

 1) Use the sample log
```bash
python ssh_bruteforce_detector.py

2) Use real Linux auth logs (optional)

On Linux, set this in ssh_bruteforce_detector.py:

LOG_FILE = "/var/log/auth.log"

Then run: python ssh_bruteforce_detector.py



---
