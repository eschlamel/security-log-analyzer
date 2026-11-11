# Security Log Analyzer & Threat Detection Dashboard

A beginner-friendly cybersecurity portfolio project that analyzes **synthetic** authentication logs for suspicious activity.

## Goals
- Parse login event data using Python
- Detect repeated failed logins from one IP address
- Save and analyze alerts; later add SQLite and Power BI
- Document findings in a reproducible GitHub repository

## Quick start
Requires Python 3.10+; no third-party packages.

```bash
python src/generate_sample_logs.py
python src/analyze_logs.py
python -m unittest discover -s tests
```

The generator creates `data/sample_auth_logs.csv` using fictional example IP ranges. The analyzer prints alerts when an IP has at least **5 failed logins within 5 minutes**.

## Repository layout
- `src/generate_sample_logs.py`: create safe synthetic authentication events
- `src/analyze_logs.py`: detect failed-login bursts
- `tests/test_analyze_logs.py`: basic automated test
- `data/`: generated synthetic events (no real credentials or personal data)
- `docs/`: screenshots and findings as the project grows

## Roadmap
1. Generate and inspect synthetic login events
2. Detect failed-login bursts and explain false positives
3. Store events and alerts in SQLite
4. Add detection for off-hours logins
5. Create a Power BI dashboard
6. Document testing, limitations, and findings

## Safety
Only use synthetic data or logs you are authorized to analyze. Do not publish real user information, secrets, or raw organizational logs.
