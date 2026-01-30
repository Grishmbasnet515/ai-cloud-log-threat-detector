# AI Cloud Log Threat Detector

An AI-powered cloud security tool that analyzes AWS CloudTrail logs (sample/simulated data only) to detect anomalous and suspicious activity using machine learning, with SOC-style risk scoring and explainable alerts.

## Project Overview
- **Goal:** Help students learn how cloud logs can be turned into security signals.
- **Data:** Uses only AWS CloudTrail sample or simulated logs.
- **Approach:** Feature engineering + Isolation Forest + rule-based risk scoring.

## Architecture
1. **Parse logs** from JSON into a normalized DataFrame.
2. **Engineer features** like hour of activity, per-user frequency, unique IPs, and sensitive API flags.
3. **Detect anomalies** using Isolation Forest (unsupervised ML).
4. **Score risk** and generate SOC-style alerts with clear reasons and actions.

## Detection Logic
Key signals used:
- Activity at unusual hours
- User behavior frequency spikes
- Multiple source IPs per user
- Sensitive API calls (IAM, policy changes, CloudTrail logging changes)

Isolation Forest provides an anomaly score, and a rule-based layer converts that into **LOW / MEDIUM / HIGH** risk.

## Sample Output
```
ALERT-0001 | Risk: HIGH | Score: 5 | Anomaly: 0.1821
Event: DeleteTrail via cloudtrail.amazonaws.com by dave from 192.0.2.99 in us-west-2 at 2026-01-29 03:12:18+00:00
Reason: High anomaly score; Sensitive API call; Unusual hour of activity
Suggested Action: Review IAM and security changes immediately; validate user intent; consider disabling credentials.
--------------------------------------------------------------------------------
```

## How to Run
```
python src/main.py --log-path data/sample_cloudtrail_logs.json
```

## Legal & Ethical Disclaimer
This project uses publicly available AWS CloudTrail sample logs and simulated data for educational and defensive security purposes only.
