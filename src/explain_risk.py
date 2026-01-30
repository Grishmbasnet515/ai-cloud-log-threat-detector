from __future__ import annotations

import pandas as pd


def _build_reason(row: pd.Series) -> str:
    reasons = []
    if row["anomaly_score"] >= 0.15:
        reasons.append("High anomaly score")
    elif row["anomaly_score"] >= 0.05:
        reasons.append("Elevated anomaly score")

    if row.get("sensitive_api_call", 0) == 1:
        reasons.append("Sensitive API call")

    if row.get("user_unique_ip_count", 0) >= 3:
        reasons.append("Multiple source IPs for user")

    hour = row.get("event_hour", -1)
    if hour in list(range(0, 6)) or hour >= 22:
        reasons.append("Unusual hour of activity")

    return "; ".join(reasons) if reasons else "Baseline activity"


def _suggest_action(risk_level: str) -> str:
    if risk_level == "HIGH":
        return "Review IAM and security changes immediately; validate user intent; consider disabling credentials."
    if risk_level == "MEDIUM":
        return "Investigate activity with the user and review recent changes."
    return "Monitor and continue baseline tracking."


def apply_risk_scoring(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    risk_scores = []
    for _, row in df.iterrows():
        score = 0
        if row["anomaly_score"] >= 0.15:
            score += 2
        elif row["anomaly_score"] >= 0.05:
            score += 1

        if row.get("sensitive_api_call", 0) == 1:
            score += 2

        if row.get("user_unique_ip_count", 0) >= 3:
            score += 1

        hour = row.get("event_hour", -1)
        if hour in list(range(0, 6)) or hour >= 22:
            score += 1

        risk_scores.append(score)

    df["risk_score"] = risk_scores

    def _risk_label(score: int) -> str:
        if score >= 4:
            return "HIGH"
        if score >= 2:
            return "MEDIUM"
        return "LOW"

    df["risk_level"] = df["risk_score"].apply(_risk_label)
    df["reason"] = df.apply(_build_reason, axis=1)
    df["suggested_action"] = df["risk_level"].apply(_suggest_action)
    return df
