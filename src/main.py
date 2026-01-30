from __future__ import annotations

import argparse
from pathlib import Path

from detect_anomalies import score_anomalies, train_isolation_forest
from explain_risk import apply_risk_scoring
from feature_engineering import build_feature_set, get_feature_columns
from parse_logs import load_and_parse


def run_pipeline(log_path: Path) -> None:
    df = load_and_parse(log_path)
    df = build_feature_set(df)

    feature_columns = get_feature_columns()
    model = train_isolation_forest(df, feature_columns)
    df = score_anomalies(df, model, feature_columns)
    df = apply_risk_scoring(df)

    alerts = df.sort_values(["risk_score", "anomaly_score"], ascending=False)
    for _, row in alerts.iterrows():
        summary = (
            f"{row['eventName']} via {row['eventSource']} "
            f"by {row['userName']} from {row['sourceIPAddress']} "
            f"in {row['awsRegion']} at {row['eventTime']}"
        )
        print(f"[{row['risk_level']}] {summary}")
        print(f"  Reason: {row['reason']}")
        print(f"  Action: {row['suggested_action']}")
        print("-" * 60)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CloudTrail anomaly detection demo.")
    parser.add_argument(
        "--log-path",
        type=Path,
        default=Path("data/sample_cloudtrail_logs.json"),
        help="Path to CloudTrail JSON logs.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_pipeline(args.log_path)
