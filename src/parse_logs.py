import json
from pathlib import Path

import pandas as pd


def load_cloudtrail_json(file_path: str | Path) -> list[dict]:
    """Load CloudTrail-style JSON and return list of event records."""
    path = Path(file_path)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    records = payload.get("Records", [])
    if not isinstance(records, list):
        raise ValueError("CloudTrail JSON must contain a list under 'Records'.")

    return records


def normalize_records(records: list[dict]) -> pd.DataFrame:
    """Normalize CloudTrail records into a DataFrame with required fields."""
    rows = []
    for record in records:
        user_identity = record.get("userIdentity") or {}
        rows.append(
            {
                "eventName": record.get("eventName", "Unknown"),
                "eventSource": record.get("eventSource", "Unknown"),
                "eventTime": record.get("eventTime"),
                "userName": user_identity.get("userName", "Unknown"),
                "sourceIPAddress": record.get("sourceIPAddress", "Unknown"),
                "awsRegion": record.get("awsRegion", "Unknown"),
            }
        )

    return pd.DataFrame(rows)


def load_and_parse(file_path: str | Path) -> pd.DataFrame:
    """Convenience wrapper to load JSON and return a DataFrame."""
    records = load_cloudtrail_json(file_path)
    return normalize_records(records)
