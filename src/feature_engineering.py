import pandas as pd


SENSITIVE_EVENT_NAMES = {
    "CreateUser",
    "DeleteUserPolicy",
    "PutRolePolicy",
    "AttachUserPolicy",
    "CreateAccessKey",
    "UpdateAssumeRolePolicy",
    "DeleteTrail",
    "StopLogging",
    "AuthorizeSecurityGroupIngress",
    "RunInstances",
}

SENSITIVE_EVENT_SOURCES = {
    "iam.amazonaws.com",
    "cloudtrail.amazonaws.com",
}


def add_time_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce", utc=True)
    df["event_hour"] = df["eventTime"].dt.hour.fillna(-1).astype(int)
    return df


def add_user_aggregate_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["user_event_count"] = df.groupby("userName")["eventName"].transform("count")
    df["user_unique_ip_count"] = df.groupby("userName")["sourceIPAddress"].transform("nunique")
    return df


def add_sensitive_api_flag(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["sensitive_api_call"] = (
        df["eventName"].isin(SENSITIVE_EVENT_NAMES)
        | df["eventSource"].isin(SENSITIVE_EVENT_SOURCES)
        | df["eventName"].str.contains("Policy", na=False)
    ).astype(int)
    return df


def build_feature_set(df: pd.DataFrame) -> pd.DataFrame:
    df = add_time_features(df)
    df = add_user_aggregate_features(df)
    df = add_sensitive_api_flag(df)
    return df


def get_feature_columns() -> list[str]:
    return [
        "event_hour",
        "user_event_count",
        "user_unique_ip_count",
        "sensitive_api_call",
    ]
