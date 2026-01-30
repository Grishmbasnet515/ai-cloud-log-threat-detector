from __future__ import annotations

import pandas as pd
from sklearn.ensemble import IsolationForest


def train_isolation_forest(
    df: pd.DataFrame,
    feature_columns: list[str],
    contamination: float = 0.15,
    random_state: int = 42,
) -> IsolationForest:
    features = df[feature_columns].fillna(0)
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(features)
    return model


def score_anomalies(
    df: pd.DataFrame,
    model: IsolationForest,
    feature_columns: list[str],
) -> pd.DataFrame:
    df = df.copy()
    features = df[feature_columns].fillna(0)

    decision_scores = model.decision_function(features)
    predictions = model.predict(features)

    df["anomaly_score"] = (-decision_scores).round(4)
    df["is_anomaly"] = (predictions == -1).astype(int)
    return df
