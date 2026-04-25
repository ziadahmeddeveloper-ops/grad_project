import pandas as pd
import numpy as np

DROP_COLS = ["Flow ID", "Source IP", "Destination IP", "Timestamp", "Label"]

def preprocess_network_input(data: dict, expected_features: list[str]) -> pd.DataFrame:
    df = pd.DataFrame([data])
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns], errors="ignore")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.apply(pd.to_numeric, errors="coerce")


    df = df.fillna(df.mean(numeric_only=True))
    df = df.fillna(0)

    for col in expected_features:
        if col not in df.columns:
            df[col] = 0

    return df[expected_features]
