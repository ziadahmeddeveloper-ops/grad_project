import re
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]
    return df


def basic_log_preprocess(df: pd.DataFrame, timestamp_col: str = "timestamp") -> pd.DataFrame:
    df = clean_column_names(df)
    if timestamp_col in df.columns:
        df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors="coerce")
        df["hour"] = df[timestamp_col].dt.hour.fillna(0)
        df["dayofweek"] = df[timestamp_col].dt.dayofweek.fillna(0)
        df["day"] = df[timestamp_col].dt.day.fillna(0)
    return df


def add_text_length_features(df: pd.DataFrame, candidate_cols=None) -> pd.DataFrame:
    df = df.copy()
    candidate_cols = candidate_cols or []
    for col in candidate_cols:
        if col in df.columns:
            df[f"{col}_len"] = df[col].astype(str).str.len().fillna(0)
            df[f"{col}_digit_count"] = df[col].astype(str).str.count(r"\d").fillna(0)
            df[f"{col}_special_count"] = df[col].astype(str).str.count(r"[^A-Za-z0-9]").fillna(0)
    return df


def fill_numeric(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    num_cols = df.select_dtypes(include=["number"]).columns
    df[num_cols] = df[num_cols].fillna(0)
    return df


def encode_categoricals(df: pd.DataFrame, max_unique: int = 100):
    df = df.copy()
    encoders = {}
    for col in df.select_dtypes(include=["object"]).columns:
        if df[col].nunique(dropna=False) <= max_unique:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            encoders[col] = le
    return df, encoders


def keep_or_create_columns(df: pd.DataFrame, feature_cols: list[str]) -> pd.DataFrame:
    df = df.copy()
    for col in feature_cols:
        if col not in df.columns:
            df[col] = 0
    return df


def scale_features(df: pd.DataFrame, feature_cols: list[str]):
    scaler = StandardScaler()
    X = scaler.fit_transform(df[feature_cols])
    return X, scaler


def create_sequences(data: np.ndarray, sequence_length: int = 10) -> np.ndarray:
    sequences = []
    for i in range(len(data) - sequence_length + 1):
        sequences.append(data[i:i + sequence_length])
    return np.array(sequences)
