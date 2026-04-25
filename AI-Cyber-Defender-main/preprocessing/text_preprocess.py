import pandas as pd

def preprocess_text_input(data: dict) -> list[str]:
    df = pd.DataFrame([data])
    row = df.iloc[0]
    parts = []
    for col, value in row.items():
        if pd.isna(value):
            continue
        parts.append(f"{col}={value}")
    return [" | ".join(parts)]
