import json
from pathlib import Path
import pandas as pd

def read_any_file(path: Path) -> pd.DataFrame:
    suffix = path.suffix.lower()

    if suffix == ".csv":
        return pd.read_csv(path, low_memory=False)

    if suffix in {".json", ".jsonl", ".ndjson"}:
        
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                obj = json.load(f)
            return pd.DataFrame(obj if isinstance(obj, list) else [obj])
        except Exception:
            pass

        
        rows = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue

        if rows:
            return pd.DataFrame(rows)

        raise ValueError(f"Could not parse JSON/JSONL file: {path}")

    raise ValueError(f"Unsupported file type: {path}")

def build_text_from_row(row: pd.Series, exclude_cols=None) -> str:
    exclude_cols = set(exclude_cols or [])
    parts = []
    for col, value in row.items():
        if col in exclude_cols or pd.isna(value):
            continue
        parts.append(f"{col}={value}")
    return " | ".join(parts)