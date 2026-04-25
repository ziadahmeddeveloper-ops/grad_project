import re
import math
from urllib.parse import urlparse
import pandas as pd


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update",
    "bank", "payment", "password", "signin", "confirm",
    "wallet", "crypto", "billing", "recover"
]

KNOWN_BRANDS = [
    "google", "facebook", "amazon", "microsoft",
    "paypal", "apple", "netflix", "bank"
]


def has_fake_brand_in_subdomain(domain: str) -> int:
    parts = domain.split(".")
    
  
    if len(parts) < 2:
        return 0

    main_domain = parts[-2]

 
    subdomains = parts[:-2]

    for brand in KNOWN_BRANDS:
        if brand in subdomains and brand != main_domain:
            return 1

    return 0

def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log2(p) for p in prob])


def is_ip(domain: str) -> int:
    pattern = r"^(?:\\d{1,3}\\.){3}\\d{1,3}$"
    return 1 if re.match(pattern, domain) else 0


def extract_url_features(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
       url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    full = url.lower()

    num_dots = url.count(".")
    num_hyphens = url.count("-")
    num_underscores = url.count("_")
    num_slashes = url.count("/")
    num_question = url.count("?")
    num_equal = url.count("=")
    num_at = url.count("@")
    num_ampersand = url.count("&")
    num_digits = sum(c.isdigit() for c in url)
    num_letters = sum(c.isalpha() for c in url)

    suspicious_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full)

    return {
        "url_length": len(url),
        "domain_length": len(domain),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_underscores": num_underscores,
        "num_slashes": num_slashes,
        "num_question": num_question,
        "num_equal": num_equal,
        "num_at": num_at,
        "num_ampersand": num_ampersand,
        "num_digits": num_digits,
        "num_letters": num_letters,
        "digit_ratio": num_digits / len(url) if len(url) else 0,
        "letter_ratio": num_letters / len(url) if len(url) else 0,
        "has_ip": is_ip(domain),
        "is_https": 1 if parsed.scheme == "https" else 0,
        "num_subdomains": max(domain.count(".") - 1, 0),
        "has_fake_brand_subdomain": has_fake_brand_in_subdomain(domain),
        "has_suspicious_keyword": 1 if suspicious_count > 0 else 0,
        "suspicious_keyword_count": suspicious_count,
        "entropy": shannon_entropy(url),
    }


def preprocess_url_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    if "url" not in df.columns:
        raise ValueError("Dataset must contain a 'url' column.")

    features_df = df["url"].apply(extract_url_features).apply(pd.Series)

    if "label" in df.columns:
        features_df["label"] = df["label"]

    return features_df