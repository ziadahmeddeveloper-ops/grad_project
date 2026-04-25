import re
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking", "confirm",
    "password", "signin", "reset", "free", "bonus", "gift", "wallet"
]

def extract_url_features(url: str) -> dict:
    url = str(url)
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "count_dots": url.count("."),
        "count_hyphen": url.count("-"),
        "count_at": url.count("@"),
        "count_question": url.count("?"),
        "count_percent": url.count("%"),
        "count_equal": url.count("="),
        "count_http": url.lower().count("http"),
        "count_https": url.lower().count("https"),
        "count_www": url.lower().count("www"),
        "count_digits": sum(ch.isdigit() for ch in url),
        "count_letters": sum(ch.isalpha() for ch in url),
        "has_ip": int(bool(re.search(r"(\d{1,3}\.){3}\d{1,3}", hostname))),
        "has_suspicious_keyword": int(any(k in url.lower() for k in SUSPICIOUS_KEYWORDS)),
        "uses_shortener": int(any(s in hostname.lower() for s in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"])),
        "subdomain_length": len(ext.subdomain),
        "domain_length": len(ext.domain),
        "suffix_length": len(ext.suffix),
        "is_https": int(parsed.scheme.lower() == "https")
    }
    return features