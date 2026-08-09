import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS=["login","verify","update","secure","account","bank","paypal","signin","confirm"]

def extract_features(url:str):
    parsed=urlparse(url)
    hostname=parsed.hostname or ""
    https=parsed.scheme=="https"
    url_length=len(url)
    has_ip=bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}",hostname))
    has_at_symbol="@" in url
    dot_count=hostname.count(".")
    hyphen_count=hostname.count("-")
    suspicious_keywords=sum(k in url.lower() for k in SUSPICIOUS_KEYWORDS)
    return {
        "https":https,
        "url_length":url_length,
        "has_ip":has_ip,
        "has_at_symbol":has_at_symbol,
        "dot_count":dot_count,
        "hyphen_count":hyphen_count,
        "suspicious_keywords":suspicious_keywords,
    }
