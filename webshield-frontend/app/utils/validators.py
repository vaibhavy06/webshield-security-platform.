import re
from urllib.parse import urlparse

def validate_url(url: str) -> bool:
    """
    Validate if a string is a properly formatted URL.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def normalize_url(url: str) -> str:
    """
    Add https:// if missing.
    """
    if not url.startswith(('http://', 'https://')):
        return f"https://{url}"
    return url
