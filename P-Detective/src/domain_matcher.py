import os
from typing import List, Tuple, Optional

def load_legitimate_domains(path: str = "data/tranco_L5NL4.csv") -> List[str]:
    """
    Load legitimate domains from a text file.
    Each line should be one domain (e.g. instagram.com).
    Lines starting with '#' are ignored as comments.
    """
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        domains = [
            line.strip().lower()
            for line in f
            if line.strip() and not line.startswith("#")
        ]
    return domains

def load_phishing_domains(path: str = "data/phishing_domains.txt") -> List[str]:
    """
    Load known phishing domains from a text file.
    Each line should be one domain (e.g. chinabswl.com).
    Lines starting with '#' are ignored as comments.
    """
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [
            line.strip().lower()
            for line in f
            if line.strip() and not line.startswith("#")
        ]


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract the domain (hostname) from a URL.
    Example:
      "https://instagram.com/some/path" -> "instagram.com"
      "http://1nstagram.com" -> "1nstagram.com"
    """
    url = url.lower().strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    try:
        # protocol://domain[:port]/...
        after_proto = url.split("://", 1)[1]
        domain_part = after_proto.split("/", 1)[0]

        # Remove any user@ (e.g. user@instagram.com)
        domain_part = domain_part.split("@", 1)[-1]

        # Remove port (e.g. instagram.com:8080)
        domain_part = domain_part.split(":", 1)[0]

        return domain_part.lower()
    except Exception:
        return None


def is_simple_lookalike(domain: str, legitimate: str) -> bool:
    """
    Simple lookalike check:
    - Same base length-ish
    - 1 character difference (e.g. 1nstagram vs instagram)
    - No extra words before/after (e.g. instagram-login.com is not simple lookalike)
    """
    if domain == legitimate:
        return False

    # Only compare if they are similar length
    if abs(len(domain) - len(legitimate)) > 2:
        return False

    # Count character differences
    diff = 0
    min_len = min(len(domain), len(legitimate))
    for i in range(min_len):
        if domain[i] != legitimate[i]:
            diff += 1
            if diff > 1:
                return False

    # If one is longer, count extra chars as differences
    diff += abs(len(domain) - len(legitimate))
    return diff == 1


def check_domain_legitimacy(url: str, legitimate_domains: List[str]) -> Tuple[bool, List[str]]:
    """
    Check if a URL's domain is legitimate, a lookalike, or in a phishing list.
    """
    domain = extract_domain_from_url(url)
    if not domain:
        return False, ["Could not extract domain from URL"]

    reasons = []

    # 1. Check phishing blacklist first
    phishing_domains = load_phishing_domains(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "data/phishing_domains.txt")
    )
    if domain in phishing_domains:
        return False, ["Domain is in known phishing list"]

    # 2. Exact match with legitimate domains
    if domain in legitimate_domains:
        return True, ["Domain matches a known legitimate site"]

    # 3. Lookalike check
    for legit in legitimate_domains:
        if is_simple_lookalike(domain, legit):
            reasons.append(
                f"Domain '{domain}' looks like known legitimate site '{legit}' (possible impersonation)"
            )
            return False, reasons

    # 4. Unknown domain
    return False, ["Domain is not in known legitimate list (unknown site)"]