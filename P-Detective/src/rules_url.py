import re
import yaml
from urllib.parse import urlparse
from typing import Tuple, List

from src.domain_matcher import load_legitimate_domains, check_domain_legitimacy


def load_config(path: str = "config/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def apply_url_rules_with_legitimate(url: str, config: dict) -> Tuple[bool, List[str]]:
    """
    Check URL legitimacy using known legitimate domains.
    If the domain matches a known legitimate site, it returns (False, reasons)
    meaning "not phishing by rules" and overrides other rules.

    Returns:
        rule_pred: bool
            True  -> rules indicate phishing
            False -> rules indicate legitimate (or overridden by legitimate domain)
        reasons: list[str]
            Human-readable reasons
    """
    legitimate_domains = load_legitimate_domains(
        config.get("legitimate_domains_path", "config/legitimate_domains.txt")
    )

    is_legit, reasons = check_domain_legitimacy(url, legitimate_domains)

    if is_legit:
        # Domain is known legitimate: override other rules
        return False, ["Domain matches a known legitimate site (overriding other rules)"]

    # Otherwise, fall back to old rules
    return apply_url_rules(url, config)


def apply_url_rules(url: str, config: dict) -> Tuple[bool, List[str]]:
    reasons = []

    # No HTTPS
    if not url.lower().startswith("https"):
        reasons.append("URL does not use HTTPS")

    # Very long URL
    if len(url) > 75:
        reasons.append("URL is very long")

    # Parse domain
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        domain = url

    # IP-based domain
    if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        reasons.append("Domain looks like an IP address")

    # Suspicious words
    domain_lower = domain.lower()
    for kw in config["suspicious_url_keywords"]:
        if kw.lower() in domain_lower:
            reasons.append(f"Domain contains suspicious word: '{kw}'")

    # Many dots
    if domain.count(".") > 3:
        reasons.append("Too many dots in domain")

    is_phishing = len(reasons) > 0
    return is_phishing, reasons