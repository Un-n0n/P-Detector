import re
import yaml

def load_config(path="config/config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)

def apply_email_rules(email_text, config):
    reasons = []
    text_lower = email_text.lower()

    # Suspicious keywords
    for kw in config["suspicious_email_keywords"]:
        if kw.lower() in text_lower:
            reasons.append(f"Contains suspicious keyword: '{kw}'")

    # Urgency words
    for uw in config["email_urgency_words"]:
        if uw.lower() in text_lower:
            reasons.append(f"Contains urgency word: '{uw}'")

    # Requests for sensitive info
    sensitive_patterns = [
        r"password",
        r"otp",
        r"card number",
        r"bank account",
        r"pin",
        r"credit card"
    ]
    for pat in sensitive_patterns:
        if re.search(pat, text_lower):
            reasons.append(f"Requests sensitive information: '{pat}'")

    # Many links
    links = re.findall(r"http\S+|https\S+", email_text)
    if len(links) > 3:
        reasons.append(f"Contains many links: {len(links)}")

    is_phishing = len(reasons) > 0
    return is_phishing, reasons