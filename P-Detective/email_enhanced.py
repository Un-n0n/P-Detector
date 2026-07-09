
# # email_enhanced.py
# import re
# import email
# from email.parser import BytesParser
# from email.policy import default as default_policy
# from pathlib import Path

# SUSPICIOUS_SENDER_KEYWORDS = [
#     "support", "security", "alert", "verify", "urgent", "confirm", "blocked",
#     "suspended", "transaction", "payment", "account", "password", "login"
# ]

# ACTION_WORDS_IN_SUBJECT = [
#     "verify", "confirm", "update", "reset", "activate", "secure", "urgent",
#     "immediately", "as soon as possible", "right now"
# ]

# SUSPICIOUS_LINK_DOMAINS = [
#     "tk", "ml", "ga", "cf", "gq", "bit", "xyz", "info", "biz", "top", "work"
# ]

# BRAND_WORDS = [
#     "instagram", "facebook", "google", "amazon", "paypal", "twitter", "linkedin",
#     "microsoft", "apple", "yahoo", "netflix", "bank", "visa", "mastercard"
# ]

# ACTION_WORDS = [
#     "login", "secure", "verify", "account", "update", "password", "reset",
#     "signin", "sign-in", "auth", "authentication", "support", "help"
# ]


# def parse_email(raw_data):
#     if isinstance(raw_data, str):
#         raw_data = raw_data.encode("utf-8")
#     msg = BytesParser(policy=default_policy).parsebytes(raw_data)
#     return msg


# def extract_headers(msg):
#     return {
#         "From": msg.get("From", ""),
#         "To": msg.get("To", ""),
#         "Subject": msg.get("Subject", ""),
#         "Date": msg.get("Date", ""),
#         "Reply-To": msg.get("Reply-To", ""),
#         "Message-ID": msg.get("Message-ID", ""),
#     }


# def extract_links(text):
#     pattern = r'http[s]?://[^\s<>"\']+'
#     return re.findall(pattern, text)


# def extract_domains_from_links(links):
#     domains = []
#     for link in links:
#         try:
#             host = link.split("://", 1)[1].split("/", 1)[0]
#             if '@' in host:
#                 host = host.split('@', 1)[1]
#             host = host.split(':', 1)[0]
#             host = host.lower().rstrip('.')
#             domains.append(host)
#         except Exception:
#             continue
#     return domains


# def load_phishing_emails(emails_path, config_file_path=None):
#     if config_file_path is None:
#         base_dir = Path(__file__).resolve().parent
#         config_file_path = base_dir / "config" / "config.yaml"
#     project_root = Path(config_file_path).resolve().parent.parent
#     abs_path = (project_root / emails_path).resolve()
#     emails = set()
#     try:
#         with open(abs_path, "r", encoding="utf-8") as f:
#             for line in f:
#                 line = line.strip()
#                 if line and not line.startswith("#"):
#                     emails.add(line)
#     except Exception:
#         return set()
#     return emails


# def email_score(email_raw, config):
#     msg = parse_email(email_raw)
#     headers = extract_headers(msg)

#     subject = headers.get("Subject", "").lower()
#     from_field = headers.get("From", "").lower()
#     reply_to = headers.get("Reply-To", "").lower()

#     body = ""
#     if msg.is_multipart():
#         for part in msg.walk():
#             ctype = part.get_content_type()
#             if ctype == "text/plain":
#                 try:
#                     body += part.get_content()
#                 except Exception:
#                     continue
#     else:
#         try:
#             body = msg.get_content()
#         except Exception:
#             body = ""

#     body_lower = body.lower()

#     score = 0.0
#     reasons = []

#     from_name = from_field.split('@')[0] if '@' in from_field else from_field
#     if any(kw in from_name for kw in SUSPICIOUS_SENDER_KEYWORDS):
#         score += 0.15
#         reasons.append("Sender name contains suspicious keywords")

#     if reply_to and '@' in reply_to and '@' in from_field:
#         from_host = from_field.split('@')[1]
#         reply_host = reply_to.split('@')[1]
#         if from_host != reply_host:
#             score += 0.2
#             reasons.append("Reply-To domain differs from From domain")

#     if any(kw in subject for kw in ACTION_WORDS_IN_SUBJECT):
#         score += 0.15
#         reasons.append("Subject contains urgent/action words")

#     links = extract_links(body)
#     link_domains = extract_domains_from_links(links)

#     if link_domains:
#         for dom in link_domains:
#             tld = dom.split('.')[-1].lower()
#             if tld in SUSPICIOUS_LINK_DOMAINS:
#                 score += 0.2
#                 reasons.append(f"Suspicious TLD in link: {tld}")
#             if any(br in dom for br in BRAND_WORDS) and any(ac in dom for ac in ACTION_WORDS):
#                 score += 0.25
#                 reasons.append("Link domain contains brand + action words")

#     if "suspended" in body_lower or "blocked" in body_lower or "locked" in body_lower:
#         score += 0.2
#         reasons.append("Email mentions suspension/block/lock")

#     urgency_words = config.get("email_urgency_words", [])
#     if any(w in body_lower for w in urgency_words):
#         score += 0.15
#         reasons.append("Email contains urgency words")

#     phishing_emails_path = config.get("phishing_emails_path")
#     if phishing_emails_path:
#         config_file = Path(__file__).resolve().parent / "config" / "config.yaml"
#         phishing_emails = load_phishing_emails(phishing_emails_path, config_file_path=config_file)
#         for phish in phishing_emails:
#             if phish.lower() in subject.lower() or phish.lower() in from_field.lower() or phish.lower() in body_lower:
#                 score = 1.0
#                 reasons = ["Email matches known phishing pattern"]
#                 break

#     score = min(score, 1.0)

#     return {
#         "score": score,
#         "reasons": reasons,
#         "headers": headers,
#         "body": body,
#         "links": links,
#     }


# def extract_email_features(emails):
#     features = []
#     for email_raw in emails:
#         msg = parse_email(email_raw)
#         subject = msg.get("Subject", "")
#         from_field = msg.get("From", "")
#         feat = [
#             len(subject),
#             len(from_field),
#             int(any(kw in subject.lower() for kw in ACTION_WORDS_IN_SUBJECT)),
#             int(any(kw in from_field.lower() for kw in SUSPICIOUS_SENDER_KEYWORDS)),
#         ]
#         features.append(feat)
#     return features

# email_enhanced.py
import re
import email
from email.parser import BytesParser
from email.policy import default as default_policy
from pathlib import Path

SUSPICIOUS_SENDER_KEYWORDS = [
    "support", "security", "alert", "verify", "urgent", "confirm", "blocked",
    "suspended", "transaction", "payment", "account", "password", "login"
]

ACTION_WORDS_IN_SUBJECT = [
    "verify", "confirm", "update", "reset", "activate", "secure", "urgent",
    "immediately", "as soon as possible", "right now"
]

SUSPICIOUS_LINK_DOMAINS = [
    "tk", "ml", "ga", "cf", "gq", "bit", "xyz", "info", "biz", "top", "work"
]

BRAND_WORDS = [
    "instagram", "facebook", "google", "amazon", "paypal", "twitter", "linkedin",
    "microsoft", "apple", "yahoo", "netflix", "bank", "visa", "mastercard"
]

ACTION_WORDS = [
    "login", "secure", "verify", "account", "update", "password", "reset",
    "signin", "sign-in", "auth", "authentication", "support", "help"
]


def parse_email_raw(raw_data):
    if isinstance(raw_data, str):
        raw_data = raw_data.encode("utf-8")
    msg = BytesParser(policy=default_policy).parsebytes(raw_data)
    return msg


def extract_headers(msg):
    return {
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "Message-ID": msg.get("Message-ID", ""),
    }


def extract_security_headers(msg):
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")

    received = msg.get_all("Received", [])

    received_spf = msg.get("Received-SPF", "")
    auth_results = msg.get("Authentication-Results", "")

    return {
        "from": from_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "date": date,
        "message_id": message_id,
        "x_mailer": x_mailer,
        "received": received,
        "received_spf": received_spf,
        "auth_results": auth_results,
    }


def extract_email_address(addr):
    if '@' in addr:
        return addr.split('<', 1)[-1].split('>', 1)[0].strip()
    return addr.strip()


def check_header_consistency(headers):
    reasons = []
    score = 0.0

    from_addr = headers["from"]
    reply_to = headers["reply_to"]
    return_path = headers["return_path"]

    from_email = extract_email_address(from_addr)
    reply_email = extract_email_address(reply_to)
    return_email = extract_email_address(return_path)

    from_domain = from_email.split('@', 1)[-1].lower() if '@' in from_email else from_email.lower()
    reply_domain = reply_email.split('@', 1)[-1].lower() if '@' in reply_email else reply_email.lower()
    return_domain = return_email.split('@', 1)[-1].lower() if '@' in return_email else return_email.lower()

    if reply_email and from_email and reply_domain and from_domain and reply_domain != from_domain:
        reasons.append("Reply-To domain differs from From domain")
        score += 0.15

    if return_email and from_email and return_domain and from_domain and return_domain != from_domain:
        reasons.append("Return-Path domain differs from From domain")
        score += 0.15

    if "fail" in headers["received_spf"].lower():
        reasons.append("SPF check failed")
        score += 0.25

    if "fail" in headers["auth_results"].lower():
        reasons.append("Authentication (DKIM/DMARC) failed")
        score += 0.25

    return score, reasons


def extract_links(text):
    pattern = r'http[s]?://[^\s<>"\']+'
    return re.findall(pattern, text)


def extract_domains_from_links(links):
    domains = []
    for link in links:
        try:
            host = link.split("://", 1)[1].split("/", 1)[0]
            if '@' in host:
                host = host.split('@', 1)[1]
            host = host.split(':', 1)[0]
            host = host.lower().rstrip('.')
            domains.append(host)
        except Exception:
            continue
    return domains


def load_phishing_emails(emails_path, config_file_path=None):
    if config_file_path is None:
        base_dir = Path(__file__).resolve().parent
        config_file_path = base_dir / "config" / "config.yaml"
    project_root = Path(config_file_path).resolve().parent.parent
    abs_path = (project_root / emails_path).resolve()
    emails = set()
    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    emails.add(line)
    except Exception:
        return set()
    return emails


def email_score(email_raw, config):
    msg = parse_email_raw(email_raw)
    headers_dict = extract_headers(msg)

    security_headers = extract_security_headers(msg)
    header_score, header_reasons = check_header_consistency(security_headers)

    subject = headers_dict.get("Subject", "").lower()
    from_field = headers_dict.get("From", "").lower()
    reply_to = headers_dict.get("Reply-To", "").lower()

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    continue
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""

    body_lower = body.lower()

    score = 0.0
    reasons = []

    from_name = from_field.split('@')[0] if '@' in from_field else from_field
    if any(kw in from_name for kw in SUSPICIOUS_SENDER_KEYWORDS):
        score += 0.15
        reasons.append("Sender name contains suspicious keywords")

    if reply_to and '@' in reply_to and '@' in from_field:
        from_host = from_field.split('@')[1]
        reply_host = reply_to.split('@')[1]
        if from_host != reply_host:
            score += 0.2
            reasons.append("Reply-To domain differs from From domain (body check)")

    if any(kw in subject for kw in ACTION_WORDS_IN_SUBJECT):
        score += 0.15
        reasons.append("Subject contains urgent/action words")

    links = extract_links(body)
    link_domains = extract_domains_from_links(links)

    if link_domains:
        for dom in link_domains:
            tld = dom.split('.')[-1].lower()
            if tld in SUSPICIOUS_LINK_DOMAINS:
                score += 0.2
                reasons.append(f"Suspicious TLD in link: {tld}")
            if any(br in dom for br in BRAND_WORDS) and any(ac in dom for ac in ACTION_WORDS):
                score += 0.25
                reasons.append("Link domain contains brand + action words")

    if "suspended" in body_lower or "blocked" in body_lower or "locked" in body_lower:
        score += 0.2
        reasons.append("Email mentions suspension/block/lock")

    urgency_words = config.get("email_urgency_words", [])
    if any(w in body_lower for w in urgency_words):
        score += 0.15
        reasons.append("Email contains urgency words")

    # Add header-based scoring
    score += header_score
    reasons.extend(header_reasons)

    # Add Received chain check
    received_score, received_reasons = check_received_chain(security_headers)
    score += received_score
    reasons.extend(received_reasons)

    phishing_emails_path = config.get("phishing_emails_path")
    if phishing_emails_path:
        config_file = Path(__file__).resolve().parent / "config" / "config.yaml"
        phishing_emails = load_phishing_emails(phishing_emails_path, config_file_path=config_file)
        for phish in phishing_emails:
            if phish.lower() in subject.lower() or phish.lower() in from_field.lower() or phish.lower() in body_lower:
                score = 1.0
                reasons = ["Email matches known phishing pattern"]
                break

    score = min(score, 1.0)

    return {
        "score": score,
        "reasons": reasons,
        "headers": headers_dict,
        "security_headers": security_headers,
        "body": body,
        "links": links,
    }


def extract_email_features(emails):
    features = []
    for email_raw in emails:
        msg = parse_email_raw(email_raw)
        subject = msg.get("Subject", "")
        from_field = msg.get("From", "")
        feat = [
            len(subject),
            len(from_field),
            int(any(kw in subject.lower() for kw in ACTION_WORDS_IN_SUBJECT)),
            int(any(kw in from_field.lower() for kw in SUSPICIOUS_SENDER_KEYWORDS)),
        ]
        features.append(feat)
    return features

def check_received_chain(headers):
    reasons = []
    score = 0.0

    from_addr = headers["from"]
    from_domain = extract_email_address(from_addr)
    if from_domain and '@' in from_domain:
        from_domain = from_domain.split('@', 1)[-1].lower()
    else:
        from_domain = from_domain.lower()

    received = headers["received"]

    # Look at the last "from" line (initial server)
    for line in reversed(received):
        if "from" in line.lower():
            # Very simple: check if from_domain appears in received line
            if from_domain and from_domain not in line.lower():
                reasons.append("Received chain does not clearly match From domain")
                score += 0.1
            break

    return score, reasons