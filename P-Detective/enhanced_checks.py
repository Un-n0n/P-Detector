#!/usr/bin/env python3

import re
import socket
import ssl
import hashlib
import math
from collections import Counter
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime

import requests

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".bit", ".xyz", ".info", ".biz",
    ".cc", ".su", ".ws", ".ru", ".cn", ".top", ".work", ".click", ".link"
]

BRAND_WORDS = [
    "instagram", "facebook", "google", "amazon", "paypal", "twitter", "linkedin",
    "microsoft", "apple", "bank", "visa", "mastercard", "yahoo", "netflix"
]

ACTION_WORDS = [
    "login", "secure", "verify", "account", "update", "password", "reset",
    "signin", "sign-in", "auth", "authentication", "support", "help"
]

PHISHING_PATHS = [
    "login", "verify", "signin", "sign-in", "secure", "account",
    "password", "reset", "update", "auth", "authentication",
    "confirm", "claim", "reward", "bonus", "free"
]


def parse_domain(url):
    if url.startswith('http://'):
        url = url[7:]
    elif url.startswith('https://'):
        url = url[8:]
    elif url.startswith('ftp://'):
        url = url[6:]

    if '/' in url:
        host_part, path_part = url.split('/', 1)
    else:
        host_part = url
        path_part = ''

    if '@' in host_part:
        host_part = host_part.split('@', 1)[1]
    if ':' in host_part:
        host_part = host_part.split(':', 1)[0]

    domain = host_part.lower().rstrip('.')
    return domain, path_part


def has_suspicious_tld(domain):
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
    return False


def has_brand_action_pattern(domain):
    parts = re.split(r'[-_.]', domain.lower())
    hits = [p for p in parts if p in BRAND_WORDS or p in ACTION_WORDS]
    return len(hits) >= 3


def has_suspicious_structure(domain):
    if domain.count('.') > 4:
        return True
    if len(domain) == 0:
        return False
    digit_ratio = sum(c.isdigit() for c in domain) / len(domain)
    if digit_ratio > 0.4:
        return True
    special_ratio = sum(c in '-_@' for c in domain) / len(domain)
    if special_ratio > 0.3:
        return True
    return False


def check_dns_resolution(domain):
    try:
        socket.getaddrinfo(domain, None, socket.AF_INET)
        return True, "Domain resolves"
    except socket.gaierror:
        return False, "Domain does not resolve"


def check_ssl_certificate(url):
    if not url.startswith("https://"):
        return None, "No HTTPS"
    try:
        host = urlparse(url).hostname
        if not host:
            return None, "Cannot parse host"
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with context.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.connect((host, 443))
            cert = s.getpeercert()
        not_after_str = cert['notAfter']
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        if not_after < datetime.utcnow():
            return False, "Certificate expired"
        common_name = cert['subject'][0][0]['value']
        if host != common_name and not host.endswith(common_name + "."):
            return False, "Certificate hostname mismatch"
        return True, "Valid certificate"
    except ssl.SSLCertVerificationError as e:
        return False, f"SSL certificate verification failed: {e}"
    except socket.gaierror:
        return False, "Cannot resolve host"
    except socket.timeout:
        return False, "Connection timed out"
    except Exception as e:
        return False, f"SSL check error: {e}"


def check_redirect_chain(url, max_redirects=3):
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        if len(resp.history) > max_redirects:
            return True, f"Too many redirects ({len(resp.history)})"
        return False, None
    except Exception:
        return False, None


def url_entropy_check(url):
    if len(url) > 200:
        return True, "Very long URL"
    def entropy(s):
        if not s:
            return 0
        c = Counter(s)
        probs = [count / len(s) for count in c.values()]
        return -sum(p * math.log2(p) for p in probs)
    if entropy(url) > 4.5:
        return True, "High character entropy in URL"
    return False, None


def subdomain_check(domain):
    parts = domain.split('.')
    if len(parts) > 5:
        return True, f"Too many subdomain levels ({len(parts)})"
    def entropy(s):
        if not s:
            return 0
        c = Counter(s)
        probs = [count / len(s) for count in c.values()]
        return -sum(p * math.log2(p) for p in probs)
    if len(parts[0]) > 15 or entropy(parts[0]) > 3.5:
        return True, "Random-looking subdomain"
    return False, None


def path_pattern_check(path):
    if any(p in path.lower() for p in PHISHING_PATHS):
        return True, "Path contains phishing-like keywords"
    return False, None


def domain_age_check(domain):
    try:
        import whois
        w = whois.whois(domain)
        if w.creation_date is None:
            return False, None
        dates = w.creation_date
        if isinstance(dates, list):
            dates = dates[0]
        age = datetime.now() - dates
        if age.days < 30:
            return True, f"Domain is very new ({age.days} days)"
        return False, None
    except Exception:
        return False, None


def url_hash_check(url, phishing_hashes_path=None, config_file_path=None):
    if phishing_hashes_path is None:
        return False, None
    if config_file_path is None:
        base_dir = Path(__file__).resolve().parent
        config_file_path = base_dir / "config" / "config.yaml"
    project_root = Path(config_file_path).resolve().parent.parent
    abs_path = (project_root / phishing_hashes_path).resolve()
    known_hashes = set()
    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    known_hashes.add(line)
    except Exception:
        return False, None
    def normalize_url(u):
        u = u.lower()
        if u.startswith("https://"):
            u = u[8:]
        elif u.startswith("http://"):
            u = u[7:]
        if ':' in u:
            u = u.split(':', 1)[0]
        return u.split('/', 1)[0] if '/' in u else u
    def url_hash(u):
        norm = normalize_url(u)
        return hashlib.sha256(norm.encode()).hexdigest()
    h = url_hash(url)
    if h in known_hashes:
        return True, "URL hash matches known phishing URL"
    return False, None


def typosquatting_check(domain):
    known = ["instagram", "facebook", "google", "amazon", "paypal"]
    for brand in known:
        if brand in domain and brand != domain.split('.')[0]:
            return True, "Possible typosquatting of a known brand"
    return False, None


def suspicious_subdomain_pattern(domain):
    parts = domain.split('.')
    if len(parts) > 3:
        first = parts[0]
        if len(first) > 10 and any(c.isdigit() for c in first):
            return True, "Suspicious long numeric subdomain"
    return False, None


def url_score(url, config):
    from domain_checker import (
        load_legitimate_domains,
        is_legitimate_domain,
        load_phishing_domains,
        load_phishing_urls,
        parse_domain,
    )

    domain, path = parse_domain(url)
    if domain is None or domain == "":
        return {"whitelisted": False, "phishing_blacklist": False, "score": 0.9, "reasons": ["Invalid URL"]}

    config_file = Path(__file__).resolve().parent / "config" / "config.yaml"

    # Whitelist
    domains_path = config["legitimate_domains_path"]
    legitimate_domains = load_legitimate_domains(domains_path, config_file_path=config_file)
    is_legit, legit_reasons = is_legitimate_domain(domain, legitimate_domains)
    if is_legit:
        return {"whitelisted": True, "phishing_blacklist": False, "score": 0.0, "reasons": legit_reasons}

    # Phishing URL blacklist
    phishing_urls_path = config.get("phishing_urls_path")
    if phishing_urls_path:
        phishing_urls = load_phishing_urls(phishing_urls_path, config_file_path=config_file)
        if url.lower() in phishing_urls:
            return {"whitelisted": False, "phishing_blacklist": True, "score": 1.0, "reasons": ["URL matches known phishing URL"]}
        if domain and domain in phishing_urls:
            return {"whitelisted": False, "phishing_blacklist": True, "score": 1.0, "reasons": ["Domain matches known phishing domain"]}

    # Phishing domains blacklist
    phishing_domains_path = config.get("phishing_domains_path")
    if phishing_domains_path:
        phishing_domains = load_phishing_domains(phishing_domains_path, config_file_path=config_file)
        if domain in phishing_domains:
            return {"whitelisted": False, "phishing_blacklist": True, "score": 1.0, "reasons": ["Domain is in known phishing list"]}
        for phish in phishing_domains:
            if domain.endswith('.' + phish):
                return {"whitelisted": False, "phishing_blacklist": True, "score": 1.0, "reasons": ["Domain is a subdomain of a known phishing site"]}

    score = 0.0
    reasons = []

    if not url.startswith("https://"):
        score += 0.15
        reasons.append("URL does not use HTTPS")

    ssl_ok, ssl_msg = check_ssl_certificate(url)
    if ssl_ok is False:
        score += 0.25
        reasons.append(ssl_msg)
    elif ssl_ok is None:
        pass
    else:
        score -= 0.05
        if score < 0:
            score = 0.0

    if has_suspicious_tld(domain):
        score += 0.25
        reasons.append("Suspicious TLD")

    if has_brand_action_pattern(domain):
        score += 0.3
        reasons.append("Suspicious brand/action word pattern in domain")

    if has_suspicious_structure(domain):
        score += 0.2
        reasons.append("Suspicious domain structure (digits/dots/special chars)")

    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 0.3
        reasons.append("IP address in URL")

    if len(path) > 100:
        score += 0.1
        reasons.append("Very long URL path")
    param_count = path.count('&') + path.count('?')
    if param_count > 5:
        score += 0.1
        reasons.append("Many query parameters")

    too_many_redirects, redirect_msg = check_redirect_chain(url)
    if too_many_redirects:
        score += 0.15
        reasons.append(redirect_msg)

    inf_len, inf_msg = url_entropy_check(url)
    if inf_len:
        score += 0.1
        reasons.append(inf_msg)

    sus_sub, sub_msg = subdomain_check(domain)
    if sus_sub:
        score += 0.15
        reasons.append(sub_msg)

    sus_path, path_msg = path_pattern_check(path)
    if sus_path:
        score += 0.15
        reasons.append(path_msg)

    sus_age, age_msg = domain_age_check(domain)
    if sus_age:
        score += 0.2
        reasons.append(age_msg)

    sus_typos, typos_msg = typosquatting_check(domain)
    if sus_typos:
        score += 0.2
        reasons.append(typos_msg)

    sus_subdom, subdom_msg = suspicious_subdomain_pattern(domain)
    if sus_subdom:
        score += 0.15
        reasons.append(subdom_msg)

    score = min(score, 1.0)

    return {"whitelisted": False, "phishing_blacklist": False, "score": score, "reasons": reasons}