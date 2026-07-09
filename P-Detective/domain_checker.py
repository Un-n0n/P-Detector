#!/usr/bin/env python3

import os
import re
import yaml
from pathlib import Path

def load_config(config_path="config/config.yaml"):
    base_dir = Path(__file__).resolve().parent
    config_file = base_dir / config_path
    with config_file.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_legitimate_domains(domains_path, config_file_path=None):
    if config_file_path is None:
        base_dir = Path(__file__).resolve().parent
        config_file_path = base_dir / "config" / "config.yaml"
    project_root = Path(config_file_path).resolve().parent.parent
    abs_path = (project_root / domains_path).resolve()

    domains = set()
    with open(abs_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower().rstrip(".")
            if line and not line.startswith("#"):
                domains.add(line)
    return domains

def load_phishing_domains(domains_path, config_file_path=None):
    if config_file_path is None:
        base_dir = Path(__file__).resolve().parent
        config_file_path = base_dir / "config" / "config.yaml"
    project_root = Path(config_file_path).resolve().parent.parent
    abs_path = (project_root / domains_path).resolve()

    domains = set()
    with open(abs_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower().rstrip(".")
            if line and not line.startswith("#"):
                domains.add(line)
    return domains

def load_phishing_urls(urls_path, config_file_path=None):
    if config_file_path is None:
        base_dir = Path(__file__).resolve().parent
        config_file_path = base_dir / "config" / "config.yaml"
    project_root = Path(config_file_path).resolve().parent.parent
    abs_path = (project_root / urls_path).resolve()

    urls = set()
    with open(abs_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                urls.add(line)
    return urls

def load_phishing_emails(emails_path, config_file_path=None):
    if config_file_path is None:
        base_dir = Path(__file__).resolve().parent
        config_file_path = base_dir / "config" / "config.yaml"
    project_root = Path(config_file_path).resolve().parent.parent
    abs_path = (project_root / emails_path).resolve()

    emails = set()
    with open(abs_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                emails.add(line)
    return emails

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

def is_legitimate_domain(domain, legitimate_domains):
    reasons = []
    if domain in legitimate_domains:
        reasons.append("Domain matches a known legitimate site")
        return True, reasons
    for legit in legitimate_domains:
        if domain.endswith('.' + legit):
            reasons.append(f"Domain is a subdomain of a known legitimate site ({legit})")
            return True, reasons
    return False, reasons

def is_phishing_domain(domain, phishing_domains):
    reasons = []
    if domain in phishing_domains:
        reasons.append("Domain is in known phishing list")
        return True, reasons
    for phish in phishing_domains:
        if domain.endswith('.' + phish):
            reasons.append(f"Domain is a subdomain of a known phishing site ({phish})")
            return True, reasons
    return False, reasons

def apply_url_rules_with_legitimate_score(url, config):
    from enhanced_checks import url_score
    return url_score(url, config)