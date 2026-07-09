#!/usr/bin/env python3

import argparse
import os
import json
import sys
import joblib
import yaml

from domain_checker import (
    load_config,
    apply_url_rules_with_legitimate_score,
)
from email_enhanced import email_score, extract_email_features
from src.rules_url import apply_url_rules_with_legitimate
from src.email_features import preprocess_for_model
from src.url_features import extract_url_features
from src.rules_email import apply_email_rules


def print_help_text():
    print()
    print("P-Detective - Phishing URL and Email Detector")
    print()
    print("USAGE:")
    print("  python3 PD3t3ct1v3.py --email \"<email text>\"")
    print("  python3 PD3t3ct1v3.py --url \"<URL>\"")
    print("  python3 PD3t3ct1v3.py --url-file <urls.txt>")
    print("  python3 PD3t3ct1v3.py --email-file <emails.txt>")
    print()
    print("OPTIONS:")
    print("  --email       Check a single email for phishing.")
    print("                Provide the full email text (subject + body).")
    print()
    print("  --url         Check a single URL for phishing.")
    print("                Provide the full URL (e.g., http://example.com).")
    print()
    print("  --url-file    Check multiple URLs from a file.")
    print("                One URL per line.")
    print()
    print("  --email-file  Check multiple emails from a file.")
    print("                Emails separated by '---' on their own line.")
    print()
    print("  --json        Output results in JSON format.")
    print()
    print("  -h, --help    Show this help message and exit.")
    print()
    print("EXAMPLES:")
    print("  Check a phishing email:")
    print("    python3 PD3t3ct1v3.py")
    print("      --email \"Your account will be locked. Verify now:")
    print("               http://fake-bank.com\"")
    print()
    print("  Check a suspicious URL:")
    print("    python3 PD3t3ct1v3.py --url http://fake-bank.com")
    print()
    print("  Check multiple URLs from a file:")
    print("    python3 PD3t3ct1v3.py --url-file urls.txt")
    print()
    print("  Check multiple emails from a file:")
    print("    python3 PD3t3ct1v3.py --email-file emails.txt")
    print()
    print("  Get JSON output:")
    print("    python3 PD3t3ct1v3.py --url http://fake-bank.com --json")
    print()


def load_config(path="config/config.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(
        description="P-Detective - Phishing URL and Email Detector",
        add_help=True
    )
    parser.add_argument("--email", type=str, default=None, help="Email text to check")
    parser.add_argument("--url", type=str, default=None, help="URL to check")
    parser.add_argument("--url-file", type=str, default=None, help="File with URLs (one per line)")
    parser.add_argument("--email-file", type=str, default=None, help="File with emails (separated by '---')")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    # Show custom help if no arguments provided
    if not args.url and not args.url_file and not args.email and not args.email_file:
        print_help_text()
        sys.exit(0)

    config = load_config()

    url_model = None
    email_model = None
    email_vectorizer = None

    try:
        if os.path.exists(config["url_model_path"]):
            url_model = joblib.load(config["url_model_path"])
        if os.path.exists(config["email_model_path"]):
            email_model = joblib.load(config["email_model_path"])
        if os.path.exists("models/email_vectorizer.pkl"):
            email_vectorizer = joblib.load("models/email_vectorizer.pkl")
    except Exception:
        pass

    phishing_threshold = config.get("phishing_threshold", 0.7)
    uncertain_threshold = config.get("uncertain_threshold", 0.4)

    results = []

    # URL file
    if args.url_file:
        with open(args.url_file, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        for url in urls:
            running_check_url(url, url_model, config, phishing_threshold, uncertain_threshold, results, args.json)

    # Email file
    if args.email_file:
        with open(args.email_file, "r", encoding="utf-8") as f:
            raw = f.read()
        emails = [e.strip() for e in raw.split("---") if e.strip()]
        for email_raw in emails:
            running_check_email(email_raw, email_model, email_vectorizer, config, phishing_threshold, uncertain_threshold, results, args.json)

    # Single URL
    if args.url and not args.url_file:
        running_check_url(args.url, url_model, config, phishing_threshold, uncertain_threshold, results, args.json)

    # Single email
    if args.email and not args.email_file:
        running_check_email(args.email, email_model, email_vectorizer, config, phishing_threshold, uncertain_threshold, results, args.json)

    if args.json:
        print(json.dumps(results, indent=2))


def running_check_url(url, url_model, config, phishing_threshold, uncertain_threshold, results, json_output):
    # Use src/url_features (should return 7 features) to match your trained model
    X_url = extract_url_features([url])
    ml_pred = None
    ml_prob = None
    ml_prob_phishing = 0.0
    if url_model is not None:
        ml_pred = url_model.predict(X_url)[0]
        ml_prob = url_model.predict_proba(X_url)[0]
        ml_prob_phishing = ml_prob[1]

    rule_info = apply_url_rules_with_legitimate_score(url, config)

    if rule_info["whitelisted"]:
        result = "legitimate"
    elif rule_info.get("phishing_blacklist", False):
        result = "phishing"
    else:
        combined = max(rule_info["score"], ml_prob_phishing)
        if combined > phishing_threshold:
            result = "phishing"
        elif combined > uncertain_threshold:
            result = "uncertain"
        else:
            result = "safe"

    entry = {
        "type": "url",
        "input": url,
        "result": result,
        "ml_pred": ml_pred,
        "ml_prob": ml_prob.tolist() if ml_prob is not None and hasattr(ml_prob, "tolist") else ml_prob,
        "rule_score": rule_info["score"],
        "reasons": rule_info["reasons"],
    }
    results.append(entry)

    if not json_output:
        print("\n=== URL Check ===")
        print(f"URL: {url}")
        print(f"Result: {result}")
        print(f"ML prediction: {ml_pred}")
        print(f"ML probability: {ml_prob}")
        print("Rule score:", rule_info["score"])
        print("Reasons:")
        for r in rule_info["reasons"]:
            print(f" - {r}")


def running_check_email(email_raw, email_model, email_vectorizer, config, phishing_threshold, uncertain_threshold, results, json_output):
    rule_info = email_score(email_raw, config)

    ml_pred_email = None
    ml_prob_email = None
    ml_prob_phishing = 0.0

    try:
        if email_model is not None and email_vectorizer is not None:
            X_email = preprocess_for_model(email_raw, email_vectorizer)
            ml_pred_email = email_model.predict(X_email)[0]
            ml_prob_email = email_model.predict_proba(X_email)[0]
            ml_prob_phishing = ml_prob_email[1]
    except Exception:
        pass

    rule_score = rule_info["score"]
    combined = max(rule_score, ml_prob_phishing)

    if rule_score >= 1.0:
        result = "phishing"
    elif combined > phishing_threshold:
        result = "phishing"
    elif combined > uncertain_threshold:
        result = "uncertain"
    else:
        result = "safe"

    entry = {
        "type": "email",
        "input_preview": email_raw[:200],
        "result": result,
        "ml_pred": ml_pred_email,
        "ml_prob": ml_prob_email.tolist() if ml_prob_email is not None and hasattr(ml_prob_email, "tolist") else ml_prob_email,
        "rule_score": rule_score,
        "reasons": rule_info["reasons"],
        "headers": rule_info["headers"],
    }
    results.append(entry)

    if not json_output:
        print("\n=== Email Check ===")
        print(f"Result: {result}")
        print(f"ML prediction: {ml_pred_email}")
        print(f"ML probability: {ml_prob_email}")
        print("Rule score:", rule_score)
        print("Reasons:")
        for r in rule_info["reasons"]:
            print(f" - {r}")


if __name__ == "__main__":
    main()
