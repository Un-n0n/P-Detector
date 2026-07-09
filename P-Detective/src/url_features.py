import re
from urllib.parse import urlparse

def extract_url_features(urls):
    features = []
    for url in urls:
        f = []
        # URL length
        f.append(len(url))
        # Number of dots
        f.append(url.count("."))
        # Number of slashes
        f.append(url.count("/"))
        # Has https?
        f.append(1 if url.startswith("https") else 0)
        # Parse domain
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split("/")[0]
        except:
            domain = url

        # Has IP address?
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        f.append(1 if re.search(ip_pattern, domain) else 0)

        # Has suspicious words in domain?
        suspicious_words = ["login", "secure", "verify", "bank", "account", "update", "reset"]
        domain_lower = domain.lower()
        f.append(1 if any(w in domain_lower for w in suspicious_words) else 0)

        # Number of subdomains (dashes in domain)
        f.append(domain.count("-"))

        features.append(f)

    return features

