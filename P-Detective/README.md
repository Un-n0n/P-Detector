 P-Detector

P-Detector is a tool for detecting phishing websites and malicious emails using domain analysis and pattern-based heuristics. It helps security analysts and researchers identify potentially harmful URLs and email content by combining multiple detection signals.

 Features

- **Domain-based detection**: Analyzes domains against trusted lists (e.g., Tranco list) to detect suspicious or newly registered domains.
- **Email-based detection**: Identifies phishing emails by analyzing headers, subject patterns, and content structure.
- **Customizable rules**: Supports configurable thresholds and detection rules to adapt to different environments.
- **Plain-text outputs**: Results are written to simple text/CSV files for easy integration with other tools.



 Requirements

- Python 3.8 or higher
- Pip (Python package manager)
- Standard Unix tools (`bash`, `git`)
 
 Installation

1. Clone the repository


 git clone https://github.com/Un-n0n/P-Detector.git
 cd P-Detector


2. Create a virtual environment (recommended)

 python3 -m venv venv
 source venv/bin/activate  # On Windows: venv\Scripts\activate


3. Install dependencies

  pip install -r requirements.txt


  Phishing Domain Dataset Setup

P-Detector uses phishing URL data from PhishTank for domain-based detection.

 Download Phishing Dataset

Download the latest verified phishing URL dataset from:

https://data.phishtank.com/data/online-valid.csv

After downloading, place the file inside the `data` folder:


P-Detector/
│
├── data/
│   └── verified_online.csv
│
└── 
And run the PD3t3ct1v3.py

