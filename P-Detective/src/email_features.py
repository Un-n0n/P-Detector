from __future__ import annotations

import re
from sklearn.feature_extraction import text

def clean_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"http\S+|www\S+|https\S+", "", text, flags=re.MULTILINE)
    text = re.sub(r"\S+@\S+", "", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def extract_features(email_texts: list[str]) -> tuple:
    cleaned = [clean_text(t) for t in email_texts]
    vectorizer = text.TfidfVectorizer(max_features=1000, stop_words="english")
    X = vectorizer.fit_transform(cleaned)
    return X, vectorizer

def preprocess_for_model(email_text: str, vectorizer):
    cleaned = clean_text(email_text)
    return vectorizer.transform([cleaned])

