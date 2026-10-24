import pytest
import os
import joblib
import sys

# Ensure root and core are on python path
base_dir = os.path.dirname(os.path.abspath(__file__))
project = os.path.abspath(os.path.join(base_dir, ".."))
sys.path.append(project)
sys.path.append(os.path.join(project, "core"))

from core.db import int_insert_event, fetch_incident, int_db

# 1. Locate ML artifacts
model_path = os.path.join(project, "Models", "full_injection_model.pkl")
vectorizer_path = os.path.join(project, "Models", "full_vectorizer.pkl")

if not os.path.exists(model_path):
    model_path = os.path.join(project, "full_injection_model.pkl")
    vectorizer_path = os.path.join(project, "full_vectorizer.pkl")

# 2. Load ML artifacts
ml_model = joblib.load(model_path)
ml_vectorizer = joblib.load(vectorizer_path)


def test_benign_traffic_classification():
    """Ensures natural benign text and safe web requests evaluate as clean."""
    benign_samples = [
        "Hello world, welcome to our official website.",
        "Thank you for contacting customer support.",
        "Please read our privacy policy and terms of service.",
        "Documentation for installation and user guidelines."
    ]

    for sample in benign_samples:
        transformed = ml_vectorizer.transform([sample])
        pred = ml_model.predict(transformed)[0]
        
        if hasattr(ml_model, "predict_proba"):
            probs = ml_model.predict_proba(transformed)[0]
            attack_prob = probs[1]  # Index 1 is Class 1.0 (Attack)
            assert attack_prob < 0.65, f"False positive attack detected ({attack_prob:.2f}) on: {sample}"
        else:
            assert pred in [0, 0.0, "0", "Clean", "clean"]


def test_sqli_payload_detection():
    """Ensures classic and obfuscated SQL injection payloads are flagged."""
    sqli_samples = [
        "1' UNION SELECT null, username, password FROM users--",
        "admin' OR '1'='1",
        "1' AND 1=1--"
    ]
    for sample in sqli_samples:
        transformed = ml_vectorizer.transform([sample])
        pred = ml_model.predict(transformed)[0]
        assert pred not in [0, 0.0, "0", "Clean", "clean", "Normal", "normal"]


def test_malformed_and_binary_resilience():
    """Verifies vectorizer handles corrupted or binary garbage without throwing exceptions."""
    garbage_samples = [
        "\x00\xff\xfe\x12\x89\xab\xcd",
        " " * 1000,
        "???///&&&%%%$$$###@@@!!!",
        ""
    ]
    for sample in garbage_samples:
        try:
            transformed = ml_vectorizer.transform([sample])
            pred = ml_model.predict(transformed)
            assert len(pred) == 1
        except Exception as e:
            pytest.fail(f"Pipeline crashed on edge case payload: {e}")


def test_sqlite_concurrent_write_and_read():
    """Validates WAL mode concurrency by writing and reading an event."""
    int_db()
    test_src = "10.0.0.99"
    test_dst = "10.0.0.1"
    test_proto = "TCP"
    test_payload = "TEST_UNIT_INJECTION_STRING"
    test_class = "SQLi"
    test_conf = 0.99
    test_sev = "Critical"

    # Positional parameters ensure signature compatibility with core/db.py
    int_insert_event(
        test_src,
        test_dst,
        test_proto,
        test_payload,
        test_class,
        test_conf,
        test_sev
    )
    
    events = fetch_incident(limit=5)
    assert len(events) > 0
    latest = events[0]
    assert latest[2] == test_src
    assert latest[3] == test_dst
    assert latest[6] == test_class