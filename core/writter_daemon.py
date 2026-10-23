# core/sniffer_daemon.py
import os
import joblib
import logging
from scapy.all import sniff, TCP, IP, Raw
from db import int_db, int_insert_event

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

BASES = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(BASES, "..", "Models", "full_injection_model.pkl")
VEC = os.path.join(BASES, "..", "Models", "full_vectorizer.pkl")

# Load ML components
try:
    model = joblib.load(MODEL)
    vectorizer = joblib.load(VEC)
    logging.info("ML Detection models loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load ML artifacts: {e}")
    exit(1)

# Label mapping: handles both numeric (0, 1, 2) and string classifications
LABEL_MAP = {
    0: "Clean",
    1: "SQLi",
    2: "XSS",
    3: "CMD_Injection",
    "0": "Clean",
    "1": "SQLi",
    "2": "XSS",
    "3": "CMD_Injection"
}

def classify_payload(payload_str):
    try:
        vec = vectorizer.transform([payload_str])
        raw_pred = model.predict(vec)[0]
        
        # Check if predict_proba exists; fallback to 1.0 if not
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(vec)[0]
            confidence = float(max(probs))
        else:
            confidence = 1.0

        # Convert numeric float/int prediction to readable string
        if isinstance(raw_pred, (int, float)):
            pred_class = LABEL_MAP.get(int(raw_pred), f"Attack_{int(raw_pred)}")
        else:
            pred_class = str(raw_pred)
        
        # Severity calculation based on normalized class
        p_upper = pred_class.upper()
        if "SQL" in p_upper or "CMD" in p_upper:
            severity = "Critical" if confidence > 0.85 else "High"
        elif "XSS" in p_upper:
            severity = "High" if confidence > 0.80 else "Medium"
        elif "CLEAN" in p_upper or "NORMAL" in p_upper or "BENIGN" in p_upper:
            severity = "Low"
        else:
            severity = "Medium"
            
        return pred_class, confidence, severity

    except Exception as e:
        logging.warning(f"Classification error: {e}")
        return "Unknown", 0.0, "Low"

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        try:
            payload_text = payload.decode('utf-8', errors='ignore')
        except Exception:
            return

        # Filter for HTTP request patterns
        if any(verb in payload_text for verb in ["GET ", "POST ", "PUT ", "DELETE "]):
            src_ip = packet[IP].src if packet.haslayer(IP) else "0.0.0.0"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "0.0.0.0"

            pred_class, conf, severity = classify_payload(payload_text)

            # Safeguard string comparison
            is_malicious = str(pred_class).lower() not in ["clean", "normal", "benign", "0", "attack_0"]

            if is_malicious and conf > 0.65:
                logging.warning(f"[ALERT] {severity} {pred_class} detected from {src_ip} -> {dst_ip} (Conf: {conf:.2f})")
                int_insert_event(src_ip, dst_ip, "TCP/HTTP", payload_text, str(pred_class), conf, severity)

def start_sniffer(interface=None):
    int_db()
    logging.info(f"Starting unprivileged packet capture daemon on interface: {interface or 'default'}")
    sniff(iface=interface, prn=packet_callback, store=0, filter="tcp port 80 or tcp port 8080 or tcp port 8000")

if __name__ == "__main__":
    start_sniffer()