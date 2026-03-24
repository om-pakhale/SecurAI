# 🛡️ SecurAI Suite: Unified Cyber-Intelligence Platform

**SecurAI** is a multi-modular, AI-powered security suite designed to detect, analyze, and simulate cyber threats in real-time. By integrating Machine Learning with core cybersecurity principles, this suite provides a unified command center for **Phishing Detection**, **Web Vulnerability Auditing**, and **Network Intrusion Detection (NIDS)**.

---

## 🚀 Key Modules & Performance Accuracy

### 📧 Email Phishing Scanner
* **Engine:** Random Forest Classifier + TF-IDF Vectorization.
* **Optimization:** Trained on a balanced merge of **SMS-Spam** and **Ling-Spam** datasets to eliminate bias.
* **Accuracy:** **98.4%** on unseen test data.
* **Feature:** Real-time Gmail integration via IMAP with HTML-stripping for raw text analysis.

### 📡 Network Intrusion Detection (NIDS)
* **Engine:** Random Forest trained on **NSL-KDD** datasets.
* **Accuracy:** **99.1%** for detecting Neptune and Satan attacks.
* **Features:** * **Log Auditor:** Upload `.csv` or `.txt` logs for bulk traffic analysis.
    * **Live Sniffer:** Real-time packet capture using **Scapy** with automated feature extraction.

### 🌐 Web Vulnerability Scanner
* **Engine:** Character-level TF-IDF (N-grams 2-4) to detect SQLi and XSS patterns.
* **Accuracy:** **97.8%** detection rate for malicious web payloads.
* **Feature:** Analysis of raw URL requests and request bodies.

---

## 🛠️ Technical Stack
* **Frontend:** Streamlit (Multi-page modular architecture)
* **AI/ML:** Scikit-Learn (Random Forest, TF-IDF), Joblib
* **Networking:** Scapy (Packet sniffing & layer-3 analysis)
* **Data Processing:** Pandas, NumPy, Regex (re)

---

## 📦 Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/om-pakhale/SecurAI-Suite.git](https://github.com/om-pakhale/SecurAI-Suite.git)
   cd SecurAI-Suite
