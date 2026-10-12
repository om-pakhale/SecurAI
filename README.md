

# 🛡️ Sentinel-Sec: Event-Driven SecOps Telemetry & Automated Triage Engine

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scapy](https://img.shields.io/badge/Network-Scapy%20DPI-red)](https://scapy.net/)
[![Docker](https://img.shields.io/badge/Deployment-Docker%20Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Security](https://img.shields.io/badge/OWASP-API%20%26%20Top%2010-orange)](https://owasp.org/)

**Sentinel-Sec** is an asynchronous Security Operations (SecOps) telemetry and threat detection framework designed to bridge the gap between network-level packet telemetry, application-layer vulnerability auditing, and automated incident response. 

Unlike traditional isolated scanning scripts, Sentinel-Sec correlates multi-stage network indicators with HTTP payload anomalies, executing context-aware LLM triage via automated orchestration pipelines before dispatching high-signal alerts to security operations teams.

---

## 🏛️ System Architecture

```text
       [ Live Network Traffic / Interface eth0 ]
                          │
                          ▼
               ┌─────────────────────┐
               │   Scapy DPI Daemon  │ ──( Linux Kernel Socket / CAP_NET_RAW )
               └──────────┬──────────┘
                          │ Raw Frame Ingestion & Protocol Normalization
                          ▼
               ┌─────────────────────┐
               │ Ingestion & Parsing │ ◄── [ Target HTTP App Audit Stream ]
               └──────────┬──────────┘
                          │ Normalized JSON Telemetry
                          ▼
               ┌─────────────────────┐
               │  ML Inference Core  │
               │  (TF-IDF + Forest)  │ ──► [ Severity Matrix (Low -> Critical) ]
               └──────────┬──────────┘
                          │ Priority Threshold >= High
                          ▼
               ┌─────────────────────┐
               │ Orchestration Bridge│
               │ (n8n Webhook Engine)│
               └──────────┬──────────┘
                          │ Threat Context & Asset Metadata
                          ▼
               ┌─────────────────────┐
               │ Gemini 1.5 Triage   │ ──► Generates Root-Cause & Remediation Plan
               └──────────┬──────────┘
                          │ Structured Markdown Alert
                          ▼
               [ Discord Ops / SIEM Channel ]

```

---

## 🚀 Core Features

### 📡 1. Decoupled Network Deep Packet Inspection (DPI)

* **Raw Socket Capture:** Leverages `Scapy` to perform deep packet inspection across TCP/IP streams, extracting HTTP request payloads in real time.
* **Privilege Separation:** Runs packet capture under granular Linux network capabilities (`CAP_NET_RAW`), eliminating the security hazard of executing front-end web dashboards with elevated `root`/`sudo` privileges.
* **Heuristic Anomaly Detection:** Flags packet sizing anomalies (>1000 bytes) and abnormal transport patterns indicating potential data staging or buffer overflow exploits.

### 🧠 2. Adversarial Machine Learning Core

* **Character n-gram Vectorization:** Implements character-level TF-IDF vectorization (n-grams 2–4) to model structural payload semantics, successfully capturing obfuscated SQLi, XSS, and command injection variations that evade traditional regex WAF rules.
* **Random Forest Classification:** High-precision multi-class classification ensemble trained on malicious injection corpora and benign web logs.
* **Traffic Profiling:** Ingests NSL-KDD benchmark telemetry to distinguish baseline operational network flow from malicious intrusion patterns.

### 🌐 3. Application Security Surface Auditor

* **Automated Form Discovery:** Crawls and parses target endpoints, identifying inputs, parameters, and form fields via `BeautifulSoup4`.
* **Vulnerability Probing:** Simulates injection vectors against application boundaries, analyzing reflection contexts and database syntax leakage (MySQL, PostgreSQL, MSSQL, Oracle).

### ⚡ 4. Event-Driven Triage Pipeline (n8n + LLM Engine)

* **Conditional Webhook Routing:** Streams normalized threat telemetry via asynchronous HTTP POST requests to an `n8n` workflow bridge, routing only `High` and `Critical` indicators downstream to eliminate operational alert fatigue.
* **Context-Aware AI Remediation:** Interacts with the `gemini-1.5-flash` reasoning engine with strict system prompts to analyze blast radius and output clear, two-sentence remediation instructions.
* **Instant Incident Dispatch:** Posts audit-ready markdown incident summaries directly to live Discord/Slack monitoring channels.

---

## 🛠️ Technical Stack

* **Networking & Packet Analysis:** Python 3.11+, Scapy, Npcap/libpcap
* **Machine Learning & Data Processing:** Scikit-Learn, Pandas, NumPy, Joblib
* **Web Scraping & Application Testing:** BeautifulSoup4, Requests, Urllib3
* **Automation & Orchestration:** n8n Workflow Automation, Google Gemini API (`gemini-1.5-flash`)
* **Presentation & Telemetry Dashboard:** Streamlit (Unprivileged Execution)
* **Containerization & Deployment:** Docker, Docker Compose

---

## 📦 Installation & Setup

### 1. System Dependencies (Linux)

Install low-level packet capture drivers and grant Python the necessary raw socket capabilities:

```bash
sudo apt update && sudo apt install -y libpcap-dev python3-dev
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))

```

*(For Windows hosts: Ensure [Npcap](https://npcap.com/) is installed with "WinPcap API-compatible Mode" enabled).*

---

### 2. Environment Configuration

Clone the repository and install project dependencies inside a virtual environment:

```bash
git clone [https://github.com/om-pakhale/SecurAI.git](https://github.com/om-pakhale/SecurAI.git)
cd SecurAI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```

Create a `.env` file in the project root directory:

```env
WEBHOOK_GATEWAY_URL="http://localhost:5678/webhook-test/sentinel-alerts"
GEMINI_API_KEY="your-gemini-api-key"
DISCORD_OPERATIONS_WEBHOOK="[https://discord.com/api/webhooks/your-webhook-id/your-webhook-token](https://discord.com/api/webhooks/your-webhook-id/your-webhook-token)"

```

---

### 3. Orchestration Configuration (n8n)

1. Import the workflow definition located in `pipelines/n8n_workflow.json` into your local n8n instance.
2. Verify node parameters:
* **Webhook Node:** Method `POST`, Path `/webhook-test/sentinel-alerts`.
* **Switch Node:** Expression `{{ $json.body.Severity }}`, routing values `High` and `Critical`.
* **AI Triage Node:** Model `gemini-1.5-flash`, System Prompt configured to enforce concise, two-sentence root-cause and remediation output.
* **Discord Node:** Linked to your operational alerts channel webhook.



---

### 4. Running the Framework

Launch the inspection dashboard as an unprivileged user:

```bash
streamlit run app.py --server.port 8501

```

Access the dashboard at `http://localhost:8501`.

---

## 📁 Repository Layout

```text
├── core/
│   ├── sniffer.py               # Background Scapy DPI packet ingestion worker
│   ├── classifier.py            # ML inference engine & feature extraction logic
│   └── auditor.py               # Application-layer HTTP form crawler & tester
├── models/
│   ├── full_injection_model.pkl # Trained Random Forest model
│   ├── full_vectorizer.pkl      # Character-level TF-IDF feature map
│   └── Model_Nids.pkl           # Pre-trained NSL-KDD anomaly detector
├── pipelines/
│   ├── n8n_workflow.json        # Exportable n8n orchestration graph
│   └── prompts.py               # Constrained SecOps system prompt templates
├── app.py                       # Unprivileged Streamlit inspection portal
├── requirements.txt             # Pinned project dependencies
├── .env.example                 # Environment configuration template
└── README.md                    # System documentation

```

---

## 👨‍💻 Author

**Om Narendra Pakhale**

*B.Tech in Artificial Intelligence & Machine Learning*

*DKTE Society's Textile & Engineering Institute*

* **LinkedIn:** [linkedin.com/in/om-pakhale](https://www.google.com/search?q=https://www.linkedin.com/in/om-pakhale/)
* **HackerOne:** [hackerone.com/om0405](https://www.google.com/search?q=https://hackerone.com/om0405)
* **GitHub:** [github.com/om-pakhale](https://github.com/om-pakhale)

---

## ⚖️ Disclaimer

*Sentinel-Sec is engineered strictly for educational research, threat detection evaluation, and authorized defensive auditing. Executing active security audits or packet capture against third-party assets without explicit, prior authorization is illegal and strictly prohibited.*

```

```