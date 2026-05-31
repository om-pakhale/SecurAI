# 🛡️ Sentinel-Sec: Integrated NIDS & Web Vulnerability Framework

Sentinel-Sec is an advanced, AI-driven Security Operations (SecOps) framework that combines machine learning detection engines with local automation orchestration pipelines. It transitions standalone security auditing tools into automated microservices—detecting live application and network threats, parsing risk vectors, and executing real-time AI triage before dispatching telemetry to monitoring channels.

## 🚀 Core Features

* **AI Web-Vulnerability Scanner:** Employs trained machine learning vectorization models to detect and classify injection vectors, including SQLi, XSS, and Command (CMD) injection strings.
* **Network Intrusion Detection System (NIDS):** Ingests network logs and captures live interface traffic using `scapy` to identify anomalous or malicious network packets against pre-trained classification layers.
* **Asynchronous Telemetry Dispatcher:** Automatically bundles real-time technical exploit details into structured JSON payloads and pipes them over local network bridges.
* **Automated Triage Pipeline (n8n Integration):** Features a case-sensitive routing gateway that parses risk severities (`High` and `Critical`) to separate priority threat indicators from logging noise.
* **Context-Aware AI Triage:** Utilizes an integrated **Gemini 1.5 Flash** reasoning engine to evaluate asset context, determine exploit impact, and draft immediate engineering remediation steps in under two sentences.
* **Instant Operational Alerting:** Streams triaged threat summaries formatted in Markdown directly into a live Discord operations room feed via automated webhooks.

---

## 📐 Architecture Workflow

```text
[ Sentinel-Sec Engine ] ──( HTTP POST JSON )──> [ n8n Webhook Trigger ]
  (Streamlit App UI)                                  │
                                                      ▼
                                              [ Switch Router Node ]
                                                      │ (If High / Critical)
                                                      ▼
[ Discord Channel Feed ] <──( Markdown Alert )── [ AI Agent (Gemini 1.5 Flash) ]
🛠️ Installation & Setup
1. Prerequisites
Ensure your environment has the required system-level dependencies for live packet capture:

Bash
sudo apt update && sudo apt install libpcap-dev python3-dev -y
2. Virtual Environment Setup
Clone the repository and install the Python dependencies within an isolated environment:

Bash
git clone [https://github.com/om-pakhale/SecurAI.git](https://github.com/om-pakhale/SecurAI.git)
cd SecurAI
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
(If a requirements file is not used, install manually via: pip install streamlit requests pandas joblib scikit-learn scapy)

3. Running the Deployed Application
Because the NIDS module binds to low-level raw sockets to sniff interface traffic, the Streamlit server must be executed with root privileges (sudo) while preserving the active virtual environment path:

Bash
sudo -E env "PATH=$PATH" streamlit run app.py
🔄 Orchestration Hub Configuration (n8n)
Webhook Trigger: Configure the node to handle incoming HTTP POST requests on the local development path: /webhook-test/sentinel-alerts.

Switch Node: Set routing criteria to Rules Mode using the case-sensitive string expression {{ $json.body.Severity }}. Route strings matching High and Critical to downstream paths.

AI Agent Node: Attach a Google Gemini Chat Model sub-node running gemini-1.5-flash for high-throughput execution. Secure it using the following system prompt guardrail:

"You are an expert SecOps Triage Assistant. Review the incoming machine learning vulnerability payload. State the core impact of the asset compromise, and provide exactly one clear, actionable engineering remediation step to secure the asset. Your entire response must be concise and limited to under two sentences total."

Discord Node: Connect the output to your Discord webhook URL and pass the compiled markdown triage template.

🛡️ Engineering Validation & Troubleshooting Notes
Local Network Loopback: When deploying across distinct host/guest virtualization layers, identify the core interface via ip a (e.g., eth0) or migrate the framework natively inside the guest container environment to leverage loopback communication safely.

Strict Property Mapping: To avoid data drops at the conditional gateway, verify that your telemetry dispatch keys exactly match the capitalization parsed by n8n (e.g., matching the Python payload dictionary property "Severity" to {{ $json.body.Severity }}).

Throttling & Resource Optimization: High-frequency automation scanning loops can choke reasoning-heavy model configurations, leading to 429 Too Many Requests API errors. This framework implements a local python loop delay (time.sleep(1.5)) paired with the rapid execution thresholds of the gemini-1.5-flash model to maintain end-to-end performance.