import streamlit as st
import requests
import json
import pandas as pd
import joblib
import imaplib as im
import email as e
import re
import time
import os
import sys
import scapy.all as sc
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Ensure core directory is in path for db operations
sys.path.append(os.path.join(os.path.dirname(__file__), "core"))
try:
    from core.db import fetch_incident, int_insert_event, int_db
    int_db()
except Exception:
    fetch_recent_events = None
    insert_event = None

N8N_WEBHOOK_URL = "http://192.168.31.92:5678/webhook-test/sentinel-alerts"

def dispatch_incident_alert(alert_type, severity, target_info, technical_details):
    """Pipes security telemetry natively into your local n8n container."""
    payload = {
        "event_source": "Sentinel-Sec Framework Engine",
        "alert_type": alert_type,
        "severity": severity,
        "target": target_info,
        "telemetry": technical_details
    }
    try:
        time.sleep(1.5)
        # Sends data over to your n8n Webhook node asynchronously
        requests.post(N8N_WEBHOOK_URL, json=payload, headers={"Content-Type": "application/json"}, timeout=3)
    except Exception:
        pass

@st.cache_resource
def load_models():
    Selecter = joblib.load('Models/Selecter_Model.pkl')
    injection_model = joblib.load('Models/injection_model.pkl')
    vector_Model = joblib.load('Models/vectorizer.pkl')
    vector_Selecter = joblib.load('Models/Selector_Vector.pkl')
    Scanner = joblib.load('Models/email_trust_model.pkl')
    Vector = joblib.load('Models/vectorizer_email.pkl')
    return Selecter, injection_model, vector_Model, vector_Selecter, Scanner, Vector

Selecter, injection_model, vector_Model, vector_Selecter, Scanner, Vector = load_models()

st.set_page_config (
    page_title ="SecurAI Suite",
    page_icon="🛡️",
    layout = "wide"
)
st.sidebar.title("SecurSuite")
page = st.sidebar.selectbox(
    "Select The Security Tool", ["Dashboard", "Email Phishing Scanner", "Web Vulnerability Scanner", "Network Intrusion Detection"]
)
if page == "Dashboard":
    st.title("🛡️ SecurAI Suite")
    st.write("Welcome To The SecurAI Suite Powered by AI WorkStation")
    col1, col2, col3 = st.columns(3)
    col1.metric("Email Status", "Active", "Secure")
    col2.metric("Web Protection", "Ready", "Shielded")
    col3.metric("Network Monitor", "Online", "Live")

elif page == "Web Vulnerability Scanner":
    
    def get_payloads(category):
        data = []
        with open('Web_APP_PAYLOADS.jsonl', 'r', encoding='utf-8') as f:
            for line in f:
                data.append(json.loads(line))
        filtered = [p for p in data if category.lower() in p.get('id', '').lower()]
        high = [p['payload'] for p in filtered if p.get('severity') == 'high'][:5]
        med = [p['payload'] for p in filtered if p.get('severity') == 'medium'][:5]
        
        return high + med

    def inject_payload_for_param(target_url, target_param, payload):
        """
        Injects a payload into a SPECIFIC parameter while keeping 
        all other parameters set to their original values.
        """
        parsed_url = urlparse(target_url)
        params = parse_qs(parsed_url.query) 
        
        params[target_param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed_url._replace(query=new_query))
        return new_url

    st.header("AI WEB-VULNERABILITY SCANNER")
    Target_Url = st.text_input('Enter The URL')

    if st.button("Run Scanner"):
        # Make sure there are query parameters
        parsed_url = urlparse(Target_Url)
        all_params = parse_qs(parsed_url.query)
        
        if not all_params:
            st.warning("Target URL has no query parameters (e.g., '?id=1') to test.")
        else:
            st.info(f"Found {len(all_params)} parameter(s) to test: {', '.join(all_params.keys())}")
            
            data1 = vector_Selecter.transform([Target_Url])
            predict = Selecter.predict(data1)[0]

            categories = {1: "SQLi", 2: "XSS", 3: "CMD"}
            chosen_cat = categories.get(predict, "SQLi")
            payloads = get_payloads(chosen_cat)
            
            vulnerability_detected = False

            # discovered query parameter
            for param_name in all_params.keys():
                st.write(f"Testing parameter: `{param_name}`...")
                
                # Inject each payload into the url
                for p in payloads:
                    new_url = inject_payload_for_param(Target_Url, param_name, p)
                    X_auditor = vector_Model.transform([new_url])
                    result = injection_model.predict(X_auditor)[0]
                    
                    if result == 1:
                        st.error(f"🚨 ALERT: {chosen_cat} Vulnerability confirmed! Parameter: `{param_name}` | Payload: {p}")
                        vulnerability_detected = True
                        dispatch_incident_alert(
                            alert_type=f"Web Vulnerability Discovered ({chosen_cat})",
                            severity="High",
                            target_info=Target_Url,
                            technical_details={"exploited_url": new_url, "payload_used": p}
                        )
                        
                time.sleep(0.5) 
                
            if not vulnerability_detected:
                st.success("✅ ML Scan Complete: All parameters evaluated clean.")
            
elif page == "Email Phishing Scanner":
    st.title('AI-EMAIL MALWARE SCANNER')
    st.write('Scanning Latest Email phishing and Bank theart Link')

    st.markdown("Login(Don't Enter User Email Password). Pls Enter Two Way Verfication App Password ")
    col1, col2 = st.columns(2)
    with col1:
        Emailid = st.text_input("Enter Email Id :")
    with col2:
        Password = st.text_input("App Password :", type='password')

    if st.button("Run Analyes"):
        with st.status("Connecting to Gmail and running AI analysis...", expanded=True) as status:
            if Emailid and Password:
                try:
                    mail = im.IMAP4_SSL("imap.gmail.com")
                    mail.login(Emailid, Password)
                    mail.select('inbox')
                    status1, data = mail.search(None, 'ALL')
                    email_id = data[0].split()
                    scan = []
                    for i in email_id[-10:]:
                        j, msg_data = mail.fetch(i, '(RFC822)')
                        for respone in msg_data:
                            if isinstance(respone, tuple):
                                msg = e.message_from_bytes(respone[1])
                                
                                body = ""
                                if msg.is_multipart():
                                    for part in msg.walk():
                                        if part.get_content_type() == "text/plain":
                                            Raw_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                                            body = re.sub('<[^<]+?>', '', Raw_body)
                                            break
                                else:
                                    raw_body = str(msg.get_payload(decode=True))
                                    body = re.sub('<[^<]+?>', '', raw_body)
                                
                                body = body.strip().replace('\n', ' ').replace('\r', '')
                                X = Vector.transform([body])
                                prob_array = Scanner.predict_proba(X)

                                malicious_prob = prob_array.flatten()[1] 

                                if malicious_prob > 0.8:
                                    prediction = 1
                                    confidence = malicious_prob * 100
                                    dispatch_incident_alert(
                                        alert_type="Phishing Indicator Confirmed",
                                        severity="Critical",
                                        target_info=Emailid,
                                        technical_details={
                                            "from_address": msg['from'],
                                            "subject_header": msg['subject'],
                                            "malicious_probability": f"{confidence:.1f}%"
                                        }
                                    )
                                else:
                                    prediction = 0
                                    confidence = (1 - malicious_prob) * 100

                                status_text = f"🚨 MALICIOUS ({confidence:.1f}%)" if prediction == 1 else f"✅ SAFE ({confidence:.1f}%)"
                                scan.append({
                                    "Subject": msg['subject'],
                                    "From": msg['from'],
                                    "AI Verdict": status_text
                                })
                        status.update(label="Scan Complete!", state="complete", expanded=False)
                    if scan:
                        st.subheader("📊 Scan Report")
                        df = pd.DataFrame(scan)
                        st.table(df) 
                    else:
                        st.info("No emails found to scan.")
                except Exception as err:
                    st.error(f"Error during scan: {err}")

elif page == "Network Intrusion Detection":
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
        'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
        'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
        'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
        'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
        'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate'
    ]
    # Loading Data And Model in the App
    data_system = joblib.load("Models/Model_Nids.pkl")
    model = data_system['model']
    encoders = data_system['encoders']
    
    st.title("📡 SecurAI: Network Intrusion Detection")
    tab1, tab2, tab3 = st.tabs(["🔍 Intruder Detector", "🎯 Attack Simulator", "Live Packet Sniffing"])
    
    with tab1:
        st.title("Upload Network Log files")
        Data = st.file_uploader("Upload the data u want to test(.txt , .csv)", accept_multiple_files=True, type=["txt", "csv"])
        if Data:
            df_list = [pd.read_csv(file, header=None) for file in Data]
            df = pd.concat(df_list, ignore_index=True)
            df = df.iloc[:, :41]
            df.columns = columns
            st.write("Analyzing....")
            try:
                for col, encoder in encoders.items():
                    df[col] = df[col].apply(lambda x: x if x in encoder.classes_ else encoder.classes_[0]) 
                    df[col] = encoder.transform(df[col])
                predictions = model.predict(df)
                df['Prediction'] = ["Attack" if x == 1 else "Normal" for x in predictions]
                st.success("Analysis Complete!")
                st.subheader("Traffic Distribution")
                st.write(df['Prediction'].value_counts())
                st.subheader("Detailed Logs with Predictions")
                def highlight_attack(s):
                    return ['background-color:#FF0000 ' if v == 'Attack' else '' for v in s]
                if df.size > 200000:
                    st.warning(f"Dataset is large ({len(df)} rows). Displaying the top 20 ")
                    st.dataframe(df.head(20).style.apply(highlight_attack, subset=['Prediction']))
                else:
                    st.dataframe(df.style.apply(highlight_attack, subset=['Prediction']))
            except Exception as e:
                st.error(f"Error during processing: {e}")

    with tab2:
        st.subheader("Simulate Attack Impacts")
        col1, col2 = st.columns(2)
        with col1:
            attacktype = st.radio("Attack type", ["Neptune", "Satan"])
        with col2:
            OS = st.radio("Operating System", ["Windows", "Linux", "Android", "Mac"])
        
        AttackC = st.number_input("Attack Count", min_value=1000, max_value=3000)
        button = st.button("Submit")
        
        if button:
            st.write("Analyzing....")
            if attacktype == "Neptune":
                st.success("Analyzing complete")
                st.warning("🚨 WARNING: High Traffic Attack")
                if OS == "Windows":
                    st.write("Your **Windows** system's connection points are clogged, like a traffic jam. Services are timing out.")
                elif OS in ["Linux", "Mac"]:
                    st.write(f"Your {OS} kernel is struggling to process the massive flood of fake connection requests.")
                elif OS == "Android":
                    st.write("Your Android device feels frozen and is rapidly draining battery due to network overload.")
                    
            elif attacktype == "Satan":
                st.success("Analyzing complete")
                st.warning(" WARNING: System Scouting Attack")
                if OS == "Windows":
                    st.write("An attacker is knocking on every virtual door on your **Windows** machine.")
                elif OS in ["Linux", "Mac"]:
                    st.write(f"Automated tools are bombarding your {OS} ports to map vulnerabilities.")
                elif OS == "Android":
                    st.write("A high-volume port scan is hitting your Android device.")
            if 1000 < AttackC <= 1500:
                st.info("Severity: Low - The system is starting to feel slightly slow.")
            elif 1500 < AttackC <= 2000:
                st.warning("Severity: Medium - Internet activity is noticeably delayed.")
            elif 2000 < AttackC <= 2500:
                st.error("Severity: High - Core functions are failing.")
            elif 2500 < AttackC < 3000:
                st.error("Severity: Critical - The entire system has crashed.")
            else:
                st.write("No immediate threat detected in this range.")

    with tab3:
        st.header("Live Deep Packet Inspection & Sniffer")
        st.write("Monitor network frames, classify injection vectors in real time, and inspect threat telemetry.")

        # Helper to load vectorizer and model for the DPI engine
        @st.cache_resource
        def load_sniffer_ml():
            v_path = 'Models/full_vectorizer.pkl' if os.path.exists('Models/full_vectorizer.pkl') else 'full_vectorizer.pkl'
            m_path = 'Models/full_injection_model.pkl' if os.path.exists('Models/full_injection_model.pkl') else 'full_injection_model.pkl'
            vec = joblib.load(v_path)
            mdl = joblib.load(m_path)
            return vec, mdl

        try:
            dpi_vectorizer, dpi_model = load_sniffer_ml()
        except Exception as ex:
            st.error(f"Failed to load Sniffer ML models: {ex}")
            dpi_vectorizer, dpi_model = None, None

        LABEL_MAP = {0: "Clean", 1: "SQLi", 2: "XSS", 3: "CMD_Injection", "0": "Clean", "1": "SQLi", "2": "XSS", "3": "CMD_Injection"}

        col_ctrl1, col_ctrl2 = st.columns([1, 1])
        with col_ctrl1:
            packet_count = st.number_input("Packets to capture on-demand", min_value=5, max_value=50, value=10)
        with col_ctrl2:
            target_port = st.text_input("Port filter", value="80 or 8080")

        # Action Button 1: Start Scanning Packets (Live on-demand capture)
        if st.button("🚀 Start Scanning Packets"):
            if not dpi_model or not dpi_vectorizer:
                st.error("Sniffer ML models are not available.")
            else:
                packet_list = []
                alerts = []

                def process_packet(pkt):
                    if sc.IP in pkt:
                        proto = "TCP" if pkt[sc.IP].proto == 6 else "UDP" if pkt[sc.IP].proto == 17 else "Other"
                        pkt_entry = {
                            "Source IP": pkt[sc.IP].src,
                            "Destination IP": pkt[sc.IP].dst,
                            "Protocol": proto,
                            "Length": len(pkt),
                            "Status": "Safe ✅",
                            "Payload": ""
                        }

                        if pkt.haslayer(sc.Raw):
                            try:
                                payload_text = pkt[sc.Raw].load.decode('utf-8', errors='ignore')
                                pkt_entry["Payload"] = payload_text[:80]
                                if any(v in payload_text for v in ["GET ", "POST ", "PUT ", "DELETE "]):
                                    vec = dpi_vectorizer.transform([payload_text])
                                    raw_pred = dpi_model.predict(vec)[0]
                                    confidence = float(max(dpi_model.predict_proba(vec)[0])) if hasattr(dpi_model, "predict_proba") else 1.0

                                    pred_class = LABEL_MAP.get(int(raw_pred), f"Attack_{raw_pred}") if isinstance(raw_pred, (int, float)) else str(raw_pred)
                                    is_malicious = str(pred_class).lower() not in ["clean", "normal", "benign", "0"]

                                    if is_malicious and confidence > 0.65:
                                        severity = "Critical" if "SQL" in pred_class.upper() or "CMD" in pred_class.upper() else "High"
                                        pkt_entry["Status"] = f"🚨 {pred_class} ({severity})"
                                        alerts.append({
                                            "Source": f"{pkt[sc.IP].src}",
                                            "Target": f"{pkt[sc.IP].dst}",
                                            "Type": pred_class,
                                            "Severity": severity,
                                            "Payload": payload_text[:120]
                                        })
                                        
                                        # Save to local database
                                        if int_insert_event:
                                            int_insert_event(pkt[sc.IP].src, pkt[sc.IP].dst, proto, payload_text, pred_class, confidence, severity)
                                        
                                        # Dispatch to n8n
                                        dispatch_incident_alert(
                                            alert_type=f"Packet Injection Intrusion ({pred_class})",
                                            severity=severity,
                                            target_info=pkt[sc.IP].dst,
                                            technical_details={"origin": pkt[sc.IP].src, "sample": payload_text[:120]}
                                        )
                            except Exception:
                                pass
                        packet_list.append(pkt_entry)

                with st.spinner(f"Sniffing {packet_count} packets on port {target_port}..."):
                    try:
                        sc.sniff(filter=f"tcp port {target_port}", prn=process_packet, store=0, count=packet_count, timeout=8)
                        if packet_list:
                            st.success(f"Captured {len(packet_list)} packets successfully.")
                            st.dataframe(pd.DataFrame(packet_list), use_container_width=True)
                            if alerts:
                                st.error(f"🚨 {len(alerts)} Malicious Injections Detected in live stream!")
                                for alt in alerts:
                                    with st.expander(f"{alt['Severity']} {alt['Type']} from {alt['Source']}"):
                                        st.code(alt['Payload'])
                        else:
                            st.info("No packets seen within the timeout window. Send traffic to test.")
                    except Exception as exc:
                        st.error(f"Packet Capture error: {exc}")

        st.divider()

        # Database Telemetry: Shows events logged by writter_daemon.py or on-demand scan
        st.subheader("📋 Recorded Telemetry Log (from Sniffer Daemon / Database)")
        if fetch_incident:
            db_records = fetch_incident(limit=25)
            if db_records:
                df_records = pd.DataFrame(db_records, columns=[
                    "ID", "Timestamp", "Source IP", "Dest IP", "Protocol",
                    "Payload Sample", "Classification", "Confidence", "Severity"
                ])
                st.dataframe(df_records, use_container_width=True, hide_index=True)
            else:
                st.info("No detections recorded in sentinel.db yet.")
        else:
            st.warning("Database module (`core/db.py`) not found. Ensure `core/db.py` exists.")