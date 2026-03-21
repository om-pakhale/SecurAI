import streamlit as st
import requests
import json
import pandas as pd
import joblib
import imaplib as im
import email as e
import re
from urllib.parse import urlparse, parse_qs , urlencode , urlunparse

@st.cache_resource
def load_models():
    Selecter  = joblib.load('Models/Selecter_Model.pkl')
    injection_model =  joblib.load('Models/injection_model.pkl')
    vector_Model = joblib.load('Models/vectorizer.pkl')
    vector_Selecter = joblib.load('Models/Selector_Vector.pkl')
    Scanner = joblib.load('Models/email_trust_model.pkl')
    Vector = joblib.load('Models/vectorizer_email.pkl')
    return Selecter, injection_model, vector_Model, vector_Selecter , Scanner , Vector

Selecter, injection_model, vector_Model, vector_Selecter , Scanner , Vector = load_models()

st.set_page_config (
    page_title ="SecurAI Suite",
    page_icon="🛡️",
    layout = "wide"
)
st.sidebar.title("SecurSuite")
page = st.sidebar.selectbox(
    "Select The Security Tool" ,["Dashboard", "Email Phishing Scanner", "Web Vulnerability Scanner", "Network Intrusion Detection"]
)
if page =="Dashboard":
    st.title("🛡️ SecurAI Suite")
    st.write("Welcome To The  SecurAI Suite Powered by AI WorkStation")
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

    def inject_payload(target_url, payload):
        parsed_url = urlparse(target_url)
        params = parse_qs(parsed_url.query) 
        
        if not params:
            return target_url + payload 
        
        
        first_param = list(params.keys())[0]
        params[first_param] = [payload]
        
        # 3. Rebuild the URL
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed_url._replace(query=new_query))
        
        return new_url
    st.header("AI WEB-VULNERABILITY SCANNER")
    Target_Url = st.text_input('Enter The URls')

    if st.button("Run Scanner"):
        data1 = vector_Selecter.transform([Target_Url])
        predict = Selecter.predict(data1)[0]

        categories = {1: "SQLi", 2: "XSS" , 3 : "CMD"}
        chosen_cat = categories.get(predict,"SQLi")
        payloads = get_payloads(chosen_cat)

        for p in payloads:
            new_url =inject_payload(Target_Url , p)
            X_auditor = vector_Model.transform([new_url])
            result = injection_model.predict(X_auditor)[0]
            
            if result == 1:
                st.error(f" ALERT: {chosen_cat} Vulnerability confirmed with payload: {p}")
elif page == "Email Phishing Scanner":
    st.set_page_config(page_title="Email Scanner AI")
    st.title('AI-EMAIL MALWARE SCANNER')
    st.write('Scanning Latest Email phishing and Bank theart Link')

    st.markdown("Login(Don't Enter User Email Password). Pls Enter Two Way Verfication App Password ")
    col1 , col2 = st.columns(2)
    with col1:
        Emailid = st.text_input("Enter Email Id :")
    with col2:
        Password  = st.text_input("App Password :", type='password')

    if st.button("Run Analyes"):
        with st.status("Connecting to Gmail and running AI analysis...", expanded=True) as status:
            if Emailid and Password:
                try:
                    mail = im.IMAP4_SSL("imap.gmail.com")
                    mail.login(Emailid , Password)
                    mail.select('inbox')
                    status1 , data = mail.search(None , 'ALL')
                    email_id = data[0].split()
                    scan = []
                    for i in email_id[-10:]:
                        j , msg_data = mail.fetch(i , '(RFC822)')
                        for  respone in msg_data:
                            if isinstance(respone,tuple):
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
    data_system = jb.load("Model_Nids.pkl")
    model = data_system['model']
    encoders = data_system['encoders']
    st.title("📡 SecurAI: Network Intrusion Detection")
    tab1, tab2 , tab3 = st.tabs(["🔍 Intruder Detector", "🎯 Attack Simulator","Live Packet Sniffing"])
    with tab1:
        st.title("Upload Network Log files")
        Data = st.file_uploader("Upload the data u want to test(.txt , .csv)",accept_multiple_files=True,type=["txt","csv"])
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
                # Visualization
                st.subheader("Traffic Distribution")
                st.write(df['Prediction'].value_counts())
                # Detailed View
                st.subheader("Detailed Logs with Predictions")
                # Highlight attacks in red
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
            
            # Logic for Attack Types

            if attacktype == "Neptune":
                st.success("Analyzing complete")
                st.warning(f"🚨 WARNING: High Traffic Attack")
                if OS == "Windows":
                    st.write("Your **Windows** system's connection points are clogged, like a traffic jam. Services are timing out.")
                elif OS in ["Linux", "Mac"]:
                    st.write(f"Your {OS} kernel is struggling to process the massive flood of fake connection requests.")
                elif OS == "Android":
                    st.write(f"Your Android device feels frozen and is rapidly draining battery due to network overload.")
                    
            elif attacktype == "Satan":
                st.success("Analyzing complete")
                st.warning(f" WARNING: System Scouting Attack")
                if OS == "Windows":
                    st.write(f"An attacker is knocking on every virtual door on your **Windows** machine.")
                elif OS in ["Linux", "Mac"]:
                    st.write(f"Automated tools are bombarding your {OS} ports to map vulnerabilities.")
                elif OS == "Android":
                    st.write(f"A high-volume port scan is hitting your Android device.")
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
