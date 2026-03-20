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

