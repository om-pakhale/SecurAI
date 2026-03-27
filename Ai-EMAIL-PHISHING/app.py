import streamlit as st
import pandas as pd
import joblib as jb
import imaplib as im
import email as e
import re

try:
    Scanner = jb.load('Models/email_trust_model.pkl')
    Vector = jb.load('Models/vectorizer_email.pkl')
except Exception as err:
    st.error(f"Failed to load AI models: {err}")

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



