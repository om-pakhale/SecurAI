import streamlit as st
import requests
import json
import pandas as pd
import joblib
from urllib.parse import urlparse, parse_qs , urlencode , urlunparse

Selecter  = joblib.load('Selecter_Model.pkl')
injection_model =  joblib.load('injection_model.pkl')
vector_Model = joblib.load('vectorizer.pkl')
vector_Selecter = joblib.load('Selector_Vector.pkl')
@st.cache_resource
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
