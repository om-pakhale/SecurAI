# All libarys Required
import streamlit as st
import pandas as pd
import joblib
import os
import requests as rp
from bs4 import BeautifulSoup as b
from urllib.parse import urljoin
import scapy.all as sc
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report


# Traing Model Path
TRAIN_DATA_PATH = "KDDTrain+.txt"
MODEL_PATH = "Model_Nids.pkl"
model2 = joblib.load('full_injection_model.pkl')
vector = joblib.load('full_vectorizer.pkl')

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
    'dst_host_srv_rerror_rate', 'attack', 'level'
]

# ---------------- LOGIC: MODEL TRAINING & LOADING ----------------
@st.cache_resource
def get_model():
    # 1. Try to load existing model
    if os.path.exists(MODEL_PATH):
        print("Loading existing model...")
        return joblib.load(MODEL_PATH)
    else:
        print("Model not found. Training new model...")
        if not os.path.exists(TRAIN_DATA_PATH):
            st.error(f"Error: {TRAIN_DATA_PATH} not found. Please upload the training dataset.")
            return None

        # --- LOGIC FROM PROJECT.PY ---
        df = pd.read_csv(TRAIN_DATA_PATH, header=None, names=columns)
        df['attack'] = df['attack'].str.strip()
        df['attack'] = df['attack'].apply(lambda x: 0 if x == 'normal' else 1)
        
        categorical_cols = ['protocol_type', 'service', 'flag']
        encoders = {} 
        for col in categorical_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            encoders[col] = le
            
        X = df.iloc[:, 0:41]
        y = df['attack']
        
        Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, random_state=11, test_size=0.2)
        rf = RandomForestClassifier(n_estimators=100, random_state=11)
        rf.fit(Xtrain, ytrain)
        
        # Save logic
        data_to_save = {
            'model': rf,
            'encoders': encoders
        }
        joblib.dump(data_to_save, MODEL_PATH)
        return data_to_save

# ---------------- UI: STREAMLIT APP ----------------
data_system = get_model()

if data_system is None:
    st.error("Could not load or train model. Please check dataset availability.")
else:
    model = data_system['model']
    encoders = data_system['encoders']

    # Header
    home = st.sidebar.radio("Chose The Model", ["Intruder Detector", "Attacker Check(Opearthing System)","Live Detection","Web Vulnerability Scanner","Financial Fraud Analyzer"])


    # --- TAB 1: INTRUDER DETECTOR ---
    if home == "Intruder Detector":
        st.header("Network Intrusion Detection system")
        st.title("Upload Network Log files")
        Data = st.file_uploader("Upload the data u want to test(.txt , .csv)", accept_multiple_files=True, type=["txt", "csv", "exl"])
        
        if Data:
            df_list = [pd.read_csv(file, header=None) for file in Data]
            df = pd.concat(df_list, ignore_index=True)
            if df.shape[1] > 41:
                df = df.iloc[:, :41]
            df.columns = columns[:41] 
            
            st.write("Analyzing....")
            try:
                # Apply Encoders
                for col, encoder in encoders.items():
                    if col in df.columns:
                        df[col] = df[col].apply(lambda x: x if x in encoder.classes_ else encoder.classes_[0]) 
                        df[col] = encoder.transform(df[col])
                
                predictions = model.predict(df)
                df['Prediction'] = ["Attack" if x == 1 else "Normal" for x in predictions]
                
                st.success("Analysis Complete!")
                
                # Visualization
                st.subheader("Traffic Distribution")
                st.write(df['Prediction'].value_counts())
                st.subheader("Detailed Logs with Predictions") 
                def highlight_attack(s):
                    return ['background-color:#FF0000' if v == 'Attack' else '' for v in s]
                
                if df.size > 200000:
                    st.warning(f"Dataset is large ({len(df)} rows). Displaying the top 20.")
                    st.dataframe(df.head(20).style.apply(highlight_attack, subset=['Prediction']))
                else:
                    st.dataframe(df.style.apply(highlight_attack, subset=['Prediction']))
                    
            except Exception as e:
                st.error(f"Error during processing: {e}")



    # --- TAB 2: ATTACK CHECKER ---
    elif home == "Attacker Check(Opearthing System)":
        st.header("Network Intrusion Detection system")
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


 # ============LIVE DETECTION==================================================

    elif home == "Live Detection":
            st.header("Live Detection Model")
            st.warning("🚨 This will scan your live Network log.")
            
            if st.button("Start Live Scan"):
                packet_list = []
                alt =  []
                def Packet_1(packet):
                    if sc.IP in packet:
                        p_type = "Tcp" if packet[sc.IP].proto == 6 else "UDP" if packet[sc.IP].proto == 17 else "Other"
                        packet_info = {
                                "Source IP": packet[sc.IP].src,
                                "Destination IP": packet[sc.IP].dst,
                                "Protocol": p_type,
                                "Length": len(packet),
                                "Info": packet.summary(),
                                "Status": "Safe ✅" 
                                        }

                        # from here code to check if packet kar contein Malious or not
                        if packet.haslayer(sc.Raw):
                            try:
                                payload = packet[sc.Raw].load.decode(errors='ignore')
                                if 'GET' in payload or 'POST' in payload:
                                    transformed_payload = vector.transform([payload])
                                    prediction = model.predict(transformed_payload)

                                    if prediction[0] == 1:
                                        packet_info["Status"] = "🚨 ATTACK"
                                        alt.append({
                                            "Time": packet.summary().split()[0],
                                            "Source": f"{packet[sc.IP].src}:{packet[sc.TCP].sport if packet.haslayer(sc.TCP) else 'N/A'}",
                                            "Payload": payload[:100] # Capture first 100 chars
                                        })
                            except Exception as e:
                                    pass
                        packet_list.append(packet_info)
                with st.spinner("Sniffing 10 packets..."):
                    try:
                        # Added timeout to prevent infinite hang
                        sc.sniff(filter ='tcp port 80',prn=Packet_1, store=0, count=10, timeout=10)
                        if packet_list:
                            live_data = pd.DataFrame(packet_list)
                            st.dataframe(live_data)
                            if alt:
                                st.error(f"🚨 {len(alt)} Potential Injection Attacks Detected!")
                                for alert in alt:
                                    with st.expander(f"Attack from {alert['Source']}"):
                                        st.code(alert['Payload'], language="sql")
                            else:
                                st.success("No malicious injections detected in these 10 packets.")
                            if not live_data[live_data['Length'] > 1000].empty:
                                st.error("🚨 Large packets detected in traffic!")
                            else:
                                st.success("No immediate traffic issues detected.")
                        else:
                            st.error("No packets captured. Ensure you are running with sudo.")
                    except Exception as e:
                        st.error(f"Error capturing packets: {e}")


# =======Web Vulnerability Scanner=========#
    elif home == "Web Vulnerability Scanner":
        st.header("Web Vulnerability Scanner")

        url = st.text_input("Upload Url")
        xss = "<script>alert('Vulnerable')</script>"
        def get(url):
            try:
                    r = rp.get(url , timeout=5)
                    s = b(r.text ,'html.parser')
                    return s.find_all('form')
            except Exception as e:
                        st.write(f"[-] Error fetching {url}: {e}")
                        return []
        def vulnerability(url):
                forms = get(url)
                for form in forms:
                    action = form.attrs.get("action")
                    post_url = urljoin(url, action)

                    # Get all input fields (name and type)
                    inputs = form.find_all('input')
                    method = form.attrs.get("method", "get").lower()
                    data ={}
                    for input_tag in inputs:
                            input_name = input_tag.attrs.get("name")
                            input_type = input_tag.attrs.get("type", "text")
                            if input_type in ["text", "search"]:
                                data[input_name] = xss
                            if method == "post":
                                res = rp.post(post_url, data=data)
                            else:
                                res = rp.get(post_url, params=data)
                            if xss in res.text:
                                st.warning(f"XSS potential detected at {post_url} ")

                            errors = ["you have an error in your sql syntax", "unclosed quotation mark", "mysql_fetch_array"]
                            for error in errors:
                                if error in res.text.lower():
                                    st.warning(f"SQL Injection potential detected at {post_url}")
                                    break                         
        if st.button("Start Vulnerability Scan"):
            if url:
                vulnerability(url)
            else:
                st.warning("Please enter a URL first.")

    elif home == "Financial Fraud Analyzer":
        st.header("Financial Fraud & CDR Analyzer")
        st.info("Upload Bank Logs, UPI Transactions, or Call Detail Records (CDR) for instant pattern analysis.")

        upload_file = st.file_uploader("Upload Excel or CSV file", type=["csv", "xlsx"])

        if upload_file is not None:
            st.write("Analyzing records...")
            try:
                if upload_file.name.endswith('.csv'):
                    df = pd.read_csv(upload_file)
                else:
                    df = pd.read_excel(upload_file)

                st.success(f"Successfully loaded {len(df)} records into the database.")
    
                with st.expander("View Raw Data Preview"):
                    st.dataframe(df.head(10))
                
                st.subheader("1. Identify Repeat Suspects")
                id_col = st.selectbox("Select the column containing Phone Numbers / UPI IDs:", df.columns)
                
                if st.button("Scan for Repeat Offenders"):
                    repeats = df[id_col].value_counts().head(10)
                    st.error("🚨 Top 10 Most Frequent Entities Detected:")
                    st.dataframe(repeats)


                st.subheader("2. Filter High-Value Transactions")
                numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
                
                if numeric_cols:
                    amt_col = st.selectbox("Select the column containing Transaction Amounts (₹):", numeric_cols)
                    threshold = st.number_input("Enter Minimum Amount Threshold (₹):", min_value=0, value=50000)
                    
                    if st.button("Filter High-Value Targets"):
                        high_value_df = df[df[amt_col] >= threshold]
                        st.warning(f"Found {len(high_value_df)} transactions above ₹{threshold}!")
                        st.dataframe(high_value_df)
                else:
                    st.write("No numeric columns detected for amount filtering.")


                st.subheader("3. Instant Suspect Cross-Reference")
                search_query = st.text_input("Enter specific UPI ID, Bank Account, or Phone Number to search:")
                
                if search_query:
                    mask = df.astype(str).apply(lambda x: x.str.contains(search_query, case=False, na=False)).any(axis=1)
                    results = df[mask]
                    
                    if not results.empty:
                        st.success(f"Target Acquired: Found {len(results)} matching records!")
                        st.dataframe(results)
                    else:
                        st.success("Target Clear: No matches found in this dataset.")

            except Exception as e:
                st.error(f"Error processing the file: Please ensure it is a valid CSV or Excel file. Details: {e}")
                        

                