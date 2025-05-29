import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import time
from scapy.all import sniff, IP, TCP, UDP

# Load models and encoders
scaler = joblib.load('saved_models/nids_scaler.joblib')
model = joblib.load('saved_models/nids_xgb_model.joblib')
label_encoder = joblib.load('saved_models/nids_label_encoder.joblib')
input_encoders = joblib.load('saved_models/nids_input_encoders.joblib')
selected_features = joblib.load('saved_models/nids_selected_features.joblib')

# Load state encoder and options
state_encoder = input_encoders['state']
state_options = list(state_encoder.classes_)

attack_info = {
    'Normal': 'This traffic is benign and not associated with any known cyberattacks.',
    'DoS': 'Denial-of-Service (DoS) attacks aim to make a machine or network resource unavailable.',
    'Exploits': 'Exploitation of known vulnerabilities to gain unauthorized access or execute commands.',
    'Generic': 'Generic attacks that do not fit into specific categories but are known malicious patterns.',
    'Fuzzers': 'Input fuzzing to find vulnerabilities by sending malformed or unexpected data.',
    'Reconnaissance': 'Scanning or information gathering to identify vulnerabilities.',
    'Analysis': 'Deep packet inspection and traffic analysis that could signal attacks.',
    'Backdoor': 'Unauthorized access pathways inserted by attackers.',
    'Shellcode': 'Injection of shellcode to exploit system-level vulnerabilities.',
    'Worms': 'Self-replicating malicious code aimed at spreading across networks.'
}

# 🎨 Custom cyber-themed styling
st.markdown("""
    <style>
        body, .main {
            background-color: #0f172a;
            color: #e2e8f0;
        }
        h1, h2, h3, .st-emotion-cache-10trblm, .st-emotion-cache-1v0mbdj {
            color: #38bdf8;
        }
        .stButton>button {
            background-color: #38bdf8;
            color: black;
            font-weight: bold;
            border-radius: 8px;
            padding: 8px 16px;
        }
        .stNumberInput label, .stSelectbox label {
            color: #f8fafc;
            font-weight: bold;
        }
        .stTextInput>div>div>input, .stSelectbox>div>div>select {
            background-color: #1e293b;
            color: #f8fafc;
        }
    </style>
""", unsafe_allow_html=True)

# 🚀 Title
st.title("🔐 EnGuardia – Turning Packets into Patterns. Patterns into Protection.")
st.markdown("Input the session-level network features below to predict the cyberattack type:")

# 🧾 Input form
with st.form("prediction_form"):
    col1, col2 = st.columns(2)
    with col1:
        dur = st.number_input("Duration", value=0.0)
        state = st.selectbox("State (categorical)", options=state_options)
        dpkts = st.number_input("Destination Packets", value=0.0)
        sbytes = st.number_input("Source Bytes", value=0.0)
        dbytes = st.number_input("Destination Bytes", value=0.0)
        rate = st.number_input("Packet Rate", value=0.0)
        sttl = st.number_input("Source TTL", value=0.0)
        dttl = st.number_input("Destination TTL", value=0.0)
    with col2:
        sload = st.number_input("Source Load", value=0.0)
        dload = st.number_input("Destination Load", value=0.0)
        dinpkt = st.number_input("Destination Interpacket Time", value=0.0)
        smean = st.number_input("Source Mean Packet Size", value=0.0)
        dmean = st.number_input("Destination Mean Packet Size", value=0.0)
        ct_state_ttl = st.number_input("Connection State/TTL", value=0.0)
        ct_srv_dst = st.number_input("Connections to Same Service", value=0.0)
        ct_flw_http_mthd = st.number_input("HTTP Method Count", value=0.0)

    submitted = st.form_submit_button("🔍 Predict Attack Type")

if submitted:
    try:
        input_data = {
            'dur': dur,
            'state': state_encoder.transform([state])[0],
            'dpkts': dpkts,
            'sbytes': sbytes,
            'dbytes': dbytes,
            'rate': rate,
            'sttl': sttl,
            'dttl': dttl,
            'sload': sload,
            'dload': dload,
            'dinpkt': dinpkt,
            'smean': smean,
            'dmean': dmean,
            'ct_state_ttl': ct_state_ttl,
            'ct_srv_dst': ct_srv_dst,
            'ct_flw_http_mthd': ct_flw_http_mthd
        }

        X = pd.DataFrame([input_data])[selected_features]
        X_scaled = scaler.transform(X)

        proba = model.predict_proba(X_scaled)[0]
        pred_idx = np.argmax(proba)
        predicted_class = label_encoder.inverse_transform([pred_idx])[0]
        confidence = proba[pred_idx]

        st.success(f"🛡️ Predicted Attack Type: **{predicted_class}**")
        st.info(f"Confidence: **{confidence:.2%}**")

        # 🔎 Show attack info immediately
        st.markdown("## 🧠 Attack Insights")
        st.markdown(attack_info.get(predicted_class, "No description available."), unsafe_allow_html=True)

    except Exception as e:
        st.error(f"❌ Prediction failed: {e}")

# 🔄 Real-time monitoring with Scapy
st.markdown("---")
st.header("📡 Live Packet Classification with Scapy")

if st.button("▶️ Start Real-Time Capture"):
    st.info("Capturing 10 packets using Scapy. Please wait...")
    captured_data = []

    def packet_callback(packet):
        try:
            features = {
                'dur': 0.01,
                'state': 'FIN' if packet.haslayer(TCP) and packet[TCP].flags == 0x01 else 'CON',
                'dpkts': 1,
                'sbytes': len(packet[IP].payload) if packet.haslayer(IP) else 0,
                'dbytes': 0,
                'rate': 0.5,
                'sttl': packet[IP].ttl if packet.haslayer(IP) else 0,
                'dttl': packet[IP].ttl - 1 if packet.haslayer(IP) else 0,
                'sload': 1000,
                'dload': 500,
                'dinpkt': 0.02,
                'smean': len(packet[IP].payload) if packet.haslayer(IP) else 0,
                'dmean': 0,
                'ct_state_ttl': 1,
                'ct_srv_dst': 2,
                'ct_flw_http_mthd': 0
            }

            for f in selected_features:
                if f in input_encoders:
                    features[f] = input_encoders[f].transform([str(features[f])])[0]

            X_live = pd.DataFrame([features])[selected_features]
            X_scaled_live = scaler.transform(X_live)
            proba_live = model.predict_proba(X_scaled_live)[0]
            pred_idx = np.argmax(proba_live)
            pred_class = label_encoder.inverse_transform([pred_idx])[0]
            confidence = proba_live[pred_idx]

            captured_data.append((pred_class, confidence))
            st.markdown(f"🔍 **{pred_class}** | Confidence: `{confidence:.2%}`")
        except Exception as e:
            st.warning(f"Packet processing failed: {e}")

    sniff(count=10, prn=packet_callback, store=False)
    st.success("✅ Real-time capture completed.")
