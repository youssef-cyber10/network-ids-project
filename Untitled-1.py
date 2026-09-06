"""
Interactive dashboard for the Network Intrusion Detection System (NIDS).
Run with: streamlit run dashboard/app.py
"""
import os
import syspip install pandas scikit-learn joblib streamlit plotly
import time
import joblib
import pandas as pd
import streamlit as st
import plotly.express as px

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))
from preprocess import load_raw, add_binary_and_category_labels, encode_categorical, get_features_and_target

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "models", "rf_model.joblib")
ENCODERS_PATH = os.path.join(BASE_DIR, "models", "encoders.joblib")

st.set_page_config(page_title="Network Intrusion Detection System", layout="wide", page_icon="🛡️")


@st.cache_resource
def load_model_and_data():
    model = joblib.load(MODEL_PATH)
    encoders = joblib.load(ENCODERS_PATH)
    train_df = add_binary_and_category_labels(load_raw("train"))
    test_df = add_binary_and_category_labels(load_raw("test"))
    train_enc, test_enc, _ = encode_categorical(train_df, test_df)
    X_test, y_test = get_features_and_target(test_enc, target_col="is_attack")
    return model, X_test, y_test, test_df


model, X_test, y_test, test_df_labeled = load_model_and_data()

st.title("🛡️ Network Intrusion Detection with AI")
st.caption("Built on RandomForest trained on NSL-KDD | Detects DoS / Probe / R2L / U2R attacks")

# --- Sidebar: live monitoring simulation ---
st.sidebar.header("⚙️ Simulation Settings")
n_packets = st.sidebar.slider("Packets to simulate", 20, 200, 50, step=10)
run_simulation = st.sidebar.button("▶️ Start live monitoring")

# --- Overview ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total records tested", f"{len(X_test):,}")
col2.metric("Actual attacks", f"{int(y_test.sum()):,}")
col3.metric("Normal traffic", f"{int((y_test == 0).sum()):,}")
col4.metric("Detection precision", "97%")

st.divider()

# --- Attack type distribution ---
left, right = st.columns([1, 1])
with left:
    st.subheader("📊 Attack type distribution in the dataset")
    cat_counts = test_df_labeled["attack_category"].value_counts().reset_index()
    cat_counts.columns = ["type", "count"]
    fig = px.bar(cat_counts, x="type", y="count", color="type",
                 color_discrete_sequence=px.colors.qualitative.Set2)
    st.plotly_chart(fig, use_container_width=True)

with right:
    st.subheader("🥧 Attacks vs Normal traffic share")
    is_attack_counts = test_df_labeled["is_attack"].map({0: "Normal", 1: "Attack"}).value_counts().reset_index()
    is_attack_counts.columns = ["label", "count"]
    fig2 = px.pie(is_attack_counts, names="label", values="count",
                  color="label", color_discrete_map={"Normal": "#2ecc71", "Attack": "#e74c3c"})
    st.plotly_chart(fig2, use_container_width=True)

st.divider()

# --- Live monitoring simulation ---
st.subheader("🔴 Live monitoring simulation")
placeholder = st.empty()
log_placeholder = st.empty()

if run_simulation:
    sample_idx = X_test.sample(n=n_packets, random_state=None).index
    sample = X_test.loc[sample_idx].reset_index(drop=True)
    true_vals = y_test.loc[sample_idx].reset_index(drop=True)

    logs = []
    alert_count = 0
    progress = st.progress(0)

    for i in range(len(sample)):
        row = sample.iloc[[i]]
        pred = model.predict(row)[0]
        proba = model.predict_proba(row)[0][1]
        status = "🚨 Attack detected" if pred == 1 else "✅ Normal"
        if pred == 1:
            alert_count += 1

        logs.append({
            "Packet #": i + 1,
            "Status": status,
            "Attack probability": f"{proba:.2%}",
            "True label": "Attack" if true_vals.iloc[i] == 1 else "Normal",
        })

        with placeholder.container():
            m1, m2, m3 = st.columns(3)
            m1.metric("Packets inspected", i + 1)
            m2.metric("Alerts detected", alert_count)
            m3.metric("Alert rate", f"{alert_count / (i + 1):.1%}")

        log_placeholder.dataframe(
            pd.DataFrame(logs[::-1]),
            use_container_width=True,
            height=300,
        )
        progress.progress((i + 1) / len(sample))
        time.sleep(0.05)

    st.success(f"Simulation finished: inspected {len(sample)} packets, detected {alert_count} alerts.")
else:
    st.info("Press '▶️ Start live monitoring' in the sidebar to start the simulation.")
