import streamlit as st
import pandas as pd
from pathlib import Path
from detector import analyze_logs, REQUIRED_COLUMNS

st.set_page_config(page_title="SOC Monitoring & Incident Detection", page_icon="🛡️", layout="wide")
st.title("🛡️ SOC-Based Security Monitoring and Incident Detection System")
st.caption("Academic prototype | Controlled sample logs | Rule-based detection")

with st.sidebar:
    st.header("Log Input")
    uploaded = st.file_uploader("Upload CSV security logs", type=["csv"])
    st.info("Use the included sample_logs.csv to try the demo.")

if uploaded:
    logs = pd.read_csv(uploaded)
else:
    logs = pd.read_csv(Path(__file__).parent / "data" / "sample_logs.csv")

st.subheader("1. Security Logs")
st.dataframe(logs, use_container_width=True)

missing = [c for c in REQUIRED_COLUMNS if c not in logs.columns]
if missing:
    st.error("Missing required columns: " + ", ".join(missing))
    st.stop()

alerts, processed = analyze_logs(logs)

st.subheader("2. Monitoring Summary")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total log events", len(processed))
c2.metric("Alerts generated", len(alerts))
c3.metric("High severity", int((alerts["severity"] == "HIGH").sum()) if not alerts.empty else 0)
c4.metric("Medium severity", int((alerts["severity"] == "MEDIUM").sum()) if not alerts.empty else 0)

st.subheader("3. Detection Alerts")
if alerts.empty:
    st.success("No suspicious activity detected in the supplied logs.")
else:
    st.dataframe(alerts, use_container_width=True)
    st.download_button(
        "Download alerts as CSV",
        data=alerts.to_csv(index=False).encode("utf-8"),
        file_name="soc_alerts.csv",
        mime="text/csv"
    )

st.subheader("4. Alert Distribution")
if not alerts.empty:
    counts = alerts["severity"].value_counts()
    st.bar_chart(counts)
else:
    st.write("No alerts to chart.")

st.subheader("5. Detection Rules")
st.markdown("""
- **Repeated failed logins (HIGH):** 5 or more failed login attempts from one source IP.
- **Possible port scan (MEDIUM):** 5 or more distinct destination ports contacted by one source IP.
- **Unauthorized access (HIGH):** Any denied/blocked access event.
""")
st.caption("Thresholds are configurable demo rules. This is not a production SIEM and uses simulated data.")
