import streamlit as st
import pandas as pd
import plotly.express as px

from threat_detection import (
    detect_failed_logins,
    detect_high_traffic
)

st.set_page_config(
    page_title="Cyber Threat Detection Dashboard",
    layout="wide"
)

st.title("🔐 Cyber Threat Detection Dashboard")

df = pd.read_csv("data/network_logs.csv")

# Metrics
st.subheader("Overview")

col1, col2, col3 = st.columns(3)

col1.metric("Total Logs", len(df))
col2.metric("Unique IPs", df["source_ip"].nunique())
col3.metric("Failed Logins",
            len(df[df["login_status"] == "Failed"]))

# Failed Login Detection

st.subheader("🚨 Suspicious Failed Login Attempts")

failed_ips = detect_failed_logins(df)

if len(failed_ips) > 0:
    st.dataframe(failed_ips)
else:
    st.success("No suspicious login activity found.")

# High Traffic Detection

st.subheader("📡 High Traffic Alerts")

traffic_alerts = detect_high_traffic(df)

if len(traffic_alerts) > 0:
    st.dataframe(traffic_alerts)
else:
    st.success("No traffic anomalies found.")

# Protocol Distribution

st.subheader("Network Protocol Distribution")

protocol_chart = px.pie(
    df,
    names="protocol",
    title="TCP vs UDP Traffic"
)

st.plotly_chart(protocol_chart, use_container_width=True)

# Traffic by Source IP

st.subheader("Traffic by Source IP")

traffic_chart = px.bar(
    df,
    x="source_ip",
    y="bytes_transferred",
    color="protocol",
    title="Bytes Transferred per Source IP"
)

st.plotly_chart(traffic_chart, use_container_width=True)

# Alerts Section

st.subheader("Generated Alerts")

for ip in failed_ips["source_ip"]:
    st.error(
        f"Multiple failed login attempts detected from {ip}"
    )

for ip in traffic_alerts["source_ip"]:
    st.warning(
        f"Unusually high traffic detected from {ip}"
    )