import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="AI-Enhanced SOC Detection Dashboard", layout="wide")

st.title("AI-Enhanced SOC Detection Dashboard")
st.write("Real Windows + Sysmon log data | Isolation Forest anomaly detection | Incident explanations")

# Load real combined data
df = pd.read_csv("combined_logs.csv")
df["_time"] = pd.to_datetime(df["_time"])

# Load anomalies
anomalies = pd.read_csv("detected_anomalies.csv")
anomalies["_time"] = pd.to_datetime(anomalies["_time"])

# Sidebar filter
severity_filter = st.selectbox("Filter by Severity", ["ALL", "HIGH", "MEDIUM", "LOW"])
filtered = anomalies.copy()
if severity_filter != "ALL":
    filtered = anomalies[anomalies["severity"] == severity_filter]

# KPI metrics
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Time Points", len(df))
col2.metric("Total Failed Logins", int(df["failed_logins"].sum()))
col3.metric("Suspicious Processes", int(df["suspicious_processes"].sum()))
col4.metric("Detected Anomalies", len(anomalies))

# Alert banners
high_alerts = anomalies[anomalies["severity"] == "HIGH"]
medium_alerts = anomalies[anomalies["severity"] == "MEDIUM"]
if not high_alerts.empty:
    st.error(f"🚨 {len(high_alerts)} HIGH severity incidents detected — Immediate action required!")
if not medium_alerts.empty:
    st.warning(f"⚠️ {len(medium_alerts)} MEDIUM severity incidents detected — Review recommended.")

# Chart
st.subheader("Failed Login Activity + Suspicious Processes Over Time")
plt.style.use("dark_background")
fig, ax1 = plt.subplots(figsize=(14, 5))

# Failed logins line
ax1.plot(df["_time"], df["failed_logins"], 
         label="Failed Logins", color="#4dabf7", linewidth=2)
ax1.set_ylabel("Failed Logins", color="#4dabf7")

# Suspicious processes on second axis
ax2 = ax1.twinx()
ax2.bar(df["_time"], df["suspicious_processes"], 
        label="Suspicious Processes", color="#ff922b", alpha=0.5, width=0.003)
ax2.set_ylabel("Suspicious Processes", color="#ff922b")

# Plot anomaly markers
colors = {"HIGH": "#ff4b4b", "MEDIUM": "#f4b400", "LOW": "#00c853"}
for severity in ["HIGH", "MEDIUM", "LOW"]:
    subset = filtered[filtered["severity"] == severity]
    if not subset.empty:
        ax1.scatter(subset["_time"], subset["failed_logins"],
                   label=f"{severity} Anomaly", color=colors[severity], 
                   s=120, zorder=5)

ax1.set_facecolor("#0e1117")
fig.patch.set_facecolor("#0e1117")
ax1.set_title("SOC Detection — Real Log Analysis", color="white")
ax1.set_xlabel("Time", color="white")
ax1.tick_params(colors="white")
ax2.tick_params(colors="white")

lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper right")

plt.xticks(rotation=45)
st.pyplot(fig)

# Two column layout
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Detected Anomalies Table")
    st.dataframe(filtered[["_time", "failed_logins", 
                           "suspicious_processes", "severity"]], 
                use_container_width=True)

with col_right:
    st.subheader("Sysmon — Suspicious Process Log")
    sysmon = pd.read_csv("logs/sysmon_logs.csv")
    st.dataframe(sysmon, use_container_width=True)

# Incident explanations
st.subheader("Incident Explanations")
if filtered.empty:
    st.info("No incidents match the selected severity filter.")
else:
    for _, row in filtered.iterrows():
        if row["severity"] == "HIGH":
            st.error(f"🔴 [{row['severity']}] {row['_time']} — {row['explanation']}")
        elif row["severity"] == "MEDIUM":
            st.warning(f"🟡 [{row['severity']}] {row['_time']} — {row['explanation']}")
        else:
            st.info(f"🟢 [{row['severity']}] {row['_time']} — {row['explanation']}")

# Footer
st.markdown("---")
st.caption("Built by Ernesto Rafin | Python + Scikit-learn Isolation Forest + Streamlit | Data: Windows Event Logs + Sysmon")