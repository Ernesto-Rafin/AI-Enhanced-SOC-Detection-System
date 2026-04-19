import pandas as pd
from sklearn.ensemble import IsolationForest

# Load combined real log data
df = pd.read_csv("combined_logs.csv")
df["_time"] = pd.to_datetime(df["_time"])

# Fill missing values
df["failed_logins"] = df["failed_logins"].fillna(0)
df["suspicious_processes"] = df["suspicious_processes"].fillna(0)

# Train model on both features
model = IsolationForest(contamination=0.4, random_state=42)
df["anomaly"] = model.fit_predict(df[["failed_logins", "suspicious_processes"]])

# Convert output
df["anomaly_label"] = df["anomaly"].map({1: "NORMAL", -1: "ANOMALY"})

# Filter anomalies
anomalies = df[df["anomaly_label"] == "ANOMALY"].copy()

# Add severity and explanation
def classify_incident(row):
    if row["failed_logins"] >= 5:
        return pd.Series([
            "HIGH",
            f"HIGH severity: {int(row['failed_logins'])} failed logins detected from single source. Possible brute-force or unauthorized access attempt."
        ])
    elif row["suspicious_processes"] >= 2:
        return pd.Series([
            "HIGH",
            f"HIGH severity: {int(row['suspicious_processes'])} suspicious processes detected including encoded PowerShell or hidden execution commands."
        ])
    elif row["suspicious_processes"] == 1:
        return pd.Series([
            "MEDIUM",
            f"MEDIUM severity: Suspicious process activity detected. Review PowerShell or CMD execution logs immediately."
        ])
    else:
        return pd.Series([
            "LOW",
            "LOW severity: Anomalous activity detected. Review logs for unusual patterns."
        ])

anomalies[["severity", "explanation"]] = anomalies.apply(classify_incident, axis=1)

# Print results
print("\n=== DETECTED ANOMALIES ===")
print(anomalies[["_time", "failed_logins", "suspicious_processes", "severity"]])

print("\n=== ANOMALY EXPLANATIONS ===")
for _, row in anomalies.iterrows():
    print(f"\n[{row['severity']}] {row['_time']}")
    print(f"  Failed Logins: {int(row['failed_logins'])} | Suspicious Processes: {int(row['suspicious_processes'])}")
    print(f"  {row['explanation']}")

# Save results
anomalies.to_csv("detected_anomalies.csv", index=False)
print("\nSaved to detected_anomalies.csv")