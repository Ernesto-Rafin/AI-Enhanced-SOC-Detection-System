import requests
import pandas as pd
import json
import urllib3

# Suppress SSL warnings since we disabled SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Splunk HEC settings
SPLUNK_URL = "http://localhost:8088/services/collector/event"
TOKEN = "your-splunk-hec-token-here"

# Load detected anomalies
anomalies = pd.read_csv("detected_anomalies.csv")
anomalies["_time"] = pd.to_datetime(anomalies["_time"])

headers = {
    "Authorization": f"Splunk {TOKEN}",
    "Content-Type": "application/json"
}

print("Sending anomalies to Splunk...")

for _, row in anomalies.iterrows():
    event = {
        "time": row["_time"].timestamp(),
        "sourcetype": "python_anomaly_detection",
        "source": "AI-SOC-Detection-System",
        "event": {
            "failed_logins": row["failed_logins"],
            "suspicious_processes": row["suspicious_processes"],
            "severity": row["severity"],
            "anomaly_label": row["anomaly_label"],
            "explanation": row["explanation"]
        }
    }

    response = requests.post(
        SPLUNK_URL,
        headers=headers,
        data=json.dumps(event),
        verify=False
    )

    if response.status_code == 200:
        print(f"Sent [{row['severity']}] anomaly at {row['_time']}")
    else:
        print(f"Error: {response.status_code} — {response.text}")

print("\nDone. Check Splunk search: sourcetype=python_anomaly_detection")