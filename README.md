# AI-Enhanced SOC Detection System

An end-to-end Security Operations Center detection pipeline that collects real Windows Event Logs and Sysmon process data, applies machine learning to detect anomalies including brute force login attacks, and forwards live security alerts into Splunk Enterprise SIEM.

## What This Project Does

Most security tools catch threats they already know about. This system uses machine learning to catch unusual patterns that static rules miss. It watches login activity and system processes, automatically classifies each threat as HIGH, MEDIUM, or LOW severity, and sends the results directly into Splunk where a real SOC analyst would investigate them.

## How It Works

- Step 1: Real Windows login logs and Sysmon process logs are collected and preprocessed into a combined dataset.
- Step 2: An Isolation Forest machine learning model analyzes the data and flags anything abnormal including brute force login attempts and suspicious PowerShell or CMD execution.
- Step 3: Each detected anomaly is classified by severity and an explanation is generated automatically.
- Step 4: Classified alerts are forwarded to Splunk Enterprise via HTTP Event Collector.
- Step 5: Everything is visualized in an interactive Streamlit dashboard with severity filtering.

## Technologies Used

Python, Scikit-learn, Isolation Forest, Pandas, Streamlit, Splunk Enterprise, HTTP Event Collector, Windows Event Logs, Sysmon

## Project Structure

| File | Description |
|------|-------------|
| anomaly_detection.py | Runs Isolation Forest and classifies anomalies by severity |
| preprocess_logs.py | Merges Windows login logs and Sysmon process logs |
| dashboard.py | Interactive Streamlit dashboard with incident explanations |
| send_to_splunk.py | Sends detected anomalies to Splunk via HTTP Event Collector |

## How To Run

```bash
pip install pandas scikit-learn streamlit requests urllib3
python preprocess_logs.py
python anomaly_detection.py
streamlit run dashboard.py
python send_to_splunk.py
```

Search in Splunk: sourcetype=python_anomaly_detection

## Key Results

The system detected a HIGH severity brute force attack with 5 consecutive failed login attempts from a single source and forwarded the alert to Splunk automatically without any manual rule being written.

## Author

**Ernesto Rafin**

B.S. Information Technology Management, University of Minnesota Crookston

CompTIA Security+ | Microsoft Cybersecurity Analyst | IEEE Published Researcher

[linkedin.com/in/ernesto47](https://linkedin.com/in/ernesto47)
