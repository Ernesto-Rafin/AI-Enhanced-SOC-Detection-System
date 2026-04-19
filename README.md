# AI-Enhanced-SOC-Detection-System
An end-to-end Security Operations Center detection pipeline that collects real Windows Event Logs and Sysmon process data, applies machine learning to detect anomalies including brute force login attacks, and forwards live security alerts into Splunk Enterprise SIEM.
What This Project Does
Most security tools catch threats they already know about. This system uses machine learning to catch unusual patterns that static rules miss. It watches login activity and system processes, automatically classifies each threat as HIGH, MEDIUM, or LOW severity, and sends the results directly into Splunk where a real SOC analyst would investigate them.
How It Works:

Step 1. Real Windows login logs and Sysmon process logs are collected and preprocessed into a combined dataset.

Step 2. An Isolation Forest machine learning model analyzes the data and flags anything that looks abnormal including brute force login attempts and suspicious PowerShell or CMD execution.

Step 3. Each detected anomaly is classified by severity and an explanation is generated automatically.

Step 4. The classified alerts are forwarded to Splunk Enterprise via HTTP Event Collector and appear as searchable events in the SIEM.

Step 5. Everything is also visualized in an interactive Streamlit dashboard with severity filtering and incident explanations.

Technologies Used:
Python, Scikit-learn, Isolation Forest, Pandas, Streamlit, Splunk Enterprise, HTTP Event Collector, Windows Event Logs, Sysmon
Project Structure
anomaly_detection.py runs the Isolation Forest model and classifies detected anomalies by severity.
preprocess_logs.py loads and merges Windows login logs and Sysmon process logs into a combined dataset.
dashboard.py builds the interactive Streamlit dashboard showing failed logins, suspicious processes, anomaly markers, and incident explanations.
send_to_splunk.py sends detected anomalies to Splunk Enterprise via HTTP Event Collector. Replace the TOKEN value with your own Splunk HEC token before running.
logs folder contains the raw Windows Event Log and Sysmon CSV data files.

How To Run This Project:
Install the required libraries:
pip install pandas scikit-learn streamlit requests urllib3
Run preprocessing:
python preprocess_logs.py
Run anomaly detection:
python anomaly_detection.py
Launch the dashboard:
streamlit run dashboard.py
Send alerts to Splunk after adding your HEC token to send_to_splunk.py:
python send_to_splunk.py
Then search in Splunk:
sourcetype=python_anomaly_detection

Key Results:
The system detected a HIGH severity brute force login attack with 5 consecutive failed login attempts from a single source and forwarded the alert to Splunk automatically without any manual rule being written.

Author
Ernesto Rafin
B.S. Information Technology Management, University of Minnesota Crookston
CompTIA Security+ | Microsoft Cybersecurity Analyst | IEEE Published Researcher
linkedin.com/in/ernesto47
