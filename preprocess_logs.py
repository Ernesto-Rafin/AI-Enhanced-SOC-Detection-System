import pandas as pd

# Load windows login logs
windows = pd.read_csv("logs/windows_logs.csv")
windows["Time"] = pd.to_datetime(windows["Time"])

# Count failed logins per minute
windows["minute"] = windows["Time"].dt.floor("min")
failed = windows[windows["Status"] == "Failed"]
failed_counts = failed.groupby("minute").size().reset_index(name="failed_logins")
failed_counts.rename(columns={"minute": "_time"}, inplace=True)

# Load sysmon logs
sysmon = pd.read_csv("logs/sysmon_logs.csv")
sysmon["Time"] = pd.to_datetime(sysmon["Time"])

# Flag suspicious commands
suspicious_keywords = ["powershell -enc", "powershell -nop", "hidden", "cmd.exe /c"]
sysmon["suspicious"] = sysmon["CommandLine"].apply(
    lambda x: 1 if any(k in str(x).lower() for k in suspicious_keywords) else 0
)

# Count suspicious processes per minute
sysmon["minute"] = sysmon["Time"].dt.floor("min")
sus_counts = sysmon.groupby("minute")["suspicious"].sum().reset_index()
sus_counts.rename(columns={"minute": "_time", "suspicious": "suspicious_processes"}, inplace=True)

# Merge both
merged = pd.merge(failed_counts, sus_counts, on="_time", how="outer").fillna(0)
merged = merged.sort_values("_time").reset_index(drop=True)

# Save
merged.to_csv("combined_logs.csv", index=False)
print("Done. Combined log data saved.")
print(merged)