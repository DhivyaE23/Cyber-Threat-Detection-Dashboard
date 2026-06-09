import pandas as pd
from threat_detection import detect_failed_logins
from threat_detection import detect_high_traffic

df = pd.read_csv("data/network_logs.csv")

print("Failed Login Detection")
print(detect_failed_logins(df))

print("\nHigh Traffic Detection")
print(detect_high_traffic(df))