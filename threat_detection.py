import pandas as pd

def detect_failed_logins(df):
    failed = df[df["login_status"] == "Failed"]

    suspicious_ips = (
        failed.groupby("source_ip")
        .size()
        .reset_index(name="failed_attempts")
    )

    suspicious_ips = suspicious_ips[
        suspicious_ips["failed_attempts"] >= 3
    ]

    return suspicious_ips


def detect_high_traffic(df):
    high_traffic = df[
        df["bytes_transferred"] > 50000
    ]

    return high_traffic