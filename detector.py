import pandas as pd

REQUIRED_COLUMNS = [
    "timestamp", "source_ip", "username", "event_type",
    "destination_ip", "destination_port", "status"
]

def preprocess_logs(logs: pd.DataFrame) -> pd.DataFrame:
    """Validate and normalize structured security logs."""
    df = logs.copy()
    missing = [column for column in REQUIRED_COLUMNS if column not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["source_ip"] = df["source_ip"].astype(str).str.strip()
    df["event_type"] = df["event_type"].astype(str).str.lower().str.strip()
    df["status"] = df["status"].astype(str).str.lower().str.strip()
    df["destination_port"] = pd.to_numeric(df["destination_port"], errors="coerce")
    df = df.dropna(subset=["timestamp", "source_ip", "event_type", "status"])
    return df

def analyze_logs(logs: pd.DataFrame, failed_login_threshold: int = 5,
                 port_scan_threshold: int = 5):
    """Apply simple SOC-style detection rules and return (alerts, processed_logs)."""
    df = preprocess_logs(logs)
    alerts = []

    # Rule 1: repeated failed authentication attempts from one source IP.
    failed = df[
        (df["event_type"].isin(["login", "authentication"])) &
        (df["status"].isin(["failed", "failure", "denied"]))
    ]
    for source_ip, group in failed.groupby("source_ip"):
        if len(group) >= failed_login_threshold:
            alerts.append({
                "timestamp": group["timestamp"].max().isoformat(),
                "source_ip": source_ip,
                "activity": "Possible Brute-Force Activity",
                "severity": "HIGH",
                "reason": f"{len(group)} failed authentication events from the same source",
                "recommended_action": "Investigate source and review account activity"
            })

    # Rule 2: possible port scanning based on distinct destination ports.
    network = df[df["event_type"].isin(["network", "connection", "port_scan"])]
    for source_ip, group in network.groupby("source_ip"):
        ports = group["destination_port"].dropna().nunique()
        if ports >= port_scan_threshold:
            alerts.append({
                "timestamp": group["timestamp"].max().isoformat(),
                "source_ip": source_ip,
                "activity": "Possible Port Scan",
                "severity": "MEDIUM",
                "reason": f"Source contacted {ports} distinct destination ports",
                "recommended_action": "Review network activity and destination ports"
            })

    # Rule 3: denied access to protected resources.
    denied = df[
        (df["event_type"].isin(["access", "resource_access", "authorization"])) &
        (df["status"].isin(["denied", "blocked", "forbidden"]))
    ]
    for _, row in denied.iterrows():
        alerts.append({
            "timestamp": row["timestamp"].isoformat(),
            "source_ip": row["source_ip"],
            "activity": "Unauthorized Access Attempt",
            "severity": "HIGH",
            "reason": f"Access attempt by {row['username']} was denied",
            "recommended_action": "Investigate access attempt and verify permissions"
        })

    alert_df = pd.DataFrame(alerts, columns=[
        "timestamp", "source_ip", "activity", "severity", "reason", "recommended_action"
    ])
    if not alert_df.empty:
        alert_df = alert_df.sort_values("timestamp").reset_index(drop=True)
    return alert_df, df
