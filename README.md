# SOC-Based Security Monitoring and Incident Detection System

Academic SOC monitoring prototype built with Python, Pandas, and Streamlit.

## Features
- Read structured CSV security logs
- Preprocess timestamps and log fields
- Detect repeated failed logins (HIGH)
- Detect possible port scanning (MEDIUM)
- Detect denied/blocked access attempts (HIGH)
- Display alerts and severity summary
- Export generated alerts to CSV

## Project structure
```text
soc-monitoring-project/
├── app.py
├── detector.py
├── requirements.txt
├── README.md
├── data/
│   └── sample_logs.csv
└── tests/
    └── test_detector.py
```

## Run locally
1. Install Python 3.10 or newer.
2. Open a terminal in this project folder.
3. Create and activate a virtual environment (optional but recommended):
   ```bash
   python -m venv .venv
   ```
   Windows:
   ```bash
   .venv\Scripts\activate
   ```
   macOS/Linux:
   ```bash
   source .venv/bin/activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Start the dashboard:
   ```bash
   streamlit run app.py
   ```

## Detection thresholds
- Failed login rule: 5 failed login/authentication records from one source IP.
- Port scan rule: 5 distinct destination ports from one source IP.
- Unauthorized access rule: denied/blocked/forbidden access event.

These are simple demonstration rules and not production detection thresholds.

## Input CSV schema
`timestamp, source_ip, username, event_type, destination_ip, destination_port, status`

Supported event types:
- `login` / `authentication`
- `network` / `connection` / `port_scan`
- `access` / `resource_access` / `authorization`

## Disclaimer
This prototype uses controlled simulated data for educational demonstration. It is not a production SIEM and does not ingest live enterprise logs.
