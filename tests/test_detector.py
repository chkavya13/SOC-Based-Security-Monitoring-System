import unittest
import pandas as pd
from detector import analyze_logs

class DetectorTests(unittest.TestCase):
    def test_detects_failed_logins(self):
        rows = [{
            "timestamp": f"2026-11-03 10:15:0{i}",
            "source_ip": "10.0.0.1",
            "username": "demo",
            "event_type": "login",
            "destination_ip": "10.0.0.10",
            "destination_port": 443,
            "status": "failed"
        } for i in range(1, 6)]
        alerts, _ = analyze_logs(pd.DataFrame(rows))
        self.assertIn("Possible Brute-Force Activity", alerts["activity"].tolist())

    def test_normal_login_no_alert(self):
        row = {
            "timestamp": "2026-11-03 10:15:00",
            "source_ip": "10.0.0.2",
            "username": "demo",
            "event_type": "login",
            "destination_ip": "10.0.0.10",
            "destination_port": 443,
            "status": "success"
        }
        alerts, _ = analyze_logs(pd.DataFrame([row]))
        self.assertTrue(alerts.empty)

if __name__ == "__main__":
    unittest.main()
