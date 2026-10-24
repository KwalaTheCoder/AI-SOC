import os
import json
import unittest

os.environ.setdefault("SOC_API_TOKEN", "")

import soc_server as soc


class SecurityAndDetectionTests(unittest.TestCase):
    def setUp(self):
        soc._ASSET_MAP.clear()

    def test_destination_asset_is_enriched(self):
        soc._ASSET_MAP["192.0.2.1"] = {
            "hostname": "dc01", "role": "domain-controller", "criticality": "critical"
        }
        ecs = soc.to_ecs({"src_ip": "203.0.113.9", "dest_ip": "192.0.2.1"})
        self.assertEqual(ecs["source.hostname"], "dc01")
        self.assertEqual(ecs["source.asset_criticality"], "critical")

    def test_old_login_failures_do_not_trigger_current_window(self):
        events = [
            {"timestamp": f"2026-07-21T10:0{i}:00", "src_ip": "203.0.113.9",
             "action": "LOGIN_FAILED", "severity": "WARNING", "event_type": "ssh"}
            for i in range(6)
        ]
        events.append({
            "timestamp": "2026-07-21T12:00:00", "src_ip": "203.0.113.9",
            "action": "LOGIN_FAILED", "severity": "INFO", "event_type": "ssh"
        })
        self.assertEqual(soc.detect_suspicious(events), [])

    def test_invalid_recent_limit_returns_400(self):
        with soc.app.test_client() as client:
            response = client.get("/recent-events?limit=not-a-number")
        self.assertEqual(response.status_code, 400)

    def test_upload_limit_is_configured(self):
        self.assertGreater(soc.app.config["MAX_CONTENT_LENGTH"], 0)

    def test_enriched_event_is_json_serializable(self):
        event = {"timestamp": "2026-07-21T14:36:58", "src_ip": "127.0.0.1"}
        event["_ecs"] = soc.to_ecs(event)
        json.dumps(event)

    def test_failed_logins_are_not_deduplicated(self):
        events = [
            {"timestamp": f"2026-07-21T14:44:5{i}", "src_ip": "203.0.113.50",
             "action": "LOGIN_FAILED", "signature": "Failed password for admin"}
            for i in range(5)
        ]
        self.assertEqual(len(soc.deduplicate(events)), 5)


if __name__ == "__main__":
    unittest.main()
