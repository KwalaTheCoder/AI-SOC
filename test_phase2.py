import json
import tempfile
import unittest
from pathlib import Path

from cve_store import CVEStore
from mitre_graph import build_graph, neighbors


class Phase2Tests(unittest.TestCase):
    def test_graph_has_multihop_path(self):
        graph = build_graph(
            [
                {"id": "T1000", "name": "Parent", "tactics": ["Discovery"], "is_subtechnique": False},
                {"id": "T1000.001", "name": "Child", "tactics": ["Discovery"], "is_subtechnique": True},
            ]
        )
        result = neighbors("tactic:discovery", 2, graph)
        self.assertTrue(any(x["id"] == "T1000.001" for x in result))
        self.assertTrue(any(x["hop"] == 2 for x in result))

    def test_nvd_import_and_asset_risk(self):
        with tempfile.TemporaryDirectory() as temp:
            feed = Path(temp) / "nvd.json"
            feed.write_text(
                json.dumps(
                    {
                        "vulnerabilities": [
                            {
                                "cve": {
                                    "id": "CVE-TEST-0001",
                                    "descriptions": [{"lang": "en", "value": "Example nginx issue"}],
                                    "metrics": {
                                        "cvssMetricV31": [
                                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                                        ]
                                    },
                                    "configurations": [
                                        {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:nginx:nginx:*"}]}]}
                                    ],
                                }
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            store = CVEStore(Path(temp) / "cve.db")
            self.assertEqual(store.import_json(feed), 1)
            self.assertEqual(store.search("nginx")[0]["cve_id"], "CVE-TEST-0001")
            risk = store.asset_risk({"hostname": "web01", "criticality": "critical", "products": ["nginx"]})
            self.assertEqual(risk["risk_score"], 10.0)


if __name__ == "__main__":
    unittest.main()
