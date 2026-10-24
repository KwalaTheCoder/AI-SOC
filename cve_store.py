"""Offline SQLite CVE store with NVD 2.0 JSON import and asset risk lookup."""
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class CVEStore:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init(self):
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS cves(
                  cve_id TEXT PRIMARY KEY, description TEXT NOT NULL, severity TEXT,
                  cvss REAL, published TEXT, modified TEXT, weaknesses TEXT, cpes TEXT,
                  raw_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
                CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss);
                """
            )

    @staticmethod
    def _normalize(entry):
        cve = entry.get("cve", entry)
        descriptions = cve.get("descriptions", [])
        description = next((x.get("value", "") for x in descriptions if x.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        metric = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                metric = metrics[key][0]
                break
        cvss_data = (metric or {}).get("cvssData", {})
        cpes = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("criteria"):
                        cpes.append(match["criteria"])
        weaknesses = [
            d.get("value", "")
            for weakness in cve.get("weaknesses", [])
            for d in weakness.get("description", [])
            if d.get("lang") == "en"
        ]
        return {
            "cve_id": cve.get("id", ""),
            "description": description,
            "severity": cvss_data.get("baseSeverity") or (metric or {}).get("baseSeverity", ""),
            "cvss": cvss_data.get("baseScore"),
            "published": cve.get("published", ""),
            "modified": cve.get("lastModified", ""),
            "weaknesses": weaknesses,
            "cpes": sorted(set(cpes)),
            "raw_json": cve,
        }

    def import_json(self, path):
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        entries = payload.get("vulnerabilities", payload if isinstance(payload, list) else [])
        imported = 0
        with self.connect() as db:
            for entry in entries:
                item = self._normalize(entry)
                if not item["cve_id"]:
                    continue
                db.execute(
                    """INSERT INTO cves VALUES(?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(cve_id) DO UPDATE SET
                       description=excluded.description,severity=excluded.severity,cvss=excluded.cvss,
                       published=excluded.published,modified=excluded.modified,
                       weaknesses=excluded.weaknesses,cpes=excluded.cpes,raw_json=excluded.raw_json""",
                    (
                        item["cve_id"], item["description"], item["severity"], item["cvss"],
                        item["published"], item["modified"], json.dumps(item["weaknesses"]),
                        json.dumps(item["cpes"]), json.dumps(item["raw_json"]),
                    ),
                )
                imported += 1
        return imported

    def search(self, text="", min_cvss=0.0, limit=20):
        pattern = f"%{text.lower()}%"
        with self.connect() as db:
            rows = db.execute(
                """SELECT cve_id,description,severity,cvss,published,modified,weaknesses,cpes
                   FROM cves WHERE COALESCE(cvss,0)>=? AND
                   (?='%%' OR lower(cve_id||' '||description||' '||cpes) LIKE ?)
                   ORDER BY COALESCE(cvss,0) DESC, published DESC LIMIT ?""",
                (float(min_cvss), pattern, pattern, max(1, min(int(limit), 500))),
            ).fetchall()
        return [dict(row) for row in rows]

    def asset_risk(self, asset, limit=50):
        terms = asset.get("cpe", []) or asset.get("products", [])
        if isinstance(terms, str):
            terms = [terms]
        matches = {}
        for term in terms:
            for item in self.search(str(term), limit=limit):
                matches[item["cve_id"]] = item
        criticality_weight = {"critical": 1.25, "high": 1.1, "medium": 1.0, "low": 0.8}
        max_cvss = max((float(x["cvss"] or 0) for x in matches.values()), default=0)
        score = min(10.0, max_cvss * criticality_weight.get(asset.get("criticality", "medium"), 1.0))
        return {"asset": asset.get("hostname") or asset.get("ip"), "risk_score": round(score, 2), "cves": list(matches.values())}
