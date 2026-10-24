"""Convert MITRE Enterprise ATT&CK STIX JSON to the local compact dataset."""
import argparse
import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def clean_text(text):
    text = re.sub(r"\(Citation:.*?\)", "", text or "")
    text = re.sub(r"\[.*?\]\(.*?\)", "", text)
    return text.replace("**", "").replace("*", "").strip()


def external_id(item):
    return next(
        (
            ref.get("external_id", "")
            for ref in item.get("external_references", [])
            if ref.get("source_name") == "mitre-attack"
        ),
        "",
    )


def parse(input_file, output_file):
    payload = json.loads(Path(input_file).read_text(encoding="utf-8"))
    techniques = []
    for item in payload.get("objects", []):
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        technique_id = external_id(item)
        if not technique_id:
            continue
        techniques.append(
            {
                "id": technique_id,
                "name": item.get("name", ""),
                "description": clean_text(item.get("description")),
                "tactics": [
                    phase.get("phase_name", "").replace("-", " ").title()
                    for phase in item.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                ],
                "platforms": item.get("x_mitre_platforms", []),
                "data_sources": item.get("x_mitre_data_sources", []),
                "is_subtechnique": bool(item.get("x_mitre_is_subtechnique")),
                "detection": clean_text(item.get("x_mitre_detection")),
            }
        )
    techniques.sort(key=lambda value: value["id"])
    Path(output_file).write_text(
        json.dumps(techniques, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({"techniques": len(techniques), "output": str(output_file)}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(BASE_DIR / "enterprise-attack.json"))
    parser.add_argument("--output", default=str(BASE_DIR / "mitre_techniques.json"))
    args = parser.parse_args()
    parse(args.input, args.output)
