"""Single operational CLI for Phase 2."""
import argparse
import json
from pathlib import Path

from cve_store import CVEStore
from mitre_graph import graph_stats, load_graph, neighbors, save_graph

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "cve.db"


def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description="SOC Phase 2 knowledge tools")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("build-graph")
    graph_query = commands.add_parser("graph-query")
    graph_query.add_argument("node")
    graph_query.add_argument("--depth", type=int, default=2)
    search_mitre_parser = commands.add_parser("search-mitre")
    search_mitre_parser.add_argument("query")
    search_mitre_parser.add_argument("--limit", type=int, default=3)
    import_cve = commands.add_parser("import-cve")
    import_cve.add_argument("file")
    search_cve = commands.add_parser("search-cve")
    search_cve.add_argument("query", nargs="?", default="")
    search_cve.add_argument("--min-cvss", type=float, default=0)
    add_incident = commands.add_parser("add-incident")
    add_incident.add_argument("file")
    search_incident = commands.add_parser("search-incidents")
    search_incident.add_argument("query")
    commands.add_parser("status")
    args = parser.parse_args()

    if args.command == "build-graph":
        emit(save_graph())
    elif args.command == "graph-query":
        emit(neighbors(args.node, args.depth))
    elif args.command == "search-mitre":
        from mitre_search import search_mitre
        emit(search_mitre(args.query, args.limit))
    elif args.command == "import-cve":
        emit({"imported": CVEStore(DB_PATH).import_json(args.file)})
    elif args.command == "search-cve":
        emit(CVEStore(DB_PATH).search(args.query, args.min_cvss))
    elif args.command == "add-incident":
        from incident_memory import IncidentMemory
        incident = json.loads(Path(args.file).read_text(encoding="utf-8"))
        emit({"id": IncidentMemory().add(incident)})
    elif args.command == "search-incidents":
        from incident_memory import IncidentMemory
        emit(IncidentMemory().search(args.query))
    elif args.command == "status":
        store = CVEStore(DB_PATH)
        with store.connect() as db:
            cve_count = db.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        emit({"graph": graph_stats(load_graph()), "cves": cve_count})


if __name__ == "__main__":
    main()
