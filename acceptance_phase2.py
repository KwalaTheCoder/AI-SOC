"""Executable acceptance report for Phase 2."""
import json
import sys

from mitre_graph import build_graph, neighbors
from mitre_search import search_mitre

QUERIES = [
    ("multiple failed login attempts brute force password", "T1110"),
    ("data exfiltration over command and control channel", "T1041"),
    ("command and control web protocol beacon", "T1071"),
    ("network service scanning multiple ports", "T1046"),
]


def main():
    checks = []
    for query, expected in QUERIES:
        results = search_mitre(query, n_results=5)
        expected_result = next((item for item in results if item["id"] == expected), None)
        checks.append(
            {
                "name": f"semantic:{expected}",
                "passed": bool(expected_result and expected_result["similarity"] >= 0.60),
                "expected_in_top5": bool(expected_result),
                "similarity": expected_result["similarity"] if expected_result else None,
                "top_result": results[0]["id"] if results else None,
            }
        )
    graph = build_graph()
    graph_result = neighbors("T1001", depth=2, graph=graph)
    checks.append(
        {
            "name": "graph:multi-hop",
            "passed": any(x["hop"] == 2 for x in graph_result),
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
        }
    )
    report = {"passed": all(x["passed"] for x in checks), "checks": checks}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
