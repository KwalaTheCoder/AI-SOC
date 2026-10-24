"""Offline MITRE tactic -> technique -> sub-technique knowledge graph."""
import json
import os
from pathlib import Path

import networkx as nx
from networkx.readwrite import json_graph

BASE_DIR = Path(__file__).resolve().parent
MITRE_FILE = Path(os.getenv("MITRE_FILE", BASE_DIR / "mitre_techniques.json"))
GRAPH_FILE = Path(os.getenv("MITRE_GRAPH_FILE", BASE_DIR / "data" / "mitre_graph.json"))


def build_graph(techniques=None):
    techniques = techniques or json.loads(MITRE_FILE.read_text(encoding="utf-8"))
    graph = nx.DiGraph()
    for item in techniques:
        technique_id = item["id"]
        graph.add_node(
            technique_id,
            kind="subtechnique" if item.get("is_subtechnique") else "technique",
            name=item.get("name", ""),
            description=item.get("description", ""),
            platforms=item.get("platforms", []),
        )
        if item.get("is_subtechnique") and "." in technique_id:
            graph.add_edge(technique_id.split(".")[0], technique_id, relation="has_subtechnique")
        # Sub-techniques are reached through their parent, preserving the
        # intended tactic -> technique -> sub-technique hierarchy.
        if not item.get("is_subtechnique"):
            for tactic in item.get("tactics", []):
                tactic_id = f"tactic:{tactic.lower().replace(' ', '-')}"
                graph.add_node(tactic_id, kind="tactic", name=tactic)
                graph.add_edge(tactic_id, technique_id, relation="contains")
    return graph


def save_graph(graph=None, path=GRAPH_FILE):
    graph = graph or build_graph()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(json_graph.node_link_data(graph), ensure_ascii=False), encoding="utf-8")
    return {"nodes": graph.number_of_nodes(), "edges": graph.number_of_edges(), "path": str(path)}


def load_graph(path=GRAPH_FILE):
    path = Path(path)
    if not path.exists():
        save_graph(path=path)
    return json_graph.node_link_graph(json.loads(path.read_text(encoding="utf-8")), directed=True)


def neighbors(node_id, depth=2, graph=None):
    graph = graph or load_graph()
    if node_id not in graph:
        return []
    seen = {node_id}
    frontier = {node_id}
    output = []
    for hop in range(1, max(1, int(depth)) + 1):
        next_frontier = set()
        for current in frontier:
            linked = set(graph.successors(current)) | set(graph.predecessors(current))
            for linked_id in linked - seen:
                seen.add(linked_id)
                next_frontier.add(linked_id)
                output.append({"id": linked_id, "hop": hop, **graph.nodes[linked_id]})
        frontier = next_frontier
    return output


def graph_stats(graph=None):
    graph = graph or load_graph()
    kinds = {}
    for _, data in graph.nodes(data=True):
        kinds[data.get("kind", "unknown")] = kinds.get(data.get("kind", "unknown"), 0) + 1
    return {"nodes": graph.number_of_nodes(), "edges": graph.number_of_edges(), "by_kind": kinds}
