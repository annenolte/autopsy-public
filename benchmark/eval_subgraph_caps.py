"""Empirically test the subgraph depth/node caps (reviewer #15).

scan_stream extracts a bidirectional BFS subgraph around each changed file,
bounded to a depth and a node cap (scan uses depth 2 / 30 nodes; the documented
limits are depth 5 / 50 nodes). The reviewer asks whether real cross-file chains
are longer or larger than these caps — if so, the cap truncates context and can
hide bugs.

This builds the real dependency graph over a codebase and measures, per node:
  * neighborhood size at depth 2 and depth 5 (bidirectional BFS, mirroring
    autopsy/graph/subgraph.py), and how often it exceeds the node caps;
  * downstream call-chain depth, and how often it exceeds 5 hops.

No LLM / API.

    python benchmark/eval_subgraph_caps.py --repo /tmp/requests_human
"""
from __future__ import annotations

import argparse
import statistics as st
from pathlib import Path

import networkx as nx

from autopsy.parser import parse_directory
from autopsy.graph.builder import build_dependency_graph


def neighborhood_size(G: nx.DiGraph, node, max_depth: int) -> int:
    """Bidirectional BFS node count to max_depth (mirrors _collect_neighbors)."""
    collected = {node}
    for succ in (False, True):
        frontier = {node}
        for _ in range(max_depth):
            nxt: set = set()
            for n in frontier:
                neigh = set(G.successors(n)) if succ else set(G.predecessors(n))
                nxt |= (neigh - collected)
            if not nxt:
                break
            collected |= nxt
            frontier = nxt
    return len(collected)


def downstream_depth(G: nx.DiGraph, node) -> int:
    """How many hops downstream (successors) the chain from node extends."""
    seen = {node}
    frontier = {node}
    depth = 0
    while frontier and depth <= 50:
        nxt: set = set()
        for n in frontier:
            nxt |= set(G.successors(n)) - seen
        if not nxt:
            break
        seen |= nxt
        frontier = nxt
        depth += 1
    return depth


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--depth-scan", type=int, default=2)
    p.add_argument("--cap-scan", type=int, default=30)
    p.add_argument("--depth-max", type=int, default=5)
    p.add_argument("--cap-max", type=int, default=50)
    args = p.parse_args()

    g = build_dependency_graph(parse_directory(args.repo))
    nodes = list(g.nodes)
    funcs = [n for n, d in g.nodes(data=True) if d.get("type") in ("function", "class")]
    print(f"repo={args.repo.name}  nodes={g.number_of_nodes()} edges={g.number_of_edges()} "
          f"(functions/classes={len(funcs)})")
    if not nodes:
        print("empty graph"); return

    sz2 = [neighborhood_size(g, n, args.depth_scan) for n in nodes]
    sz5 = [neighborhood_size(g, n, args.depth_max) for n in nodes]
    depths = [downstream_depth(g, n) for n in funcs] or [0]

    def line(vals):
        return f"median={int(st.median(vals))} p90={int(sorted(vals)[int(0.9*(len(vals)-1))])} max={max(vals)}"

    over_scan = sum(1 for s in sz2 if s > args.cap_scan)
    over_max = sum(1 for s in sz5 if s > args.cap_max)
    deep = sum(1 for d in depths if d > args.depth_max)

    print(f"\nNeighborhood size @ depth {args.depth_scan} (scan setting): {line(sz2)}")
    print(f"   exceed {args.cap_scan}-node scan cap: {over_scan}/{len(nodes)} = {round(100*over_scan/len(nodes))}%")
    print(f"Neighborhood size @ depth {args.depth_max} (documented limit): {line(sz5)}")
    print(f"   exceed {args.cap_max}-node cap: {over_max}/{len(nodes)} = {round(100*over_max/len(nodes))}%")
    print(f"\nDownstream call-chain depth (functions): {line(depths)}")
    print(f"   chains deeper than {args.depth_max} hops: {deep}/{len(funcs)} = "
          f"{round(100*deep/max(len(funcs),1))}%")


if __name__ == "__main__":
    main()
