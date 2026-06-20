# Subgraph depth / node-cap study (reviewer #15)

scan_stream extracts a bidirectional-BFS subgraph around each changed file,
bounded by depth and a node cap (scan uses **depth 2 / 30 nodes**; the documented
limit is **depth 5 / 50 nodes**). The reviewer asked whether real cross-file
chains are longer or larger than these caps — if so, the cap truncates context
and can hide bugs. `benchmark/eval_subgraph_caps.py` measures this directly on
real dependency graphs (no LLM).

## Results

| repo | nodes | % nbhd > 30 @ depth2 | % nbhd > 50 @ depth5 | % chains > 5 hops | max chain |
|------|-------|---------------------|---------------------|-------------------|-----------|
| demo_project | 23 | 0% | 0% | 0% | 2 |
| pygoat (core) | 91 | 5% | 4% | 0% | 1 |
| requests (src) | 281 | 6% | **13%** | **9%** | 6 |
| flask (src) | 331 | 5% | 4% | 4% | 8 |
| autopsy (self) | 140 | 6% | 4% | 4% | 8 |

## Honest reading
- **For the median node the caps are fine** — typical neighborhoods are ~5–21
  nodes and typical downstream chains are 0–1 hops, well within depth 5 / 50.
- **But a real minority exceeds them.** On mature libraries, **5–13%** of nodes
  have neighborhoods larger than the node cap (requests p90 = 60 nodes at depth
  5, max 277), and **4–9%** of functions have downstream call chains **deeper
  than 5 hops** (max observed 8). For those nodes the cap truncates the subgraph,
  so a cross-file vulnerability whose chain sits beyond the boundary can be
  missed. This empirically confirms the reviewer's concern and bounds it.
- The synthetic `demo_project` exceeds nothing — another reason it understates
  difficulty versus real code.
- The map-reduce scanner (`--chunked`) removes *file-line* truncation but **not**
  this subgraph-neighborhood cap; raising/adapting the cap for hub nodes (high
  fan-in/out) is the natural mitigation and remains future work.

## Reproduce
```bash
python benchmark/eval_subgraph_caps.py --repo /tmp/requests_human/src
python benchmark/eval_subgraph_caps.py --repo /path/to/any/repo
```
