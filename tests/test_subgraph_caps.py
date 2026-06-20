"""Self-contained tests for the subgraph cap-study measurement helpers.

Uses the in-repo demo_project so no external clone is needed.
"""
import sys
from pathlib import Path

_BENCH = Path(__file__).resolve().parent.parent / "benchmark"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

from autopsy.parser import parse_directory
from autopsy.graph.builder import build_dependency_graph
from eval_subgraph_caps import neighborhood_size, downstream_depth

_DEMO = Path(__file__).resolve().parent.parent / "demo_project"


def _graph():
    return build_dependency_graph(parse_directory(_DEMO))


def test_neighborhood_grows_monotonically_with_depth():
    g = _graph()
    n = next(iter(g.nodes))
    s1 = neighborhood_size(g, n, 1)
    s3 = neighborhood_size(g, n, 3)
    assert s1 >= 1 and s3 >= s1  # deeper BFS never shrinks the neighborhood


def test_downstream_depth_is_bounded_and_nonneg():
    g = _graph()
    for n, d in g.nodes(data=True):
        if d.get("type") == "function":
            depth = downstream_depth(g, n)
            assert 0 <= depth <= 50
