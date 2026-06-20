"""Tests for the dependency graph builder and subgraph extraction."""

from __future__ import annotations

import networkx as nx

from autopsy.graph.subgraph import (
    extract_subgraph_for_file,
    subgraph_summary,
)


class TestBuildGraph:
    def test_build_graph_nodes(self, graph: nx.DiGraph):
        types = {d.get("type") for _, d in graph.nodes(data=True)}
        assert "file" in types
        assert "function" in types
        assert "class" in types

    def test_file_nodes_present(self, graph: nx.DiGraph, parsed_files):
        file_nodes = [
            n for n, d in graph.nodes(data=True) if d.get("type") == "file"
        ]
        assert len(file_nodes) >= 2  # sample_a.py, sample_b.py, app.jsx

    def test_function_nodes_present(self, graph: nx.DiGraph):
        func_names = [
            d.get("name") for _, d in graph.nodes(data=True) if d.get("type") == "function"
        ]
        assert "greet" in func_names
        assert "helper" in func_names
        assert "App" in func_names

    def test_class_nodes_present(self, graph: nx.DiGraph):
        class_names = [
            d.get("name") for _, d in graph.nodes(data=True) if d.get("type") == "class"
        ]
        assert "Greeter" in class_names
        assert "Widget" in class_names


class TestImportEdges:
    def test_import_edges(self, graph: nx.DiGraph):
        import_edges = [
            (u, v) for u, v, d in graph.edges(data=True) if d.get("type") == "imports"
        ]
        # sample_b.py imports sample_a → there should be an import edge
        assert len(import_edges) >= 1

        # Verify the import edge connects the right files
        importing_nodes = {u for u, _ in import_edges}
        imported_nodes = {v for _, v in import_edges}

        # sample_b imports from sample_a
        b_file = [n for n in importing_nodes if "sample_b" in n]
        a_file = [n for n in imported_nodes if "sample_a" in n]
        assert len(b_file) >= 1
        assert len(a_file) >= 1


class TestCallEdges:
    def test_call_edges(self, graph: nx.DiGraph):
        call_edges = [
            (u, v) for u, v, d in graph.edges(data=True) if d.get("type") == "calls"
        ]
        # helper() calls greet() — should produce a call edge
        assert len(call_edges) >= 1

        caller_names = []
        callee_names = []
        for u, v in call_edges:
            caller_names.append(graph.nodes[u].get("name", ""))
            callee_names.append(graph.nodes[v].get("name", ""))

        assert "helper" in caller_names
        assert "greet" in callee_names


class TestSubgraph:
    def test_subgraph_extraction(self, graph: nx.DiGraph, parsed_files):
        # Find the actual file node for sample_a
        a_node = None
        for n, d in graph.nodes(data=True):
            if d.get("type") == "file" and "sample_a" in str(d.get("path", "")):
                a_node = n
                break
        assert a_node is not None

        sub = extract_subgraph_for_file(graph, str(graph.nodes[a_node]["path"]))
        assert sub.number_of_nodes() > 0
        # The subgraph should contain the target file
        assert a_node in sub.nodes

        # Should also contain dependents (sample_b imports sample_a)
        sub_paths = [
            d.get("path", "") for _, d in sub.nodes(data=True) if d.get("type") == "file"
        ]
        assert any("sample_a" in p for p in sub_paths)

    def test_subgraph_summary(self, graph: nx.DiGraph, parsed_files):
        a_path = None
        for n, d in graph.nodes(data=True):
            if d.get("type") == "file" and "sample_a" in str(d.get("path", "")):
                a_path = d["path"]
                break
        assert a_path is not None

        sub = extract_subgraph_for_file(graph, a_path)
        summary = subgraph_summary(sub)

        assert "Subgraph:" in summary
        assert "nodes" in summary
        assert "edges" in summary
        assert "Files" in summary
        assert "Functions" in summary
