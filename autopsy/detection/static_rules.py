"""General, deterministic static rules built on the AST + dependency graph.

These complement the LLM scan. Their value is that they are *scale-invariant*:
an LLM's recall degrades as a codebase grows and its attention is spread across
more code, but an AST/graph rule fires identically on a 200-line demo and a
500k-line monorepo, in linear time, with no context-window limit. On large
repositories this deterministic layer is what keeps recall from collapsing.

Every rule here is a general security pattern (not tied to any particular
project): weak password hashing, and user-controlled values interpolated into a
SQL string that reaches an execution sink. Crucially, each rule is written to
fire on the *vulnerable* shape and stay silent on the safe shape — e.g. an
interpolated SQL string is flagged, but a parameterized query that binds the
same value is not.

IMPORTANT (evaluation honesty): findings from this layer are deterministic
static analysis, not evidence of LLM reasoning. When benchmarking, attribute
static-layer and LLM-layer findings separately, and validate these rules on code
they were not written against (see benchmark/heldout/).
"""

from __future__ import annotations

from pathlib import Path

from autopsy.parser.core import parse_file
from autopsy.parser.extractors import _find_all, _text
from autopsy.parser.languages import get_parser


# DB-API execution methods that run a raw SQL string.
_DBAPI_EXEC = {"execute", "executescript", "executemany"}

# Hash constructors considered cryptographically weak for security use.
_WEAK_HASHES = {"md5", "sha1"}


def _enclosing_function(line: int, parsed):
    best = None
    for fn in parsed.all_functions:
        if fn.line_start <= line <= fn.line_end:
            if best is None or fn.line_start > best.line_start:
                best = fn
    return best


def _ancestor_function(node):
    """Nearest enclosing function_definition AST node (handles nested defs)."""
    n = node.parent
    while n is not None:
        if n.type == "function_definition":
            return n
        n = n.parent
    return None


def _param_names(func_node) -> set[str]:
    """Parameter names of a function_definition node, read from the AST."""
    out: set[str] = set()
    pnode = func_node.child_by_field_name("parameters")
    if pnode is None:
        return out
    for c in pnode.children:
        if c.type == "identifier":
            out.add(_text(c))
        elif c.type in ("default_parameter", "typed_parameter",
                        "typed_default_parameter"):
            nm = c.child_by_field_name("name")
            if nm is not None:
                out.add(_text(nm))
            else:
                ids = _find_all(c, "identifier")
                if ids:
                    out.add(_text(ids[0]))
    return out


def _qual_name(func_node) -> str:
    """A dotted name for a (possibly nested) function: enclosing defs joined."""
    names = []
    n = func_node
    while n is not None:
        if n.type in ("function_definition", "class_definition"):
            nm = n.child_by_field_name("name")
            if nm is not None:
                names.append(_text(nm))
        n = n.parent
    return ".".join(reversed(names)) if names else "<anonymous>"


def _identifiers(node) -> set[str]:
    out: set[str] = set()
    for ident in _find_all(node, "identifier"):
        out.add(_text(ident))
    return out


def _string_interpolated_params(args_node, param_set: set[str]) -> set[str]:
    """Params that are interpolated/concatenated into a STRING within args.

    This is the SQL-injection shape (f-string interpolation, ``+`` concat, or
    ``%`` formatting that mixes a string with a parameter). A value passed as a
    *bound* parameter (e.g. inside a separate list argument, with no string
    formatting) is deliberately NOT matched — that is the safe, parameterized
    form.
    """
    hit: set[str] = set()
    if args_node is None:
        return hit
    # f-string interpolations: {param} inside a string literal
    for interp in _find_all(args_node, "interpolation"):
        hit |= _identifiers(interp) & param_set
    # binary string ops: "..." + param, "..." % param
    for binop in _find_all(args_node, "binary_operator"):
        if _find_all(binop, "string"):
            hit |= _identifiers(binop) & param_set
    return hit


def _python_parses(root_dir: Path, only_files):
    root_dir = Path(root_dir)
    only = set(only_files or [])
    out = []
    for p in sorted(root_dir.rglob("*.py")):
        pf = parse_file(p)
        if pf is None or pf.language != "python":
            continue
        rel = p.relative_to(root_dir).as_posix()
        if only and not (rel in only or p.name in only):
            continue
        out.append((p, rel, pf))
    return out


def _sql_sink_names(root_dir: Path) -> set[str]:
    """Names of functions that are raw-SQL sinks.

    Seeds with the DB-API exec methods, then adds any wrapper function whose
    body calls one of them (e.g. ``execute_query`` -> ``conn.execute(sql)``).
    This is a 1-level resolution over the call graph and generalizes to any
    project's thin DB wrappers.
    """
    sinks = set(_DBAPI_EXEC)
    for p in sorted(Path(root_dir).rglob("*.py")):
        pf = parse_file(p)
        if pf is None or pf.language != "python":
            continue
        tree = get_parser("python").parse(pf.source.encode("utf-8"))
        for call in _find_all(tree.root_node, "call"):
            fnode = call.child_by_field_name("function")
            if not fnode:
                continue
            base = _text(fnode).split(".")[-1]
            if base in _DBAPI_EXEC:
                owner = _enclosing_function(call.start_point[0] + 1, pf)
                if owner:
                    sinks.add(owner.name)
    return sinks


def detect_sql_string_injection(root_dir: Path, only_files=None) -> list[dict]:
    """Flag a function parameter interpolated into a SQL string passed to a sink."""
    root_dir = Path(root_dir)
    sinks = _sql_sink_names(root_dir)
    findings: list[dict] = []
    for p, rel, pf in _python_parses(root_dir, only_files):
        tree = get_parser("python").parse(pf.source.encode("utf-8"))
        for call in _find_all(tree.root_node, "call"):
            fnode = call.child_by_field_name("function")
            if not fnode:
                continue
            base = _text(fnode).split(".")[-1]
            if base not in sinks:
                continue
            owner_node = _ancestor_function(call)
            if owner_node is None:
                continue
            params = _param_names(owner_node)
            if not params:
                continue
            args = call.child_by_field_name("arguments")
            tainted = _string_interpolated_params(args, params)
            if not tainted:
                continue
            line = call.start_point[0] + 1
            findings.append({
                "caller_file": rel,
                "caller_function": _qual_name(owner_node),
                "sink": base,
                "tainted_params": sorted(tainted),
                "line": line,
                "severity": "CRITICAL",
                "category": "SQLi",
                "description": (
                    f"{_qual_name(owner_node)}() interpolates parameter(s) "
                    f"{sorted(tainted)} into a SQL string passed to {base}() — "
                    f"a SQL injection sink. Use bound parameters instead."
                ),
            })
    return findings


def detect_weak_hashing(root_dir: Path, only_files=None) -> list[dict]:
    """Flag use of cryptographically weak hashes (md5/sha1)."""
    findings: list[dict] = []
    for p, rel, pf in _python_parses(root_dir, only_files):
        tree = get_parser("python").parse(pf.source.encode("utf-8"))
        for call in _find_all(tree.root_node, "call"):
            fnode = call.child_by_field_name("function")
            if not fnode:
                continue
            base = _text(fnode).split(".")[-1]
            if base not in _WEAK_HASHES:
                continue
            line = call.start_point[0] + 1
            owner = _enclosing_function(line, pf)
            findings.append({
                "caller_file": rel,
                "caller_function": owner.qualified_name if owner else "<module>",
                "algorithm": base,
                "line": line,
                "severity": "HIGH",
                "category": "Weak Crypto",
                "description": (
                    f"{base.upper()} is cryptographically weak; if used for "
                    f"passwords or security tokens it is trivially brute-forced. "
                    f"Use a slow, salted KDF (bcrypt/scrypt/PBKDF2)."
                ),
            })
    return findings


def detect_static_rules(root_dir: Path, only_files=None) -> list[dict]:
    """Run all static rules and return the combined finding list."""
    return (
        detect_sql_string_injection(root_dir, only_files)
        + detect_weak_hashing(root_dir, only_files)
    )


def format_static_findings(findings: list[dict]) -> str:
    """Render static findings as SCAN-format `## [SEVERITY:]` blocks."""
    if not findings:
        return ""
    blocks: list[str] = []
    for f in findings:
        blocks.append(
            f"## [SEVERITY: {f['severity']}] {f['category']} (static): "
            f"{f.get('caller_function', 'code')}\n"
            f"**Category:** {f['category']}\n"
            f"**Location:** `{f['caller_file']}:{f['line']}`\n"
            f"**Attack Scenario:**\n{f['description']}\n"
            f"**Fix:**\nSee description.\n"
            f"---\n"
        )
    return (
        "🔎 Graph/AST static rules — deterministic findings\n\n"
        + "\n".join(blocks)
    )
