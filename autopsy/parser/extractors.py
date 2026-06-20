"""Language-specific AST extractors using Tree-sitter queries."""

from __future__ import annotations

from tree_sitter import Node

from autopsy.parser.models import ImportDef, FunctionDef, ClassDef, CallSite


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _text(node: Node) -> str:
    """Extract UTF-8 text from a tree-sitter node."""
    return node.text.decode("utf-8") if node.text else ""


def _children_of_type(node: Node, type_name: str) -> list[Node]:
    """Get all direct children of a specific type."""
    return [c for c in node.children if c.type == type_name]


def _find_all(node: Node, type_name: str) -> list[Node]:
    """Recursively find all descendant nodes of a given type."""
    results = []
    if node.type == type_name:
        results.append(node)
    for child in node.children:
        results.extend(_find_all(child, type_name))
    return results


# ---------------------------------------------------------------------------
# Call extraction (shared across languages)
# ---------------------------------------------------------------------------

def extract_calls(node: Node) -> list[CallSite]:
    """Extract all function/method calls from a subtree."""
    calls = []
    for call_node in _find_all(node, "call"):
        func_node = call_node.child_by_field_name("function")
        if func_node:
            calls.append(CallSite(
                name=_text(func_node),
                line=call_node.start_point[0] + 1,
            ))
    # Also handle JS/TS call_expression
    for call_node in _find_all(node, "call_expression"):
        func_node = call_node.child_by_field_name("function")
        if func_node:
            calls.append(CallSite(
                name=_text(func_node),
                line=call_node.start_point[0] + 1,
            ))
    return calls


# ---------------------------------------------------------------------------
# Python extractor
# ---------------------------------------------------------------------------

def extract_python_imports(root: Node) -> list[ImportDef]:
    """Extract imports from a Python AST."""
    imports = []

    for node in _find_all(root, "import_statement"):
        for name_node in _find_all(node, "dotted_name"):
            imports.append(ImportDef(
                module=_text(name_node),
                line=node.start_point[0] + 1,
            ))
            break

    for node in _find_all(root, "import_from_statement"):
        module_node = node.child_by_field_name("module_name")
        module = _text(module_node) if module_node else ""

        # Check for relative import dots
        is_relative = any(c.type == "relative_import" or _text(c) == "." for c in node.children)

        names = []
        for name_node in _find_all(node, "dotted_name"):
            if name_node != module_node:
                names.append(_text(name_node))
        for name_node in _children_of_type(node, "aliased_import"):
            name_child = name_node.child_by_field_name("name")
            if name_child:
                names.append(_text(name_child))

        imports.append(ImportDef(
            module=module,
            names=names,
            line=node.start_point[0] + 1,
            is_relative=is_relative,
        ))

    return imports


def extract_python_functions(root: Node, prefix: str = "") -> list[FunctionDef]:
    """Extract top-level function definitions from a Python AST."""
    functions = []
    for node in _children_of_type(root, "function_definition"):
        name_node = node.child_by_field_name("name")
        name = _text(name_node) if name_node else "<anonymous>"
        qualified = f"{prefix}.{name}" if prefix else name

        params = []
        params_node = node.child_by_field_name("parameters")
        if params_node:
            for p in params_node.children:
                if p.type in ("identifier", "typed_parameter", "default_parameter"):
                    param_name_node = p.child_by_field_name("name") if p.type != "identifier" else p
                    if param_name_node:
                        params.append(_text(param_name_node))

        decorators = []
        for dec in _find_all(node, "decorator"):
            decorators.append(_text(dec).lstrip("@").strip())

        body = node.child_by_field_name("body")
        calls = extract_calls(body) if body else []

        functions.append(FunctionDef(
            name=name,
            qualified_name=qualified,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            params=params,
            decorators=decorators,
            calls=calls,
        ))
    return functions


def extract_python_classes(root: Node) -> list[ClassDef]:
    """Extract class definitions from a Python AST."""
    classes = []
    for node in _children_of_type(root, "class_definition"):
        name_node = node.child_by_field_name("name")
        name = _text(name_node) if name_node else "<anonymous>"

        bases = []
        arg_list = node.child_by_field_name("superclasses")
        if arg_list:
            for arg in arg_list.children:
                if arg.type in ("identifier", "dotted_name", "attribute"):
                    bases.append(_text(arg))

        body = node.child_by_field_name("body")
        methods = extract_python_functions(body, prefix=name) if body else []

        classes.append(ClassDef(
            name=name,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            bases=bases,
            methods=methods,
        ))
    return classes


# ---------------------------------------------------------------------------
# JavaScript / TypeScript extractor
# ---------------------------------------------------------------------------

def extract_js_imports(root: Node) -> list[ImportDef]:
    """Extract imports from JS/TS AST."""
    imports = []

    for node in _find_all(root, "import_statement"):
        source_node = node.child_by_field_name("source")
        module = _text(source_node).strip("'\"") if source_node else ""

        names = []
        for spec in _find_all(node, "import_specifier"):
            name_node = spec.child_by_field_name("name")
            if name_node:
                names.append(_text(name_node))

        # Default import
        for clause in _find_all(node, "import_clause"):
            for child in clause.children:
                if child.type == "identifier":
                    names.append(_text(child))

        imports.append(ImportDef(
            module=module,
            names=names,
            line=node.start_point[0] + 1,
        ))

    # require() calls
    for call in _find_all(root, "call_expression"):
        func = call.child_by_field_name("function")
        if func and _text(func) == "require":
            args = call.child_by_field_name("arguments")
            if args and args.child_count > 0:
                for arg in args.children:
                    if arg.type == "string":
                        module = _text(arg).strip("'\"")
                        imports.append(ImportDef(
                            module=module,
                            line=call.start_point[0] + 1,
                        ))
                        break

    return imports


def _unwrapped_children(node: Node) -> list[Node]:
    """Direct children, with `export ...` statements unwrapped one level.

    In ES modules / TypeScript, top-level declarations are usually exported, so
    a `function`/`class`/`const` lives inside an `export_statement` rather than
    directly under the module root. Without unwrapping, the module-level
    extractors miss every exported declaration.
    """
    out: list[Node] = []
    for c in node.children:
        if c.type == "export_statement":
            out.extend(c.children)
        else:
            out.append(c)
    return out


def _extract_js_functions_from_node(root: Node, prefix: str = "") -> list[FunctionDef]:
    """Extract function definitions from JS/TS node."""
    functions = []
    kids = _unwrapped_children(root)

    # Regular function declarations
    for node_type in ("function_declaration", "method_definition"):
        for node in [c for c in kids if c.type == node_type]:
            name_node = node.child_by_field_name("name")
            name = _text(name_node) if name_node else "<anonymous>"
            qualified = f"{prefix}.{name}" if prefix else name

            params = []
            params_node = node.child_by_field_name("parameters")
            if params_node:
                for p in params_node.children:
                    if p.type in ("identifier", "required_parameter", "optional_parameter"):
                        pname = p.child_by_field_name("pattern") or p
                        params.append(_text(pname))

            body = node.child_by_field_name("body")
            calls = extract_calls(body) if body else []

            functions.append(FunctionDef(
                name=name,
                qualified_name=qualified,
                line_start=node.start_point[0] + 1,
                line_end=node.end_point[0] + 1,
                params=params,
                calls=calls,
            ))

    # Arrow functions assigned to variables: const foo = () => {}
    for node in [c for c in kids if c.type == "lexical_declaration"]:
        for declarator in _children_of_type(node, "variable_declarator"):
            name_node = declarator.child_by_field_name("name")
            value_node = declarator.child_by_field_name("value")
            if value_node and value_node.type == "arrow_function":
                name = _text(name_node) if name_node else "<anonymous>"
                qualified = f"{prefix}.{name}" if prefix else name

                params = []
                params_node = value_node.child_by_field_name("parameters")
                if params_node:
                    for p in params_node.children:
                        if p.type in ("identifier", "required_parameter", "optional_parameter"):
                            params.append(_text(p))
                # Single param without parens
                if not params_node:
                    param = value_node.child_by_field_name("parameter")
                    if param:
                        params.append(_text(param))

                body = value_node.child_by_field_name("body")
                calls = extract_calls(body) if body else []

                functions.append(FunctionDef(
                    name=name,
                    qualified_name=qualified,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    params=params,
                    calls=calls,
                ))

    return functions


def extract_js_functions(root: Node, prefix: str = "") -> list[FunctionDef]:
    return _extract_js_functions_from_node(root, prefix)


def extract_js_classes(root: Node) -> list[ClassDef]:
    """Extract class definitions from JS/TS AST."""
    classes = []
    for node in _find_all(root, "class_declaration"):
        name_node = node.child_by_field_name("name")
        name = _text(name_node) if name_node else "<anonymous>"

        bases = []
        heritage = node.child_by_field_name("heritage") or node.child_by_field_name("superclass")
        if heritage:
            bases.append(_text(heritage))

        body = node.child_by_field_name("body")
        methods = _extract_js_functions_from_node(body, prefix=name) if body else []

        classes.append(ClassDef(
            name=name,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            bases=bases,
            methods=methods,
        ))
    return classes
