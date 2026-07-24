#!/usr/bin/env python3
"""Reject cycles in the repository's ``agentforge`` import graph.

The graph serialization is deliberately stable because the local-gate report binds
its SHA-256 digest as review evidence.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import sys
from collections.abc import Iterable
from pathlib import Path

PACKAGE = "agentforge"


def _module_name(source_root: Path, source_file: Path) -> str:
    return ".".join(source_file.relative_to(source_root).with_suffix("").parts)


def _absolute_from_module(source_module: str, node: ast.ImportFrom) -> str | None:
    if node.level == 0:
        return node.module

    source_parts = source_module.split(".")
    package_parts = source_parts[:-1]
    keep = len(package_parts) - node.level + 1
    if keep < 1:
        return None
    prefix = package_parts[:keep]
    if node.module:
        prefix.extend(node.module.split("."))
    return ".".join(prefix)


def _imports(source_module: str, tree: ast.AST) -> Iterable[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == PACKAGE or alias.name.startswith(f"{PACKAGE}."):
                    yield alias.name
        elif isinstance(node, ast.ImportFrom):
            module = _absolute_from_module(source_module, node)
            if not module or (module != PACKAGE and not module.startswith(f"{PACKAGE}.")):
                continue
            if module == PACKAGE:
                for alias in node.names:
                    if alias.name != "*":
                        yield f"{PACKAGE}.{alias.name}"
            else:
                yield module


def _target_module(import_name: str, modules: set[str]) -> str | None:
    candidate = import_name
    while candidate == PACKAGE or candidate.startswith(f"{PACKAGE}."):
        if candidate in modules:
            return candidate
        if "." not in candidate:
            break
        candidate = candidate.rsplit(".", 1)[0]
    return None


def build_graph(repository: Path) -> tuple[dict[str, set[str]], str]:
    source_root = repository / "src"
    package_root = source_root / PACKAGE
    if not package_root.is_dir():
        return {}, hashlib.sha256(b"").hexdigest()

    source_files = sorted(package_root.rglob("*.py"))
    symlinks = [source_file for source_file in source_files if source_file.is_symlink()]
    if symlinks:
        raise ValueError(f"refusing symlinked source file: {symlinks[0]}")
    modules = {_module_name(source_root, source_file) for source_file in source_files}
    graph = {module: set() for module in modules}
    canonical_edges: set[tuple[str, str]] = set()

    for source_file in source_files:
        source_module = _module_name(source_root, source_file)
        try:
            tree = ast.parse(source_file.read_text(encoding="utf-8"), filename=str(source_file))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise ValueError(f"cannot parse {source_file}: {exc}") from exc

        for imported in _imports(source_module, tree):
            canonical_edges.add((source_module, imported))
            target = _target_module(imported, modules)
            if target is not None and target != source_module:
                graph[source_module].add(target)

    canonical = "".join(f"{source} -> {target}\n" for source, target in sorted(canonical_edges))
    return graph, hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def find_cycle(graph: dict[str, set[str]]) -> list[str] | None:
    visited: set[str] = set()
    active: set[str] = set()
    path: list[str] = []

    def visit(module: str) -> list[str] | None:
        if module in active:
            start = path.index(module)
            return [*path[start:], module]
        if module in visited:
            return None

        active.add(module)
        path.append(module)
        for dependency in sorted(graph[module]):
            cycle = visit(dependency)
            if cycle is not None:
                return cycle
        path.pop()
        active.remove(module)
        visited.add(module)
        return None

    for module in sorted(graph):
        cycle = visit(module)
        if cycle is not None:
            return cycle
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--hash-only",
        action="store_true",
        help="print only the canonical import-edge SHA-256 digest",
    )
    args = parser.parse_args()

    try:
        graph, graph_hash = build_graph(Path.cwd())
    except ValueError as exc:
        print(f"import-cycle error: {exc}", file=sys.stderr)
        return 1

    cycle = find_cycle(graph)
    if cycle is not None:
        print(f"import cycle: {' -> '.join(cycle)}", file=sys.stderr)
        return 1
    if args.hash_only:
        print(graph_hash)
    else:
        print(f"import graph acyclic; sha256={graph_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
