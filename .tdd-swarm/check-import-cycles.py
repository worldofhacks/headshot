#!/usr/bin/env python3
"""Reject cycles in the canonical repository ``agentforge`` import graph."""

from __future__ import annotations

import argparse
import ast
import hashlib
import os
import stat
import sys
from pathlib import Path

PACKAGE = "agentforge"


def _reject_symlink_components(path: Path, repository: Path) -> None:
    """Reject a symlink before any traversal or source read."""
    try:
        relative = path.relative_to(repository)
    except ValueError as exc:
        raise ValueError(f"path is outside repository: {path}") from exc

    current = repository
    for part in relative.parts:
        current = current / part
        try:
            status = os.lstat(current)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(status.st_mode):
            raise ValueError(f"refusing symlinked source path: {current}")


def _module_name(source_root: Path, source_file: Path) -> str:
    parts = list(source_file.relative_to(source_root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _source_package(source_module: str, *, initializer: bool) -> str:
    if initializer:
        return source_module
    return source_module.rpartition(".")[0]


def _from_package(
    source_module: str,
    *,
    initializer: bool,
    node: ast.ImportFrom,
) -> str | None:
    if node.level == 0:
        return node.module

    package_parts = _source_package(
        source_module,
        initializer=initializer,
    ).split(".")
    parents_to_drop = node.level - 1
    if parents_to_drop >= len(package_parts):
        return None
    if parents_to_drop:
        package_parts = package_parts[:-parents_to_drop]
    if node.module:
        package_parts.extend(node.module.split("."))
    return ".".join(package_parts)


def _repository_target(import_name: str, modules: set[str]) -> str | None:
    candidate = import_name
    while candidate == PACKAGE or candidate.startswith(f"{PACKAGE}."):
        if candidate in modules:
            return candidate
        if "." not in candidate:
            break
        candidate = candidate.rsplit(".", 1)[0]
    return None


def _import_targets(
    source_module: str,
    *,
    initializer: bool,
    tree: ast.AST,
    modules: set[str],
) -> set[str]:
    targets: set[str] = set()

    def import_nodes(root: ast.AST) -> list[ast.Import | ast.ImportFrom]:
        nodes: list[ast.Import | ast.ImportFrom] = []

        class Visitor(ast.NodeVisitor):
            def visit_If(self, node: ast.If) -> None:
                test = node.test
                is_main_guard = (
                    isinstance(test, ast.Compare)
                    and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"
                    and len(test.ops) == 1
                    and isinstance(test.ops[0], ast.Eq)
                    and len(test.comparators) == 1
                    and isinstance(test.comparators[0], ast.Constant)
                    and test.comparators[0].value == "__main__"
                )
                if not is_main_guard:
                    self.generic_visit(node)
                else:
                    for statement in node.orelse:
                        self.visit(statement)

            def visit_Import(self, node: ast.Import) -> None:
                nodes.append(node)

            def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
                nodes.append(node)

        Visitor().visit(root)
        return nodes

    for node in import_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                target = _repository_target(alias.name, modules)
                if target is not None:
                    targets.add(target)
            continue

        if not isinstance(node, ast.ImportFrom):
            continue
        package = _from_package(
            source_module,
            initializer=initializer,
            node=node,
        )
        if not package or (package != PACKAGE and not package.startswith(f"{PACKAGE}.")):
            continue

        package_target = _repository_target(package, modules)
        for alias in node.names:
            concrete = (
                None
                if alias.name == "*"
                else _repository_target(f"{package}.{alias.name}", modules)
            )
            if concrete is not None and concrete != package_target:
                targets.add(concrete)
            elif package_target is not None:
                targets.add(package_target)
    return targets


def build_graph(repository: Path) -> tuple[dict[str, set[str]], str]:
    repository = repository.absolute()
    source_root = repository / "src"
    package_root = source_root / PACKAGE
    _reject_symlink_components(source_root, repository)
    _reject_symlink_components(package_root, repository)
    if not package_root.exists():
        return {}, hashlib.sha256(b"").hexdigest()
    if not package_root.is_dir():
        raise ValueError(f"package root is not a directory: {package_root}")

    source_files = sorted(package_root.rglob("*.py"))
    for source_file in source_files:
        _reject_symlink_components(source_file.parent, repository)
        _reject_symlink_components(source_file, repository)
        status = os.lstat(source_file)
        if not stat.S_ISREG(status.st_mode):
            raise ValueError(f"source is not a regular file: {source_file}")

    modules = {_module_name(source_root, source_file) for source_file in source_files}
    graph = {module: set() for module in modules}
    edges: set[tuple[str, str]] = set()

    for source_file in source_files:
        source_module = _module_name(source_root, source_file)
        try:
            source = source_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(source_file))
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise ValueError(f"cannot parse {source_file}: {exc}") from exc

        targets = _import_targets(
            source_module,
            initializer=source_file.name == "__init__.py",
            tree=tree,
            modules=modules,
        )
        graph[source_module].update(targets)
        edges.update((source_module, target) for target in targets)

    canonical = "".join(f"{source} -> {target}\n" for source, target in sorted(edges))
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
