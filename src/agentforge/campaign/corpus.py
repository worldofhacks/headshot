"""Validated, deterministic MVP corpus loading for Web and private Runner composition."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentforge.agents.red_team.seed_replay import corpus_sha256, seed_to_attempt
from agentforge.evals.validation import validate_corpus

MVP_CORPUS_ID = "m11-seed-corpus-v1"
MVP_CASE_COUNT = 9
MVP_CATEGORIES = frozenset({"prompt_injection", "data_exfiltration", "tool_misuse"})


class CorpusUnavailable(RuntimeError):
    """The reviewed corpus cannot be loaded exactly and no dispatch may begin."""


@dataclass(frozen=True, slots=True)
class AuthoredCase:
    payload: dict[str, Any]
    content_hash: str


@dataclass(frozen=True, slots=True)
class AuthoredCorpus:
    corpus_id: str
    content_hash: str
    cases: tuple[AuthoredCase, ...]
    categories: frozenset[str]
    root: Path


def corpus_root(configured: str | os.PathLike[str] | None = None) -> Path:
    if configured is not None:
        return Path(configured)
    environment_path = os.environ.get("AGENTFORGE_EVALS_DIR")
    if environment_path:
        return Path(environment_path)
    packaged = Path("/app/evals")
    if packaged.is_dir():
        return packaged
    return Path(__file__).resolve().parents[3] / "evals"


def load_mvp_corpus(root: str | os.PathLike[str] | None = None) -> AuthoredCorpus:
    selected = corpus_root(root)
    summary = validate_corpus(selected)
    if summary.case_count != MVP_CASE_COUNT or summary.categories != MVP_CATEGORIES:
        raise CorpusUnavailable("MVP corpus identity or category coverage differs from policy")
    cases: list[AuthoredCase] = []
    attempts: list[dict[str, Any]] = []
    for path in sorted((selected / "seeds").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        canonical = json.dumps(
            payload, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        cases.append(
            AuthoredCase(
                payload=payload,
                content_hash=hashlib.sha256(canonical).hexdigest(),
            )
        )
        attempts.append(seed_to_attempt(payload))
    if len(cases) != MVP_CASE_COUNT:
        raise CorpusUnavailable("MVP corpus does not contain exactly nine authored cases")
    return AuthoredCorpus(
        corpus_id=MVP_CORPUS_ID,
        content_hash=corpus_sha256(attempts),
        cases=tuple(cases),
        categories=summary.categories,
        root=selected.resolve(),
    )


__all__ = [
    "AuthoredCase",
    "AuthoredCorpus",
    "CorpusUnavailable",
    "MVP_CASE_COUNT",
    "MVP_CATEGORIES",
    "MVP_CORPUS_ID",
    "corpus_root",
    "load_mvp_corpus",
]
