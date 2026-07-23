from __future__ import annotations

import shutil

import pytest

from agentforge.campaign.corpus import (
    FULL_SCAN_CASE_COUNT,
    CorpusUnavailable,
    load_full_scan_corpus,
    reviewed_bundle_root,
)


def test_full_scan_corpus_binds_reviewed_tool_candidates() -> None:
    corpus = load_full_scan_corpus()

    assert len(corpus.cases) == FULL_SCAN_CASE_COUNT
    assert corpus.tool_sources == ("garak", "promptfoo", "pyrit")
    generated = corpus.cases[-5:]
    assert all(case.payload["case_id"].startswith("AF-M11-TOOL-") for case in generated)
    assert all(
        "provenance sha256" in case.payload["test_design"]["adversarial_condition"]
        for case in generated
    )
    assert any(len(case.payload["input_sequence"][0]) > 1_000 for case in generated)


def test_full_scan_corpus_rejects_tampered_reviewed_bundle(tmp_path) -> None:
    source = reviewed_bundle_root()
    for path in source.glob("*.bundle.json"):
        shutil.copy2(path, tmp_path / path.name)
    promptfoo = tmp_path / "promptfoo.bundle.json"
    promptfoo.write_bytes(promptfoo.read_bytes() + b" ")

    with pytest.raises(CorpusUnavailable, match="pinned digest"):
        load_full_scan_corpus(bundle_root=tmp_path)
