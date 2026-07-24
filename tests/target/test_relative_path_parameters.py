"""Parameterized relative-path support for sub-resource attack surfaces.

Some targets expose sub-resources whose path carries a server-issued resource id (and an index),
e.g. ``documents/{document_id}/status`` and ``documents/{document_id}/pages/{page}``. A surface must
declare that shape as a trusted, immutable ``relative_path`` while still refusing traversal, absolute
paths, URL-override syntax, and any second authority. Concrete values are substituted only at the
dispatch boundary from the authorized attempt — the surface path itself stays a stable template.
"""

from __future__ import annotations

import pytest

from agentforge.target.spec import (
    DefinitionError,
    relative_path_parameters,
    validate_relative_path,
)


def test_static_path_has_no_parameters() -> None:
    assert validate_relative_path("evidence/search") == "evidence/search"
    assert relative_path_parameters("evidence/search") == ()


def test_single_parameter_segment_is_accepted_and_extracted() -> None:
    path = validate_relative_path("documents/{document_id}/status")
    assert path == "documents/{document_id}/status"
    assert relative_path_parameters(path) == ("document_id",)


def test_multiple_distinct_parameters_are_ordered() -> None:
    path = validate_relative_path("documents/{document_id}/pages/{page}")
    assert relative_path_parameters(path) == ("document_id", "page")


def test_repeated_parameter_name_is_rejected() -> None:
    with pytest.raises(DefinitionError):
        validate_relative_path("documents/{document_id}/x/{document_id}")


@pytest.mark.parametrize(
    "bad",
    [
        "documents/{}/status",  # empty name
        "documents/{1id}/status",  # must start with a letter
        "documents/{Document}/status",  # uppercase not allowed
        "documents/{doc-id}/status",  # hyphen not allowed in a param name
        "documents/x{id}/status",  # literal + param mixed in one segment
        "documents/{id}x/status",  # param + literal mixed in one segment
        "documents/{a}{b}/status",  # two params in one segment
        "documents/{id/status",  # unbalanced brace
    ],
)
def test_malformed_parameter_segments_are_rejected(bad: str) -> None:
    with pytest.raises(DefinitionError):
        validate_relative_path(bad)


@pytest.mark.parametrize(
    "bad",
    [
        "/documents/{document_id}/status",  # absolute
        "documents/../{document_id}",  # traversal
        "documents/{document_id}/status?x=1",  # query
        "documents/{document_id}%2f",  # percent-encoding
    ],
)
def test_traversal_and_override_still_refused_with_parameters(bad: str) -> None:
    with pytest.raises(DefinitionError):
        validate_relative_path(bad)
