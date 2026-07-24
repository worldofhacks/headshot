"""Adapter payload profiles for the full Clinical Co-Pilot Bruno surface set.

ABSOLUTE CONSTRAINT: NO target/network request in ANY test. Every test injects a FAKE HTTP client
(no socket) and exercises only request-shaping + credential-placement policy for each profile:

* ``copilot_public_get``       — GET liveness/readiness; NO credential, NO body, NO auth header.
* ``copilot_evidence_search``  — POST anonymous retrieval; body ``{"query","k"}``, no credential.
* ``copilot_document_upload``  — POST multipart synthetic document; ``session_id`` in the FORM, a
                                 synthetic fixture as the file part, NO Authorization header.
* ``copilot_document_read``    — GET a document sub-resource; ``document_id`` substituted into the
                                 path and ``session_id`` placed in the QUERY, no auth header.

The redaction guarantee holds throughout: the injected session Secret's raw value never appears in
the adapter repr, an error message, or a recorded URL — only in the outgoing wire payload/params
the injected client transmits (the target must receive the real credential).
"""

from __future__ import annotations

import json

import pytest

from agentforge.secrets import Secret
from agentforge.target.base import AdapterError, TargetRequest, TargetResponse
from agentforge.target.openemr_adapter import OpenEmrAdapter

FAKE_SESSION = "sess-sentinel-9f3c-patient-pinned"
BASE_URL = "https://copilot.example.test"


class _FakeResponse:
    def __init__(self, status_code=200, text="", headers=None, content=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        if content is not None:
            self.content = content


class _RecordingClient:
    def __init__(self, response):
        self.response = response
        self.calls: list[dict] = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.response


# --------------------------------------------------------------------------- public GET


def test_public_get_profile_sends_no_body_no_credential_no_auth() -> None:
    client = _RecordingClient(_FakeResponse(200, '{"status":"alive"}'))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="health",
        method="GET",
        payload_profile="copilot_public_get",
        client=client,
        credential=None,
    )

    resp = adapter.send(TargetRequest(turns=()))

    assert isinstance(resp, TargetResponse)
    assert resp.status == 200
    call = client.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == f"{BASE_URL}/health"
    assert "json" not in call  # no request body
    assert call.get("auth") is None
    assert "Authorization" not in call.get("headers", {})


def test_public_get_ready_returns_dependency_envelope_verbatim() -> None:
    envelope = '{"status":"ready","checks":[{"name":"anthropic","ok":true}]}'
    client = _RecordingClient(_FakeResponse(200, envelope))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="ready",
        method="GET",
        payload_profile="copilot_public_get",
        client=client,
    )
    assert adapter.send(TargetRequest(turns=())).output == envelope


# --------------------------------------------------------------------------- evidence search


def test_evidence_search_profile_posts_query_and_k_without_credential() -> None:
    client = _RecordingClient(_FakeResponse(200, '{"items":[]}'))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="evidence/search",
        method="POST",
        payload_profile="copilot_evidence_search",
        client=client,
        credential=None,
    )

    adapter.send(TargetRequest(turns=("type 2 diabetes; HbA1c",), metadata={"k": "5"}))

    call = client.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == f"{BASE_URL}/evidence/search"
    assert call["json"] == {"query": "type 2 diabetes; HbA1c", "k": 5}
    assert call.get("auth") is None
    assert "Authorization" not in call.get("headers", {})


def test_evidence_search_defaults_k_when_absent() -> None:
    client = _RecordingClient(_FakeResponse(200, '{"items":[]}'))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="evidence/search",
        method="POST",
        payload_profile="copilot_evidence_search",
        client=client,
    )
    adapter.send(TargetRequest(turns=("hba1c",)))
    assert client.calls[0]["json"] == {"query": "hba1c", "k": 5}


# --------------------------------------------------------------------------- document upload


def _fixture_resolver(ref: str):
    assert ref == "fixture://clinical-copilot/week2/clean-pdf-20260724"
    return ("clean.pdf", b"%PDF-1.7 synthetic", "application/pdf")


def test_document_upload_profile_posts_multipart_with_session_in_form() -> None:
    client = _RecordingClient(_FakeResponse(200, '{"document_id":"doc-1","state":"complete"}'))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents",
        method="POST",
        payload_profile="copilot_document_upload",
        client=client,
        credential=Secret(FAKE_SESSION),
        fixture_resolver=_fixture_resolver,
    )

    adapter.send(
        TargetRequest(
            turns=(),
            metadata={
                "doc_type": "lab_pdf",
                "fixture_ref": "fixture://clinical-copilot/week2/clean-pdf-20260724",
            },
        )
    )

    call = client.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == f"{BASE_URL}/documents"
    # session_id + doc_type travel in the multipart FORM, not the URL and not a header.
    assert call["data"] == {"session_id": FAKE_SESSION, "doc_type": "lab_pdf"}
    assert call["files"] == {"file": ("clean.pdf", b"%PDF-1.7 synthetic", "application/pdf")}
    assert call.get("auth") is None
    assert "Authorization" not in call.get("headers", {})
    # No JSON Content-Type is forced — the client sets the multipart boundary itself.
    assert call.get("headers", {}).get("Content-Type") != "application/json"


def test_document_upload_without_credential_fails_closed() -> None:
    client = _RecordingClient(_FakeResponse(200, "{}"))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents",
        method="POST",
        payload_profile="copilot_document_upload",
        client=client,
        credential=None,
        fixture_resolver=_fixture_resolver,
    )
    with pytest.raises(AdapterError):
        adapter.send(
            TargetRequest(
                turns=(),
                metadata={
                    "doc_type": "lab_pdf",
                    "fixture_ref": "fixture://clinical-copilot/week2/clean-pdf-20260724",
                },
            )
        )
    assert client.calls == []


def test_document_upload_without_fixture_resolver_fails_closed() -> None:
    client = _RecordingClient(_FakeResponse(200, "{}"))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents",
        method="POST",
        payload_profile="copilot_document_upload",
        client=client,
        credential=Secret(FAKE_SESSION),
    )
    with pytest.raises(AdapterError):
        adapter.send(
            TargetRequest(turns=(), metadata={"doc_type": "lab_pdf", "fixture_ref": "fixture://x"})
        )
    assert client.calls == []


# --------------------------------------------------------------------------- document read


def test_document_read_substitutes_path_param_and_puts_session_in_query() -> None:
    client = _RecordingClient(_FakeResponse(200, '{"state":"complete"}'))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents/{document_id}/status",
        method="GET",
        payload_profile="copilot_document_read",
        client=client,
        credential=Secret(FAKE_SESSION),
    )

    adapter.send(
        TargetRequest(
            turns=(),
            metadata={"path_params": json.dumps({"document_id": "doc-abc-123"})},
        )
    )

    call = client.calls[0]
    assert call["method"] == "GET"
    # document_id is substituted into the PATH; the SID travels in the QUERY params, not the path.
    assert call["url"] == f"{BASE_URL}/documents/doc-abc-123/status"
    assert call["params"] == {"session_id": FAKE_SESSION}
    assert call.get("auth") is None
    # The recorded URL (pre-send) never contains the raw session.
    assert FAKE_SESSION not in call["url"]


def test_document_read_two_path_params_are_substituted() -> None:
    client = _RecordingClient(_FakeResponse(200, "PNGDATA", headers={"Content-Type": "image/png"}))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents/{document_id}/pages/{page}",
        method="GET",
        payload_profile="copilot_document_read",
        client=client,
        credential=Secret(FAKE_SESSION),
        allowed_content_types=("application/json", "image/png"),
    )
    adapter.send(
        TargetRequest(
            turns=(), metadata={"path_params": json.dumps({"document_id": "doc-1", "page": "1"})}
        )
    )
    assert client.calls[0]["url"] == f"{BASE_URL}/documents/doc-1/pages/1"


def test_document_read_missing_path_param_fails_closed() -> None:
    client = _RecordingClient(_FakeResponse(200, "{}"))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents/{document_id}/status",
        method="GET",
        payload_profile="copilot_document_read",
        client=client,
        credential=Secret(FAKE_SESSION),
    )
    with pytest.raises(AdapterError):
        adapter.send(TargetRequest(turns=(), metadata={}))
    assert client.calls == []


@pytest.mark.parametrize("evil", ["../secret", "a/b", "x?y", "z#w", "p%2f"])
def test_document_read_unsafe_path_param_is_refused(evil: str) -> None:
    client = _RecordingClient(_FakeResponse(200, "{}"))
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents/{document_id}/status",
        method="GET",
        payload_profile="copilot_document_read",
        client=client,
        credential=Secret(FAKE_SESSION),
    )
    with pytest.raises(AdapterError):
        adapter.send(
            TargetRequest(turns=(), metadata={"path_params": json.dumps({"document_id": evil})})
        )
    assert client.calls == []


def test_binary_png_response_is_summarized_not_stored_as_mojibake() -> None:
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    client = _RecordingClient(
        _FakeResponse(
            200, png.decode("latin-1"), headers={"Content-Type": "image/png"}, content=png
        )
    )
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents/{document_id}/pages/{page}",
        method="GET",
        payload_profile="copilot_document_read",
        client=client,
        credential=Secret(FAKE_SESSION),
        allowed_content_types=("image/png",),
    )
    resp = adapter.send(
        TargetRequest(
            turns=(), metadata={"path_params": json.dumps({"document_id": "doc-1", "page": "1"})}
        )
    )
    summary = json.loads(resp.output)
    assert summary["binary_response"] is True
    assert summary["content_type"] == "image/png"
    assert summary["byte_length"] == len(png)
    assert len(summary["sha256"]) == 64


# ------------------------------------------------------------------- redaction + construction


def test_session_never_appears_in_repr_for_new_profiles() -> None:
    adapter = OpenEmrAdapter(
        base_url=BASE_URL,
        relative_path="documents/{document_id}/status",
        method="GET",
        payload_profile="copilot_document_read",
        credential=Secret(FAKE_SESSION),
    )
    assert FAKE_SESSION not in repr(adapter)


def test_public_get_profile_requires_get_method() -> None:
    with pytest.raises(ValueError):
        OpenEmrAdapter(
            base_url=BASE_URL,
            relative_path="health",
            method="POST",
            payload_profile="copilot_public_get",
        )


def test_document_upload_profile_requires_post_method() -> None:
    with pytest.raises(ValueError):
        OpenEmrAdapter(
            base_url=BASE_URL,
            relative_path="documents",
            method="GET",
            payload_profile="copilot_document_upload",
        )
