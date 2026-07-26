"""Authorization requests must leave enough time for approval and full execution."""

import pytest
from pydantic import ValidationError

from agentforge.api.router import AuthorizationRequestInput


def _payload(*, run_timeout_seconds: float, expires_in_seconds: int) -> dict[str, object]:
    return {
        "target_id": "openemr-copilot",
        "target_version": "1.0.0",
        "surface_id": "copilot-chat",
        "surface_version": "1.0.0",
        "corpus_hash": "a" * 64,
        "run_nonce": "authorization-window-test",
        "caps": {
            "budget_usd": 5,
            "max_attempts_per_run": 34,
            "target_requests_per_second": 1,
            "run_timeout_seconds": run_timeout_seconds,
        },
        "expires_in_seconds": expires_in_seconds,
    }


def test_authorization_rejects_window_equal_to_run_timeout() -> None:
    with pytest.raises(ValidationError, match="must exceed the run timeout"):
        AuthorizationRequestInput.model_validate(
            _payload(run_timeout_seconds=900, expires_in_seconds=900)
        )


def test_authorization_accepts_approval_and_launch_buffer() -> None:
    request = AuthorizationRequestInput.model_validate(
        _payload(run_timeout_seconds=900, expires_in_seconds=1800)
    )

    assert request.expires_in_seconds == 1800
