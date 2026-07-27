"""An un-parseable Red Team PROPOSAL costs one case, not the whole campaign.

Live incident, campaign ``8f44953bdd10`` (headshot-live-100-batch-01, 34 authorized cases). Three
cases adjudicated normally; the fourth killed the run:

    CampaignAbort[red_team_proposal_failed]
      <- HostedStructuredOutputInvalid[invalid_structured_output]
        <- HostedProviderError[hosted-provider-unavailable]
          <- TypeError

The durable ``provider_call_events`` rows for that run name the cause exactly. Successful Red Team
selections emitted 3677 / 3720 / 3676 output tokens; the failing one emitted **16383** — one below
16384, the role's whole output ceiling (8192 output + 8192 reasoning) — after 295 seconds. The
model ran away, hit the cap, and OpenRouter returned ``content: null``.

Two separate defects sat behind that abort, and this suite covers the second one.

* Classification (already fixed in ``providers/openrouter.py``, pinned by
  ``tests/test_structured_output_truncation.py``): ``json.loads(None)`` raised ``TypeError``, which
  a broad handler rewrote into a generic "failed validation".
* **Isolation (here).** The DISPATCH phase already isolates ``HostedStructuredOutputInvalid`` per
  case — that is what ``tests/test_campaign_fault_isolation_db.py`` proves. The PROPOSAL phase did
  not: its handler rewrote *every* exception into a campaign-fatal ``CampaignAbort``, and both
  ``select_next_work()`` call sites sit outside the loop's isolation. So one un-parseable proposal
  discarded the authority to evaluate the other 30 authorized cases.

The two phases cannot be isolated the same way, and the difference is the whole design. A dispatch
failure happens *after* the target turns ran, so its evidence exists and an ERROR verdict can be
written against it. A proposal failure produced no target traffic at all — nothing was attacked and
nothing was adjudicated — so the pre-bound attempt is abandoned un-attempted rather than handed a
verdict it did not earn. ``_record_operational_error_verdict`` is deliberately NOT reused: it
demands a persisted evidence hash and would abort with ``attempt_evidence_unavailable``, swapping
one campaign-fatal abort for another.

What this pins, against a real migrated PostgreSQL, the real control-plane store, the real
``OpenRouterTransport`` (so retry admission, ledger settlement and provider lineage are all
genuine) and the real Runner loop — only the socket is scripted:

* a proposal-phase ``HostedStructuredOutputInvalid`` costs exactly one case;
* ``HostedStructuredOutputTruncated``, the production shape, is isolated identically because it is
  a subclass;
* a proposal-phase ``HostedProviderUnavailable`` — an upstream that could not be reached after its
  authorized retry — costs exactly one case on the same terms. This is the SECOND live incident,
  campaign ``75ab8ed7`` at 14:41 on 2026-07-27, which reached 4 of 34 cases before one retryable
  upstream status ended it: ``CampaignAbort[red_team_proposal_failed] <-
  HostedProviderError[hosted-provider-unavailable] <- _RetryableResponse``. With
  ``max_retries = 0`` the first transient blip is also the last, so a single 429/502/503 outside
  anyone's control discarded 30 authorized cases;
* the isolated provider fault is a distinct TYPE, never an error code — the base class and several
  campaign-fatal siblings share the identical ``hosted-provider-unavailable`` code;
* the abandoned attempt gets no verdict, no evidence, no finding and no Documentation execution;
* migration 0026's identity ``decisive + indeterminate + operational_error = attempt_count`` still
  holds for the completed run;
* budget, provider-route, model-identity and credential failures during the proposal still abort;
* a wholly broken model reaches an honest terminal abort instead of a "complete" summary over a
  campaign that attacked nothing.

Also recorded here: the failing production call had only ``physical_sequence=1``. That is governed,
not a bug — ``scripts/derive_retry_configuration.py`` grants retry authority to the Judge alone, so
``red_team.max_retries == 0`` and the transport sends exactly once. A retry would not have helped
anyway: 16383 of 16384 output tokens is a deterministic run-away, not a transient.
"""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import Engine

import agentforge.runner as runner_module
from agentforge.agents.red_team import HostedReplaySelectorError
from agentforge.campaign.coordinator import CampaignAbort
from agentforge.campaign.corpus import LIVE_100_BATCH_IDS
from agentforge.control_plane.store import _EXACT_COUNT_CORPUS_ID
from agentforge.policy.scoped_credentials import (
    CredentialLeaseExpiredError,
    CredentialResolutionError,
)
from agentforge.providers.openrouter import (
    HostedBudgetExceeded,
    HostedProviderUnavailable,
    HostedRetryAdmissionRefused,
    HostedSettlementAccountingInvalid,
    HostedSettlementBudgetExceeded,
    HostedStructuredOutputInvalid,
    HostedStructuredOutputTruncated,
)
from agentforge.runner import DispatchUnavailable, _AbandonedProposal

# The dispatch-phase isolation suite already owns an authorized nine-case hosted campaign against a
# migrated database. Reusing its harness keeps the two phases provably under the SAME campaign
# shape, so a divergence between them is a real behavioural difference and not a fixture artefact.
from test_campaign_fault_isolation_db import (  # type: ignore[import-not-found]
    _MODELS,
    _conforming,
    _install_scripted_provider,
    _rows,
    _runner,
)
from test_campaign_fault_isolation_db import (
    hosted_campaign as _authorized_hosted_campaign,  # type: ignore[import-not-found]
)

#: Bound under the fixture's own name so pytest resolves it inside this module too. Aliased on
#: import rather than re-declared, so the two suites can never drift onto different campaigns.
hosted_campaign = _authorized_hosted_campaign

# Exactly what the provider returned on the run that died: the completion ran to the ceiling and no
# assistant content survived it.
_RUNAWAY_OUTPUT_TOKENS = 16_383
_RUNAWAY_REASONING_TOKENS = 1


class _RedTeamProvider:
    """A provider socket that answers every role, and can break the Red Team on a named case.

    Each ``*_for_ordinals`` set names *attempt ordinals* whose Red Team call should fail in one
    specific way. Every failure is injected at the wire, after full measured usage, so settlement
    genuinely succeeds and the fault is post-measurement — exactly as in production. Nothing is
    stubbed above the socket.
    """

    def __init__(
        self,
        *,
        truncated_for_ordinals: frozenset[int] = frozenset(),
        malformed_for_ordinals: frozenset[int] = frozenset(),
        overcharged_for_ordinals: frozenset[int] = frozenset(),
        unauthorized_route_for_ordinals: frozenset[int] = frozenset(),
        substituted_model_for_ordinals: frozenset[int] = frozenset(),
        unavailable_for_ordinals: frozenset[int] = frozenset(),
    ) -> None:
        self._truncated = truncated_for_ordinals
        self._malformed = malformed_for_ordinals
        self._overcharged = overcharged_for_ordinals
        self._unauthorized_route = unauthorized_route_for_ordinals
        self._substituted_model = substituted_model_for_ordinals
        self._unavailable = unavailable_for_ordinals
        self.requests: list[str] = []
        self._case_ordinal = 0

    def note_case(self, ordinal: int) -> None:
        self._case_ordinal = ordinal

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        model = body.get("model", "")
        role = next((r for r, (m, _u, _s) in _MODELS.items() if m == model), "unknown")
        self.requests.append(role)
        served = _MODELS[role][2] if role in _MODELS else "Unknown"
        if role == "red_team" and self._case_ordinal in self._unavailable:
            # The production shape of the 14:41 abort on run 75ab8ed7: a retryable upstream status
            # with nothing observed. Returned at the wire so the REAL transport classifies it,
            # exhausts its authorized retry, and raises its own typed exhaustion — nothing about
            # the failure is stubbed above the socket.
            return httpx.Response(503, json={"error": {"message": "upstream unavailable"}})

        schema = body["response_format"]["json_schema"]["schema"]
        content: str | None = json.dumps(_conforming(schema))
        cost = 0.000001
        output_tokens = 5
        reasoning_tokens = 1
        reported_model = model
        finish_reason = "stop"

        if role == "red_team" and self._case_ordinal in self._truncated:
            # The production shape: HTTP 200, correct identity and route, measured usage right at
            # the ceiling, and no assistant content at all.
            content = None
            finish_reason = "length"
            output_tokens = _RUNAWAY_OUTPUT_TOKENS
            reasoning_tokens = _RUNAWAY_REASONING_TOKENS
        elif role == "red_team" and self._case_ordinal in self._malformed:
            # Valid JSON, wrong shape — a formatting failure that is not a truncation.
            content = json.dumps({"totally": "unexpected"})
        elif role == "red_team" and self._case_ordinal in self._overcharged:
            # A measured cost past the role's authorized ceiling: settlement, not formatting.
            cost = 5.0
        elif role == "red_team" and self._case_ordinal in self._unauthorized_route:
            served = "SomeOtherUpstream"
        elif role == "red_team" and self._case_ordinal in self._substituted_model:
            reported_model = "someone-else/not-the-authorized-model"

        return httpx.Response(
            200,
            json={
                "id": f"gen-{role}-{len(self.requests)}",
                "model": reported_model,
                "choices": [{"finish_reason": finish_reason, "message": {"content": content}}],
                "usage": {
                    "prompt_tokens": 10,
                    # OpenRouter reports reasoning INSIDE completion_tokens; the transport stores
                    # the disjoint counts. Report the sum so the durable rows carry the exact
                    # numbers this fixture names.
                    "completion_tokens": output_tokens + reasoning_tokens,
                    "completion_tokens_details": {"reasoning_tokens": reasoning_tokens},
                    "cost": cost,
                },
                "openrouter_metadata": {
                    "requested": model,
                    "endpoints": {
                        "available": [
                            {"selected": True, "provider": served, "model": model},
                        ]
                    },
                },
            },
        )


def _drive(monkeypatch, corpus, provider: _RedTeamProvider) -> None:
    """Install the scripted socket and let it see which attempt ordinal is in flight."""

    _install_scripted_provider(monkeypatch, provider)
    # The hosted selection path is only defined for exact-manifest workloads; treat the nine-case
    # MVP corpus as one so it can exercise the same pre-bound-attempt chronology as live-100.
    monkeypatch.setattr(
        runner_module,
        "_EXACT_MANIFEST_WORKLOAD_IDS",
        frozenset({*runner_module._EXACT_MANIFEST_WORKLOAD_IDS, corpus.corpus_id}),
    )
    real_ensure = runner_module.DurableCampaignRunner._ensure_attempt_for_case

    def tracking_ensure(self, *, run_id, ordinal, case):
        # On the hosted path this runs immediately before the Red Team call for the pre-bound
        # case, so the ordinal is authoritative for the proposal about to be made.
        provider.note_case(ordinal)
        return real_ensure(self, run_id=run_id, ordinal=ordinal, case=case)

    monkeypatch.setattr(
        runner_module.DurableCampaignRunner, "_ensure_attempt_for_case", tracking_ensure
    )


def _role_configuration(configuration, name: str):
    return next(role for role in configuration.roles if role.role == name)


def _summaries(engine: Engine, run_id: str):
    return _rows(
        engine,
        "SELECT attempt_count, decisive_verdict_count, indeterminate_verdict_count, "
        "operational_error_count FROM campaign_run_summaries WHERE run_id = :r",
        r=run_id,
    )


def _states(engine: Engine, run_id: str) -> list[str]:
    return [
        row["state"]
        for row in _rows(
            engine,
            "SELECT state FROM campaign_run_events WHERE run_id = :r ORDER BY id",
            r=run_id,
        )
    ]


def _attempts(engine: Engine, run_id: str):
    return _rows(
        engine,
        "SELECT attempt_id, ordinal, case_id FROM campaign_attempts "
        "WHERE run_id = :r ORDER BY ordinal",
        r=run_id,
    )


def _verdicts(engine: Engine, run_id: str) -> dict[str, dict]:
    return {
        row["attempt_id"]: row
        for row in _rows(
            engine,
            "SELECT attempt_id, state, error_code FROM verdict WHERE campaign_run_id = :r",
            r=run_id,
        )
    }


# ---------------------------------------------------------------------------------------
# The incident: one un-parseable proposal must cost exactly one case.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("failure_kind", "expected_error_code"),
    [
        ("truncated_for_ordinals", "structured_output_truncated"),
        ("malformed_for_ordinals", "invalid_structured_output"),
        # An unreachable provider isolates on identical terms. This is the 14:41 abort of run
        # 75ab8ed7, which reached 4 of 34 cases before one retryable upstream status ended it —
        # and with max_retries=0 the first blip is also the last. Nothing was observed, so like a
        # proposal that would not parse it is a fact about ONE case, not about the run's authority.
        ("unavailable_for_ordinals", "hosted-provider-unavailable"),
    ],
)
def test_an_unparseable_proposal_isolates_one_case_and_the_campaign_continues(
    hosted_campaign, monkeypatch, tmp_path, failure_kind, expected_error_code
) -> None:
    """The regression that ended run 8f44953bdd10, reproduced and now survived.

    Both parameters are the same isolation on the same seam: ``HostedStructuredOutputTruncated``
    (the production shape) is a *subclass* of ``HostedStructuredOutputInvalid``, which is precisely
    why the narrowed handler needs no second branch for it.
    """

    store, run, corpus, configuration, _physical = hosted_campaign
    engine = store._engine
    provider = _RedTeamProvider(**{failure_kind: frozenset({1})})
    _drive(monkeypatch, corpus, provider)

    runner = _runner(store, corpus, tmp_path, configuration)
    assert runner.run_once(worker_id="proposal-isolation-test") is True

    # --- the campaign reached the end rather than dead-lettering on case 2 -------------
    states = _states(engine, run.run_id)
    assert "failed" not in states and "aborted" not in states, states
    assert states[-1] == "complete"

    # --- the abandoned case still owns its ordinal, and nothing after it shifted -------
    attempts = _attempts(engine, run.run_id)
    assert [row["ordinal"] for row in attempts] == list(range(len(corpus.cases)))
    abandoned = attempts[1]["attempt_id"]

    # --- it was abandoned un-attempted: no evidence, no verdict, no fabrication --------
    verdicts = _verdicts(engine, run.run_id)
    assert abandoned not in verdicts, "a case that was never attacked must not be adjudicated"
    evidence = _rows(
        engine,
        "SELECT attempt_id FROM attempt_result WHERE campaign_run_id = :r AND attempt_id = :a",
        r=run.run_id,
        a=abandoned,
    )
    assert evidence == [], "no target turn ran, so no evidence may exist"
    assert store.persisted_evidence_content_hash(run_id=run.run_id, attempt_id=abandoned) is None

    # --- every OTHER authorized case was really evaluated ------------------------------
    assert len(verdicts) == len(corpus.cases) - 1
    for row in attempts:
        if row["attempt_id"] == abandoned:
            continue
        assert verdicts[row["attempt_id"]]["state"] != "ERROR"

    # --- the failure is not silent: the hosted execution carries the typed reason -------
    red_team_executions = _rows(
        engine,
        "SELECT execution_id, status, error_code FROM agent_executions "
        "WHERE campaign_run_id = :r AND agent_role = 'red_team' AND attempt_id = :a",
        r=run.run_id,
        a=abandoned,
    )
    assert len(red_team_executions) == 1
    assert red_team_executions[0]["status"] == "failed"
    assert red_team_executions[0]["error_code"] == expected_error_code

    # --- ERROR is never a security signal, and neither is an abandoned proposal --------
    findings = _rows(
        engine,
        "SELECT attempt_id FROM finding_evidence_links WHERE campaign_run_id = :r",
        r=run.run_id,
    )
    assert abandoned not in {row["attempt_id"] for row in findings}
    documentation = _rows(
        engine,
        "SELECT attempt_id FROM agent_executions "
        "WHERE campaign_run_id = :r AND agent_role = 'documentation'",
        r=run.run_id,
    )
    assert abandoned not in {row["attempt_id"] for row in documentation}

    # --- migration 0026's identity still holds for the completed run -------------------
    summary = _rows(
        engine,
        "SELECT attempt_count, decisive_verdict_count, indeterminate_verdict_count, "
        "operational_error_count FROM campaign_run_summaries WHERE run_id = :r",
        r=run.run_id,
    )[0]
    assert summary["attempt_count"] == len(corpus.cases) - 1
    assert (
        summary["decisive_verdict_count"]
        + summary["indeterminate_verdict_count"]
        + summary["operational_error_count"]
    ) == summary["attempt_count"]
    # An abandoned proposal is not an operational-error VERDICT. It contributes nothing to any of
    # the four terms, which is exactly why the CHECK holds without a migration.
    assert summary["operational_error_count"] == 0


def test_the_red_team_proposal_is_sent_exactly_once(hosted_campaign, monkeypatch, tmp_path) -> None:
    """The production observation — one physical_sequence, no retry row — is governed, not a bug.

    ``derive_retry_configuration.py`` grants retry authority to the Judge alone, so the Red Team's
    ``max_retries`` is 0 and the transport sends once. This test does not argue for changing that;
    it pins the fact so the absent retry row is never mistaken for a lost write.
    """

    store, run, corpus, configuration, _physical = hosted_campaign
    engine = store._engine
    provider = _RedTeamProvider(truncated_for_ordinals=frozenset({1}))
    _drive(monkeypatch, corpus, provider)

    assert _role_configuration(configuration, "red_team").limits.max_retries == 0
    runner = _runner(store, corpus, tmp_path, configuration)
    assert runner.run_once(worker_id="proposal-isolation-test") is True

    abandoned = _attempts(engine, run.run_id)[1]["attempt_id"]
    sequences = [
        row["physical_sequence"]
        for row in _rows(
            engine,
            "SELECT pci.physical_sequence FROM provider_call_invocations pci "
            "JOIN agent_executions ae ON ae.execution_id = pci.logical_execution_id "
            "WHERE pci.campaign_run_id = :r AND ae.agent_role = 'red_team' "
            "AND ae.attempt_id = :a ORDER BY pci.physical_sequence",
            r=run.run_id,
            a=abandoned,
        )
    ]
    assert sequences == [1]

    statuses = [
        row["status"]
        for row in _rows(
            engine,
            "SELECT pce.status FROM provider_call_events pce "
            "JOIN agent_executions ae ON ae.execution_id = pce.logical_execution_id "
            "WHERE pce.campaign_run_id = :r AND ae.agent_role = 'red_team' AND ae.attempt_id = :a",
            r=run.run_id,
            a=abandoned,
        )
    ]
    assert statuses == ["invalid_output"]

    # The run-away is durably measured, so the operator can see WHY it failed rather than only that
    # it did. This is the number that named the fault on run 8f44953bdd10.
    tokens = _rows(
        engine,
        "SELECT pce.output_tokens FROM provider_call_events pce "
        "JOIN agent_executions ae ON ae.execution_id = pce.logical_execution_id "
        "WHERE pce.campaign_run_id = :r AND ae.agent_role = 'red_team' AND ae.attempt_id = :a",
        r=run.run_id,
        a=abandoned,
    )
    assert [row["output_tokens"] for row in tokens] == [_RUNAWAY_OUTPUT_TOKENS]


def test_several_abandoned_proposals_still_leave_a_truthful_completed_run(
    hosted_campaign, monkeypatch, tmp_path
) -> None:
    """Isolation must compose: three broken proposals cost three cases, not three campaigns."""

    store, run, corpus, configuration, _physical = hosted_campaign
    engine = store._engine
    broken = frozenset({1, 3, 6})
    provider = _RedTeamProvider(truncated_for_ordinals=broken)
    _drive(monkeypatch, corpus, provider)

    runner = _runner(store, corpus, tmp_path, configuration)
    assert runner.run_once(worker_id="proposal-isolation-test") is True
    assert _states(engine, run.run_id)[-1] == "complete"

    attempts = _attempts(engine, run.run_id)
    verdicts = _verdicts(engine, run.run_id)
    abandoned = {row["attempt_id"] for row in attempts if row["ordinal"] in broken}
    assert len(abandoned) == len(broken)
    assert abandoned.isdisjoint(verdicts)
    assert len(verdicts) == len(corpus.cases) - len(broken)

    summary = _rows(
        engine,
        "SELECT attempt_count, decisive_verdict_count, indeterminate_verdict_count, "
        "operational_error_count FROM campaign_run_summaries WHERE run_id = :r",
        r=run.run_id,
    )[0]
    assert summary["attempt_count"] == len(corpus.cases) - len(broken)
    assert (
        summary["decisive_verdict_count"]
        + summary["indeterminate_verdict_count"]
        + summary["operational_error_count"]
    ) == summary["attempt_count"]


# ---------------------------------------------------------------------------------------
# A campaign that attacked nothing may never be reported as a campaign that found nothing.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure_kind",
    ["truncated_for_ordinals", "unavailable_for_ordinals"],
)
def test_a_wholly_broken_model_aborts_instead_of_completing_an_empty_campaign(
    hosted_campaign, monkeypatch, tmp_path, failure_kind
) -> None:
    """Total abandonment is the one case where the original abort is still the honest answer.

    Parametrized over both isolatable faults because the risk they create is identical and is the
    dangerous one: isolation must never turn a total outage into a campaign that reports finding
    nothing. A sustained provider outage abandons every case in turn and must still end `aborted`
    with no summary and no verdicts, exactly as a wholly unparseable model does.
    """

    store, run, corpus, configuration, _physical = hosted_campaign
    engine = store._engine
    provider = _RedTeamProvider(
        **{failure_kind: frozenset(range(len(corpus.cases)))},
    )
    _drive(monkeypatch, corpus, provider)

    runner = _runner(store, corpus, tmp_path, configuration)
    # It terminates rather than spinning: every cycle removes one case from remaining authority.
    with pytest.raises(DispatchUnavailable, match="campaign_aborted"):
        runner.run_once(worker_id="proposal-isolation-test")

    states = _states(engine, run.run_id)
    assert states[-1] == "aborted"
    assert "complete" not in states
    assert _summaries(engine, run.run_id) == []
    assert _verdicts(engine, run.run_id) == {}
    assert (
        _rows(
            engine,
            "SELECT attempt_id FROM attempt_result WHERE campaign_run_id = :r",
            r=run.run_id,
        )
        == []
    )
    # Every case was pre-bound and then abandoned; none was silently dropped from the ledger.
    assert len(_attempts(engine, run.run_id)) == len(corpus.cases)
    # One orchestrator and one Red Team call per case, exactly as on the success path — the
    # exact-caps envelope is unchanged by abandoning.
    assert provider.requests.count("red_team") == len(corpus.cases)
    assert provider.requests.count("orchestrator") == len(corpus.cases)


# ---------------------------------------------------------------------------------------
# The isolation must stay narrow: every genuinely campaign-fatal proposal failure still aborts.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure_kind",
    [
        "overcharged_for_ordinals",
        "unauthorized_route_for_ordinals",
        "substituted_model_for_ordinals",
    ],
)
def test_a_governance_failure_during_the_proposal_still_aborts_the_campaign(
    hosted_campaign, monkeypatch, tmp_path, failure_kind
) -> None:
    """Budget exhaustion, an unauthorized provider route and a substituted model are facts about
    the whole run, not about one case, and none of them may be skipped past."""

    store, run, corpus, configuration, _physical = hosted_campaign
    engine = store._engine
    provider = _RedTeamProvider(**{failure_kind: frozenset({1})})
    _drive(monkeypatch, corpus, provider)

    runner = _runner(store, corpus, tmp_path, configuration)
    with pytest.raises(DispatchUnavailable, match="campaign_aborted"):
        runner.run_once(worker_id="proposal-isolation-test")

    states = _states(engine, run.run_id)
    assert states[-1] == "aborted"
    assert "complete" not in states
    assert _summaries(engine, run.run_id) == []
    # It stopped AT the offending case rather than skipping onward through the corpus.
    assert len(_attempts(engine, run.run_id)) == 2
    assert len(_verdicts(engine, run.run_id)) == 1


def test_a_credential_failure_during_the_proposal_still_aborts_the_campaign(
    hosted_campaign, monkeypatch, tmp_path
) -> None:
    """A credential that stops resolving mid-run is an authority failure, never a skippable case."""

    store, run, corpus, configuration, _physical = hosted_campaign
    engine = store._engine
    provider = _RedTeamProvider()
    _drive(monkeypatch, corpus, provider)

    runner = _runner(store, corpus, tmp_path, configuration)
    red_team_reference = _role_configuration(configuration, "red_team").credential_reference
    resolver = runner.credentials
    real_resolve = resolver.resolve
    seen = {"red_team": 0}

    def failing_resolve(reference: str):
        if reference == red_team_reference:
            seen["red_team"] += 1
            if seen["red_team"] > 1:
                raise CredentialResolutionError("hosted credential lease is gone")
        return real_resolve(reference)

    monkeypatch.setattr(resolver, "resolve", failing_resolve)

    with pytest.raises(DispatchUnavailable, match="campaign_aborted"):
        runner.run_once(worker_id="proposal-isolation-test")

    states = _states(engine, run.run_id)
    assert states[-1] == "aborted"
    assert "complete" not in states
    assert _summaries(engine, run.run_id) == []
    assert len(_verdicts(engine, run.run_id)) == 1


# ---------------------------------------------------------------------------------------
# Type algebra. The isolation is only safe because the isolatable set is exactly one branch wide.
# ---------------------------------------------------------------------------------------


def test_truncation_rides_the_same_isolation_because_it_is_a_subclass() -> None:
    """The single reason the narrowed handler needs no branch for the production failure shape."""

    assert issubclass(HostedStructuredOutputTruncated, HostedStructuredOutputInvalid)


@pytest.mark.parametrize(
    "governance_type",
    [
        HostedRetryAdmissionRefused,
        HostedBudgetExceeded,
        HostedSettlementBudgetExceeded,
        HostedSettlementAccountingInvalid,
        HostedReplaySelectorError,
        CampaignAbort,
        DispatchUnavailable,
        CredentialResolutionError,
        CredentialLeaseExpiredError,
    ],
)
def test_no_campaign_fatal_type_can_be_swallowed_by_the_proposal_isolation(
    governance_type,
) -> None:
    """Cap exhaustion, refused retry authority, an unauthorized selection, a lost lease and a dead
    credential are all facts about the run. None may be an instance of the isolatable type."""

    assert not issubclass(governance_type, HostedStructuredOutputInvalid)
    # The provider-unreachable type is isolated on the same terms, so it needs the same guard.
    # HostedProviderUnavailable is a SUBCLASS of HostedProviderError, and several governance
    # failures — budget exhaustion, settlement, accounting — are siblings under that same base.
    # Isolating the base would have swallowed every one of them.
    assert not issubclass(governance_type, HostedProviderUnavailable)


def test_an_abandoned_proposal_is_not_an_abort_and_carries_the_case_it_dropped() -> None:
    """It must not be catchable as a campaign failure, and it must name its own case precisely.

    Naming the exact case is what lets the selection loop prune remaining authority instead of
    assuming ``remaining[0]``, and advancing the ordinal with it is what stops the NEXT case from
    colliding with the abandoned attempt's immutable ordinal.
    """

    sentinel = object()
    abandoned = _AbandonedProposal(
        case=sentinel,
        case_id="case-042",
        attempt_id="a" * 64,
        error_code="structured_output_truncated",
    )

    assert not isinstance(abandoned, CampaignAbort)
    assert not isinstance(abandoned, DispatchUnavailable)
    assert abandoned.case is sentinel
    assert abandoned.case_id == "case-042"
    assert abandoned.error_code == "structured_output_truncated"


def test_the_incident_corpus_is_outside_the_exact_completion_count_gate() -> None:
    """Bounds the one residual risk this change knowingly leaves open.

    ``complete_campaign_job`` refuses completion when the corpus is ``_EXACT_COUNT_CORPUS_ID`` and
    the durable attempt count differs from the authorized ``logical_case_limit``. An abandoned
    proposal lowers that count by one, so on the live-100 WHOLE a completed run with an abandoned
    case would be refused. The batches — which is how live-100 is actually dispatched, and what run
    8f44953bdd10 was — are separately authorized workloads and are NOT that corpus, so this change
    does not silently arm that gate. Pinned so a future re-authorization of the whole cannot make
    the residual invisible.
    """

    assert _EXACT_COUNT_CORPUS_ID not in LIVE_100_BATCH_IDS


def test_the_isolatable_provider_fault_is_a_type_and_never_an_error_code() -> None:
    """The trap this change had to avoid, pinned so nobody re-introduces it.

    ``HostedProviderUnavailable`` does not own its ``code``: the base class and several genuinely
    campaign-fatal types share the identical string ``hosted-provider-unavailable``. Isolating on
    the code — or on the base class — would therefore have swallowed a settlement failure, an
    unobserved physical-call fault, and an absent structured output, every one of which must abort
    the run. Only the exact narrow subclass may be isolated.
    """

    from agentforge.providers.openrouter import (  # noqa: PLC0415
        HostedProviderError,
        HostedSettlementFailed,
    )

    assert HostedSettlementFailed.code == HostedProviderUnavailable.code
    assert HostedProviderError.code == HostedProviderUnavailable.code
    # Sharing a code, but NOT the isolatable type — which is the whole reason the handler
    # discriminates by type.
    assert not issubclass(HostedSettlementFailed, HostedProviderUnavailable)
