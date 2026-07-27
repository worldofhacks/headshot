"""A campaign survives an un-adjudicable case — proven against a migrated PostgreSQL.

Run 50da57b037d44b3c93a10e4c2edf61a8 completed 11 of 34 cases and then dead-lettered because
Gemini returned one schema-invalid body on case 12. Both of that case's target turns had already
succeeded and its evidence was durably written; only adjudication failed. The remaining 22 cases
were never attempted.

This exercises the real thing end to end: a real migrated database, the real control-plane store,
the real ``OpenRouterTransport`` (so retry classification, ledger settlement and provider lineage
are all genuine), and the real Runner campaign loop. Only the socket is faked, by a scripted
``httpx.MockTransport``, so the Judge can be made to return schema-invalid bodies on demand.

What it pins:

* case 1 adjudicates normally;
* case 2's Judge returns two schema-invalid responses, exhausting its authorized retry;
* case 2 still receives a durable ERROR verdict against its already-observed evidence;
* no finding and no Documentation execution is created for that case;
* case 3 executes afterwards — the campaign is not abandoned;
* every authored turn produced exactly one target request, and the retry produced none;
* physical provider sequences and per-role totals reconcile with the durable rows;
* the campaign summary reports the operational error separately from security verdicts.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from decimal import Decimal

import httpx
import pytest
from sqlalchemy import Engine, text

import agentforge.runner as runner_module
from agentforge.agents.hosted import (
    HostedConfigurationSet,
    HostedLimits,
    HostedRoleConfiguration,
    TokenPrices,
)
from agentforge.agents.hosted_policy import DEFAULT_HOSTED_GENERATION_POLICY
from agentforge.agents.prompts import load_prompt_registry
from agentforge.auth.permissions import (
    CAMPAIGN_AUTHORIZE,
    CAMPAIGN_LAUNCH,
    CONFIG_MANAGE,
    TARGETS_MANAGE,
)
from agentforge.auth.principal import Principal
from agentforge.campaign.corpus import load_mvp_corpus, verified_case_payload
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.policy.scoped_credentials import SealedEnvironmentCredentialResolver
from agentforge.providers.openrouter import OpenRouterTransport
from agentforge.target.catalog import TrustedTargetCatalog
from agentforge.target.spec import ExecutionProfile, HostedRunBinding, SafetyCaps
from agentforge.telemetry import OutboundHttpTelemetry
from test_hosted_agent_execution_lineage import (
    _LangfuseProjection,  # type: ignore[import-not-found]
)

_ORG = "org_FaultIsolation"
_PROMPTS = {record.role: record for record in load_prompt_registry()}
_POLICY = DEFAULT_HOSTED_GENERATION_POLICY
_POLICY_SHA = _POLICY.policy_sha256

_MODELS = {
    "orchestrator": ("anthropic/claude-opus-4.8", "anthropic", "Anthropic"),
    "red_team": ("qwen/qwen3.5-397b-a17b", "chutes", "Chutes"),
    "judge": ("google/gemini-2.5-pro", "google-vertex", "Google"),
    "documentation": ("openai/gpt-5.4", "openai", "OpenAI"),
}


def _principal(user: str, *permissions: str) -> Principal:
    return Principal(
        user_id=user,
        session_id=f"sess_{user}",
        organization_id=_ORG,
        organization_role="org:operator",
        organization_permissions=frozenset(permissions),
    )


def _configuration(*, judge_retries: int) -> HostedConfigurationSet:
    """Four-role configuration; only the Judge is granted retry authority."""

    roles = []
    for role, (model, upstream, _served) in _MODELS.items():
        roles.append(
            HostedRoleConfiguration(
                role=role,  # type: ignore[arg-type]
                provider="openrouter",
                model_id=model,
                upstream_provider=upstream,
                credential_reference=f"secretref://staging/providers/openrouter/{role}/gen-1",
                prompt_sha256=_PROMPTS[role].sha256,
                policy_sha256=hashlib.sha256(f"{role}:policy:v1".encode()).hexdigest(),
                prices=TokenPrices(
                    input_usd_per_million_tokens=Decimal("0.000001"),
                    output_usd_per_million_tokens=Decimal("0.000001"),
                    reasoning_usd_per_million_tokens=Decimal("0.000001"),
                ),
                limits=HostedLimits(
                    # Platform ceilings are closed: 56 per role, 136 global, $10 measured,
                    # 0.5 rps, 1 retry, 1 concurrent. The fixture stays inside all of them.
                    max_calls=56,
                    max_input_tokens=4_000_000,
                    max_output_tokens=1_000_000,
                    max_reasoning_tokens=1_000_000,
                    max_usd=Decimal("1"),
                    max_retries=judge_retries if role == "judge" else 0,
                    max_requests_per_second=Decimal("0.5"),
                    max_concurrency=1,
                ),
            )
        )
    return HostedConfigurationSet(
        roles=tuple(roles),
        global_limits=HostedLimits(
            max_calls=136,
            max_input_tokens=16_000_000,
            max_output_tokens=4_000_000,
            max_reasoning_tokens=4_000_000,
            max_usd=Decimal("4"),
            max_retries=judge_retries,
            max_requests_per_second=Decimal("0.5"),
            max_concurrency=1,
        ),
    )


def _clean(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "TRUNCATE TABLE provider_call_events, provider_call_invocations, "
                "agent_executions, agent_configuration_versions, hosted_configuration_sets, "
                "audit_events, command_idempotency, verdict, attempt_result, "
                "finding_evidence_links, campaign_attempts, campaign_run_summaries, "
                "campaign_run_events, campaign_runs, campaign_authorization_decisions, "
                "campaign_authorization_requests, surface_state_events, "
                "attack_surface_definitions, surface_identities, target_lifecycle_events, "
                "target_definitions, target_identities, jobs RESTART IDENTITY CASCADE"
            )
        )


#: Enums the roles validate in code rather than in their JSON Schema, so a schema-derived
#: response cannot discover them. Values are taken from the runtime's own tuples.
_MISSING = object()

_CODE_VALIDATED: dict[str, object] = {
    "priority_reason": "coverage_gap",
    "mutation_policy": "coverage_guided",
    "attack_class": "invariant",
    "state": "NO_EXPLOIT_OBSERVED",
    # The Evaluator refuses an error_code on a non-ERROR verdict.
    "error_code": None,
    # Only regressions the snapshot actually offers may be triggered, and a fresh run offers
    # none. An invented identifier is refused as "unauthorized regression trigger".
    "regression_triggers": [],
}


def _conforming(schema: dict) -> object:
    """Synthesize the smallest value satisfying ``schema``.

    Deriving the answer from the request's own schema keeps the fake honest: it cannot drift
    from what the runtime actually asked for, and a schema change shows up as a test failure
    rather than as a silently wrong stub.
    """

    if "enum" in schema:
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]
    kind = schema.get("type")
    if kind == "object":
        out: dict[str, object] = {}
        properties = schema.get("properties", {})
        for name in schema.get("required", list(properties)):
            child = properties.get(name, {"type": "string"})
            preferred = _CODE_VALIDATED.get(name, _MISSING)
            # Prefer the known-safe value even when the schema enumerates the field: the first
            # enum member is often structurally valid but semantically refused (for instance
            # "regression_reappearance" requires an active regression trigger to exist).
            if preferred is not _MISSING and ("enum" not in child or preferred in child["enum"]):
                out[name] = preferred
            else:
                out[name] = _conforming(child)
        return out
    if kind == "array":
        item = schema.get("items", {"type": "string"})
        return [_conforming(item) for _ in range(max(1, int(schema.get("minItems", 1))))]
    if kind == "integer":
        return 1
    if kind == "number":
        return 1.0
    if kind == "boolean":
        return False
    return "synthetic"


class _ScriptedProvider:
    """A provider socket that answers each role, and can make the Judge malform on cue.

    ``judge_invalid_for_ordinals`` names the *case ordinals* whose Judge responses should fail
    schema validation. Every physical Judge call for those ordinals returns a body that is valid
    JSON but does not match the Judge's schema, which is exactly the production failure.
    """

    def __init__(self, *, judge_invalid_for_ordinals: set[int]) -> None:
        self._invalid_ordinals = judge_invalid_for_ordinals
        self.requests: list[str] = []
        self._judge_calls = 0
        self._case_ordinal = 0

    def note_case(self, ordinal: int) -> None:
        self._case_ordinal = ordinal

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        model = body.get("model", "")
        role = next((r for r, (m, _u, _s) in _MODELS.items() if m == model), "unknown")
        self.requests.append(role)
        if role == "judge":
            self._judge_calls += 1
        schema = body["response_format"]["json_schema"]["schema"]
        if role == "judge" and self._case_ordinal in self._invalid_ordinals:
            # Valid JSON, wrong shape — the exact production failure mode.
            content = json.dumps({"totally": "unexpected"})
        else:
            content = json.dumps(_conforming(schema))
        served = _MODELS[role][2] if role in _MODELS else "Unknown"
        return httpx.Response(
            200,
            json={
                "id": f"gen-{role}-{len(self.requests)}",
                "model": model,
                "choices": [{"message": {"content": content}}],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "completion_tokens_details": {"reasoning_tokens": 1},
                    "cost": 0.000001,
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


def test_hosted_campaign_harness_smoke(hosted_campaign, monkeypatch, tmp_path) -> None:
    """Prove the harness can drive one hosted campaign at all before asserting on its details."""

    store, run, corpus, _configuration_used, _physical = hosted_campaign
    provider = _ScriptedProvider(judge_invalid_for_ordinals=set())
    _install_scripted_provider(monkeypatch, provider)
    # The hosted selection path is only defined for exact-manifest workloads; treat the MVP
    # corpus as one for this test so the nine-case fixture can exercise it.
    monkeypatch.setattr(
        runner_module,
        "_EXACT_MANIFEST_WORKLOAD_IDS",
        frozenset({*runner_module._EXACT_MANIFEST_WORKLOAD_IDS, corpus.corpus_id}),
    )

    runner = _runner(store, corpus, tmp_path, _configuration_used)
    worked = runner.run_once(worker_id="fault-isolation-test")

    assert worked is True
    assert provider.requests, "no provider call was made at all"


def _rows(engine: Engine, sql: str, **params):
    with engine.connect() as connection:
        return connection.execute(text(sql), params).mappings().all()


def test_one_unadjudicable_case_does_not_end_the_campaign(
    hosted_campaign, monkeypatch, tmp_path
) -> None:
    """The regression that ended run 50da57b0, reproduced and now survived.

    Case ordinal 1 (the second case) has its Judge return schema-invalid output on BOTH its
    authorized physical attempts. Every other case adjudicates normally.
    """

    store, run, corpus, configuration, physical = hosted_campaign
    engine = store._engine
    provider = _ScriptedProvider(judge_invalid_for_ordinals={1})
    _install_scripted_provider(monkeypatch, provider)
    monkeypatch.setattr(
        runner_module,
        "_EXACT_MANIFEST_WORKLOAD_IDS",
        frozenset({*runner_module._EXACT_MANIFEST_WORKLOAD_IDS, corpus.corpus_id}),
    )

    # The provider needs to know which case is in flight; the attempt ordinal is authoritative.
    real_ensure = runner_module.DurableCampaignRunner._ensure_attempt_for_case

    def tracking_ensure(self, *, run_id, ordinal, case):
        provider.note_case(ordinal)
        return real_ensure(self, run_id=run_id, ordinal=ordinal, case=case)

    monkeypatch.setattr(
        runner_module.DurableCampaignRunner, "_ensure_attempt_for_case", tracking_ensure
    )

    runner = _runner(store, corpus, tmp_path, configuration)
    assert runner.run_once(worker_id="fault-isolation-test") is True

    # --- the campaign reached the end rather than dead-lettering on case 2 -------------
    states = [
        row["state"]
        for row in _rows(
            engine,
            "SELECT state FROM campaign_run_events WHERE run_id = :r ORDER BY id",
            r=run.run_id,
        )
    ]
    assert "failed" not in states and "aborted" not in states, states
    assert states[-1] == "complete"

    attempts = _rows(
        engine,
        "SELECT attempt_id, ordinal FROM campaign_attempts WHERE run_id = :r ORDER BY ordinal",
        r=run.run_id,
    )
    assert len(attempts) == len(corpus.cases), "every authored case was attempted"

    # --- case 2 carries a durable ERROR verdict, the others are adjudicated -------------
    verdicts = {
        row["attempt_id"]: row
        for row in _rows(
            engine,
            "SELECT attempt_id, state, confidence, reason_codes, error_code "
            "FROM verdict WHERE campaign_run_id = :r",
            r=run.run_id,
        )
    }
    assert len(verdicts) == len(corpus.cases), "no case was left un-adjudicated"

    failed_attempt = attempts[1]["attempt_id"]
    failed = verdicts[failed_attempt]
    assert failed["state"] == "ERROR"
    assert failed["confidence"] == 0.0
    assert failed["reason_codes"] == ["judge_invalid_structured_output"]
    assert failed["error_code"] == "invalid_structured_output"

    for index, attempt in enumerate(attempts):
        if index == 1:
            continue
        assert verdicts[attempt["attempt_id"]]["state"] != "ERROR"

    # --- case 3 really did execute after the failure -----------------------------------
    assert attempts[2]["ordinal"] == 2
    assert verdicts[attempts[2]["attempt_id"]]["state"] != "ERROR"

    # --- no finding and no Documentation execution for the errored case ----------------
    findings = _rows(
        engine,
        "SELECT attempt_id FROM finding_evidence_links WHERE campaign_run_id = :r",
        r=run.run_id,
    )
    assert failed_attempt not in {row["attempt_id"] for row in findings}
    documentation = _rows(
        engine,
        "SELECT attempt_id FROM agent_executions "
        "WHERE campaign_run_id = :r AND agent_role = 'documentation'",
        r=run.run_id,
    )
    assert failed_attempt not in {row["attempt_id"] for row in documentation}

    # --- the retry was a model round-trip, never a target turn -------------------------
    target_requests = _rows(
        engine,
        "SELECT count(*) AS n FROM attempt_result WHERE campaign_run_id = :r",
        r=run.run_id,
    )[0]["n"]
    assert target_requests == len(corpus.cases), "one durable result per authored case"

    # --- provider sequences and totals reconcile ---------------------------------------
    judge_sequences = [
        row["physical_sequence"]
        for row in _rows(
            engine,
            "SELECT pci.physical_sequence FROM provider_call_invocations pci "
            "JOIN agent_executions ae ON ae.execution_id = pci.logical_execution_id "
            "WHERE pci.campaign_run_id = :r AND ae.agent_role = 'judge' "
            "AND ae.attempt_id = :a ORDER BY pci.physical_sequence",
            r=run.run_id,
            a=failed_attempt,
        )
    ]
    assert judge_sequences == [1, 2], "the failed Judge used exactly its authorized retry"

    invalid_events = _rows(
        engine,
        "SELECT pce.status FROM provider_call_events pce "
        "JOIN agent_executions ae ON ae.execution_id = pce.logical_execution_id "
        "WHERE pce.campaign_run_id = :r AND ae.attempt_id = :a AND ae.agent_role = 'judge'",
        r=run.run_id,
        a=failed_attempt,
    )
    assert [row["status"] for row in invalid_events] == ["invalid_output", "invalid_output"]

    # Every provider call the transport made is durably recorded — none were lost to the retry.
    recorded = _rows(
        engine,
        "SELECT count(*) AS n FROM provider_call_events WHERE campaign_run_id = :r",
        r=run.run_id,
    )[0]["n"]
    assert recorded == len(provider.requests)

    # --- the summary reports the operational error separately --------------------------
    summary = _rows(
        engine,
        "SELECT attempt_count, decisive_verdict_count, indeterminate_verdict_count, "
        "operational_error_count FROM campaign_run_summaries WHERE run_id = :r",
        r=run.run_id,
    )[0]
    assert summary["operational_error_count"] == 1
    assert summary["attempt_count"] == len(corpus.cases)
    total = (
        summary["decisive_verdict_count"]
        + summary["indeterminate_verdict_count"]
        + summary["operational_error_count"]
    )
    assert total == len(corpus.cases), "the three counts partition every adjudicated case"


@pytest.fixture
def hosted_campaign(migrated_db: Engine):
    """Authorize one synthetic hosted campaign over the nine-case MVP corpus."""

    _clean(migrated_db)
    store = ControlPlaneStore(migrated_db, environment="staging")
    launcher = _principal("user_Launcher", TARGETS_MANAGE, CONFIG_MANAGE, CAMPAIGN_LAUNCH)
    approver = _principal("user_Approver", CAMPAIGN_AUTHORIZE)
    corpus = load_mvp_corpus()
    catalog = TrustedTargetCatalog.from_environment("staging")
    catalog.synchronize(store, organization_id=_ORG)

    configuration = _configuration(judge_retries=1)
    store.stage_hosted_configuration_set(
        principal=launcher,
        configuration=configuration,
        release_sha256="e" * 64,
        rationale="Fault-isolation integration fixture.",
        idempotency_key="fault-isolation-config",
    )
    binding = HostedRunBinding(
        configuration_set_sha256=configuration.configuration_sha256,
        generation_policy_sha256=_POLICY_SHA,
        session_generation="generation-20260727",
        provider_model_call_limit=configuration.global_limits.max_calls,
        provider_model_spend_limit_usd=format(configuration.global_limits.max_usd, "f"),
        provider_max_retries=configuration.global_limits.max_retries,
        provider_max_concurrency=configuration.global_limits.max_concurrency,
        # Must cover the slowest role bound; Red Team is 180s.
        provider_timeout_seconds=180.0,
    )
    physical = sum(len(verified_case_payload(case)["input_sequence"]) for case in corpus.cases)
    scope = store.build_scope(
        principal=launcher,
        target_id="synthetic-copilot",
        target_version="1.1.0",
        surface_id="synthetic-chat",
        surface_version="1.1.0",
        corpus_id=corpus.corpus_id,
        corpus_hash=corpus.content_hash,
        # Must sit inside the synthetic target's own published caps
        # (budget 1.0 / attempts 14 / 100 rps / 300s / logical 14 / physical 51 / retries 2).
        caps=SafetyCaps(
            budget_usd=1.0,
            max_attempts_per_run=len(corpus.cases),
            target_requests_per_second=100.0,
            run_timeout_seconds=300.0,
            # Exact-manifest workloads require caps that match the corpus exactly.
            logical_case_limit=len(corpus.cases),
            physical_request_limit=physical,
            target_retries_per_turn=0,
        ),
        run_nonce="fault-isolation-nonce",
        execution_profile=ExecutionProfile.SYNTHETIC,
        hosted_run=binding,
    )
    request = store.request_campaign_authorization(
        principal=launcher,
        scope=scope,
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30),
        idempotency_key="fault-isolation-request",
    )
    store.decide_campaign_authorization(
        principal=approver,
        request_id=request.request_id,
        decision="approved",
        idempotency_key="fault-isolation-approve",
    )
    run = store.launch_campaign(
        principal=launcher,
        request_id=request.request_id,
        idempotency_key="fault-isolation-launch",
    )
    return store, run, corpus, configuration, physical


class _AdvancingClock:
    """A monotonic clock the test drives forward, so 0.5 rps pacing costs no wall time."""

    def __init__(self) -> None:
        self._now = 0.0

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += max(0.0, float(seconds))


def _credentials(configuration: HostedConfigurationSet, catalog: TrustedTargetCatalog):
    """Bind every hosted role reference plus the synthetic target's own credential."""

    bindings: dict[str, str] = {}
    environment: dict[str, str] = {}
    references = [role.credential_reference for role in configuration.roles]
    references += [
        entry.target.credential_ref
        for entry in catalog.entries
        if entry.target.credential_ref is not None
    ]
    for index, reference in enumerate(dict.fromkeys(references)):
        variable = f"AGENTFORGE_TEST_CRED_{index}"
        bindings[reference] = variable
        environment[variable] = f"test-secret-{index}"
    return SealedEnvironmentCredentialResolver(bindings, environment=environment)


def _runner(store: ControlPlaneStore, corpus, manifest_root, configuration):
    clock = _AdvancingClock()
    catalog = TrustedTargetCatalog.from_environment("staging")
    # OutboundHttpTelemetry.begin_agent returns `langfuse_state is not None`, so with Langfuse
    # unconfigured the lifecycle's observability gate refuses every hosted call before it is
    # made. Only the remote Langfuse client is stood in for; the store, lifecycle and DB stay
    # real. (Recipe proven in tests/test_provider_evidence_preservation.py.)
    telemetry = OutboundHttpTelemetry(store._engine, environment="staging")
    telemetry.langfuse = _LangfuseProjection()
    return runner_module.DurableCampaignRunner(
        engine=store._engine,
        environment="staging",
        corpus=corpus,
        catalog=catalog,
        manifest_root=manifest_root,
        clock=clock,
        sleeper=clock.advance,
        credentials=_credentials(configuration, catalog),
        telemetry=telemetry,
    )


def _install_scripted_provider(monkeypatch, provider: _ScriptedProvider) -> None:
    """Keep the real transport; replace only its socket."""

    real = OpenRouterTransport

    def factory(**kwargs):
        kwargs.setdefault("client", httpx.Client(transport=httpx.MockTransport(provider)))
        return real(**kwargs)

    monkeypatch.setattr(runner_module, "OpenRouterTransport", factory)
