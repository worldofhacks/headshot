"""Stage 4 of the governed generative loop — binding an authorized generated corpus to dispatch.

Stages 1–3 established that a generated case was curated, human-approved, given a corpus identity
of its own, and covered by a fresh exact-scope grant. This module is the last gate before the
target: it converts that state into the exact arguments the governed four-role composition takes,
and refuses to produce them for anything that did not pass every earlier stage.

**Built against the seam, not against an import.** The governed composition root
(``agentforge.governed_acceptance.run_governed_acceptance``) arrives with the 0022 work in PR #50,
which is not merged at this base. So this module depends on the *shape* of that entrypoint —
:class:`GovernedAcceptanceRunner`, a structural protocol — and resolves the real callable at
runtime via :func:`resolve_governed_runner`. Three consequences, all deliberate:

* nothing here imports a module that does not exist yet, so it lands and tests green today;
* the moment #50 merges, :func:`resolve_governed_runner` starts returning the real function and the
  wiring is complete with no edit to this module; and
* if that entrypoint's signature has drifted from what this was built against,
  :class:`GovernedRunnerIncompatible` says so immediately and by name, instead of surfacing as a
  ``TypeError`` at the moment of a live dispatch.

**Why a generated case may be passed as `reviewed_case`.** The 0022 entrypoint names its parameter
``reviewed_case`` because its own scope was the authored seed corpus, and pins
``acceptance_context_sha256`` to that case's content hash so the authority covers the exact bytes
dispatched. A stage-2-approved generated case satisfies that contract in the way that matters: a
human reviewed those exact bytes and a record says so. What this module must add — and does — is
proving that approval and its authorization still hold *at the moment of binding*, because the
0022 seam takes ``reviewed_case`` on trust from its caller. That trust is what lives here.

**One grant, many cases.** The stage-3 scope authorizes the generated *corpus*, and every case
dispatched under it shares that ``scope_hash`` — the same shape the platform already uses for the
nine-case authored corpus under a single grant. The 0022 runner happens to bind one case per
governed run (``target_call_limit = 1``); that is its harness shape, not a second authorization.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from agentforge.agents.red_team.seed_replay import seed_to_attempt
from agentforge.campaign.generated_profile import GeneratedDispatchPlan

# The exact keyword parameters `run_governed_acceptance` accepts, pinned from PR #50
# (`agent/governed-0022-four-role`, `src/agentforge/governed_acceptance.py`). Recorded here so a
# drift in that entrypoint is a named, testable failure rather than a call-time TypeError.
GOVERNED_RUNNER_PARAMETERS: frozenset[str] = frozenset(
    {
        "engine",
        "environment",
        "organization_id",
        "authorization_request_id",
        "scope_hash",
        "launcher_user_id",
        "launcher_session_id",
        "configuration",
        "generation_policy_sha256",
        "reviewed_case",
        "reviewed_case_content_hash",
        "reviewed_category",
        "oracle_canary_markers",
        "dispatch",
        "transport",
        "telemetry",
        "judge_calibration",
        "expires_at",
    }
)

# The four keys the 0022 governed dispatch projects a Red Team proposal onto before comparing it
# with the authorized attempt. Pinned so the compatibility test can assert, without importing it,
# that a generated case survives that comparison unchanged.
SEED_REPLAY_PROJECTION_KEYS: tuple[str, ...] = (
    "schema_version",
    "case_ref",
    "input_sequence",
    "category",
)

_GOVERNED_RUNNER_MODULE = "agentforge.governed_acceptance"
_GOVERNED_RUNNER_ATTRIBUTE = "run_governed_acceptance"


class GeneratedDispatchError(ValueError):
    """An approved generated case cannot be bound to a governed dispatch."""


class GovernedRunnerUnavailable(RuntimeError):
    """The governed four-role composition root is not present in this tree.

    Raised only after every gate this module owns has passed, so the missing piece is unambiguous:
    the governance is complete and the 0022 dispatch path is what is absent.
    """

    code = "governed-runner-unavailable"


class GovernedRunnerIncompatible(RuntimeError):
    """The governed composition root is present but is not the interface this was built against."""

    code = "governed-runner-incompatible"


@runtime_checkable
class GovernedAcceptanceRunner(Protocol):
    """The structural shape of ``run_governed_acceptance`` (PR #50).

    Every parameter is keyword-only in the real entrypoint, so this module never depends on
    positional order.
    """

    def __call__(self, **kwargs: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class AuthorizedGeneratedCase:
    """One approved, authorized generated case, ready for exactly one bounded dispatch.

    Every field is derived and re-verified at construction time by
    :func:`authorize_generated_cases`; nothing here is caller-supplied narrative.
    """

    instance_id: str
    case_id: str
    category: str
    payload: dict[str, Any]
    case_sha256: str
    corpus_id: str
    corpus_hash: str
    scope_hash: str
    approved_bundle_sha256: str
    reviewer_id: str
    launcher_user_id: str

    def seed_replay_projection(self) -> dict[str, Any]:
        """The bytes the governed dispatch will compare against, exactly as 0022 computes them."""

        return seed_to_attempt(self.payload)

    def runner_kwargs(
        self,
        *,
        engine: Any,
        environment: str,
        organization_id: str,
        authorization_request_id: str,
        launcher_session_id: str,
        configuration: Any,
        generation_policy_sha256: str,
        oracle_canary_markers: Sequence[str],
        dispatch: Any,
        transport: Any,
        telemetry: Any,
        judge_calibration: Mapping[str, Any],
        expires_at: Any = None,
    ) -> dict[str, Any]:
        """Assemble the complete governed-runner call for this one case.

        The three fields that carry the governance — ``reviewed_case``,
        ``reviewed_case_content_hash`` and ``scope_hash`` — come from this authorized case and
        cannot be overridden by the caller. Everything else is infrastructure the caller owns.
        """

        return {
            "engine": engine,
            "environment": environment,
            "organization_id": organization_id,
            "authorization_request_id": authorization_request_id,
            "scope_hash": self.scope_hash,
            "launcher_user_id": self.launcher_user_id,
            "launcher_session_id": launcher_session_id,
            "configuration": configuration,
            "generation_policy_sha256": generation_policy_sha256,
            "reviewed_case": dict(self.payload),
            "reviewed_case_content_hash": self.case_sha256,
            "reviewed_category": self.category,
            "oracle_canary_markers": tuple(oracle_canary_markers),
            "dispatch": dispatch,
            "transport": transport,
            "telemetry": telemetry,
            "judge_calibration": judge_calibration,
            "expires_at": expires_at,
        }


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def resolve_governed_runner(runner: Any = None) -> GovernedAcceptanceRunner:
    """Return the governed composition root, or say precisely why it cannot be used.

    With no argument this imports ``run_governed_acceptance`` from the 0022 work. Passing an
    explicit ``runner`` is the injection seam used by tests and by any composition root that has
    already resolved it.

    A resolved callable is signature-checked against :data:`GOVERNED_RUNNER_PARAMETERS`, so a
    drifted entrypoint is refused here rather than at dispatch time. A callable that accepts
    ``**kwargs`` is accepted as-is, since it cannot be shown to be incompatible.
    """

    if runner is None:
        try:
            module = __import__(_GOVERNED_RUNNER_MODULE, fromlist=[_GOVERNED_RUNNER_ATTRIBUTE])
            runner = getattr(module, _GOVERNED_RUNNER_ATTRIBUTE)
        except (ImportError, AttributeError) as exc:
            raise GovernedRunnerUnavailable(
                "the governed four-role composition root "
                f"({_GOVERNED_RUNNER_MODULE}.{_GOVERNED_RUNNER_ATTRIBUTE}) is not present in this "
                "tree — every generative governance gate passed, and dispatch stacks on 0022 "
                "(PR #50)"
            ) from exc

    if not callable(runner):
        raise GovernedRunnerIncompatible("the resolved governed runner is not callable")

    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError):
        # A callable whose signature cannot be introspected (a C builtin, an exotic partial) is
        # accepted: it cannot be shown incompatible, and refusing it would block a valid seam.
        return runner

    if any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in signature.parameters.values()
    ):
        return runner

    accepted = {
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind
        in (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    }
    missing = GOVERNED_RUNNER_PARAMETERS - accepted
    if missing:
        raise GovernedRunnerIncompatible(
            "the governed runner does not accept "
            f"{sorted(missing)} — this module was built against the PR #50 interface and that "
            "entrypoint has drifted; re-pin GOVERNED_RUNNER_PARAMETERS after reviewing the change"
        )
    required_unsatisfied = {
        name
        for name, parameter in signature.parameters.items()
        if parameter.default is inspect.Parameter.empty
        and parameter.kind
        in (inspect.Parameter.KEYWORD_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        and name not in GOVERNED_RUNNER_PARAMETERS
    }
    if required_unsatisfied:
        raise GovernedRunnerIncompatible(
            "the governed runner requires "
            f"{sorted(required_unsatisfied)}, which this binding does not supply — the PR #50 "
            "interface has gained a required parameter"
        )
    return runner


def authorize_generated_cases(
    plan: GeneratedDispatchPlan,
    *,
    launcher_user_id: str,
) -> tuple[AuthorizedGeneratedCase, ...]:
    """Convert a stage-3 plan into per-case dispatch authorizations, re-verifying every gate.

    This is defence in depth on purpose. Stage 3 already established the corpus identity and the
    fresh grant, but this is the last point before content leaves the platform, so the checks that
    matter are re-run against the concrete case rather than inherited from an earlier object:

    1. the case's content hash re-derives from its payload (nothing changed since approval);
    2. the case is one of the profile's approved generated cases, not a base-corpus case;
    3. a review record covers this exact case hash; and
    4. the launcher is not the approver — a launcher may not approve their own operation, and the
       0022 authority enforces the same separation in the database.

    Raises :class:`GeneratedDispatchError` on any failure, and authorizes NOTHING: a partially
    valid plan never yields a partially authorized set.
    """

    if not isinstance(plan, GeneratedDispatchPlan):
        raise GeneratedDispatchError("only a stage-3 GeneratedDispatchPlan may be authorized")
    if not isinstance(launcher_user_id, str) or not launcher_user_id.strip():
        raise GeneratedDispatchError("a launching principal identity is required")

    profile = plan.profile

    # (4) Two-person authority, checked before anything else so the refusal is unambiguous.
    if launcher_user_id == profile.reviewer_id:
        raise GeneratedDispatchError(
            "the launching principal approved this generated content — a launcher may not "
            "approve their own operation (fail closed)"
        )
    # The generator must not be able to launch its own unreviewed-in-spirit content either.
    if launcher_user_id == profile.generator_principal:
        raise GeneratedDispatchError(
            "the launching principal generated this content — generation and launch must be "
            "separate principals (fail closed)"
        )

    approved_hashes = set(profile.generated_case_sha256)
    records_by_hash = {record.case_sha256: record for record in profile.review_records}
    scope_hash = plan.scope.scope_hash()

    if not profile.approved_cases:
        raise GeneratedDispatchError(
            "the generated profile retains no approved case payloads — stage 3 must carry them "
            "so this gate can re-verify the reviewed bytes rather than trust a projection"
        )

    authorized: list[AuthorizedGeneratedCase] = []
    for candidate in profile.approved_cases:
        payload = dict(candidate.payload)

        # (1) The bytes have not changed since a human approved them.
        if _canonical_sha256(payload) != candidate.case_sha256:
            raise GeneratedDispatchError(
                f"generated case {candidate.instance_id} changed after approval — its content "
                "hash does not re-derive (fail closed)"
            )
        # (2) It is an approved generated case, not something else riding the plan.
        if candidate.case_sha256 not in approved_hashes:
            raise GeneratedDispatchError(
                f"case {candidate.instance_id} is not among the profile's approved generated cases"
            )
        # (3) A review record covers this exact content, and names the profile's reviewer.
        record = records_by_hash.get(candidate.case_sha256)
        if record is None:
            raise GeneratedDispatchError(
                f"case {candidate.instance_id} carries no review record for its content"
            )
        if record.reviewer_id != profile.reviewer_id:
            raise GeneratedDispatchError(
                f"case {candidate.instance_id} was approved by a principal other than the "
                "profile's reviewer (fail closed)"
            )

        authorized.append(
            AuthorizedGeneratedCase(
                instance_id=candidate.instance_id,
                case_id=payload["case_id"],
                category=payload["category"],
                payload=payload,
                case_sha256=candidate.case_sha256,
                corpus_id=profile.corpus_id,
                corpus_hash=profile.content_hash,
                scope_hash=scope_hash,
                approved_bundle_sha256=profile.approved_bundle_sha256,
                reviewer_id=record.reviewer_id,
                launcher_user_id=launcher_user_id,
            )
        )

    if not authorized:
        raise GeneratedDispatchError("the plan authorizes no generated case to dispatch")
    return tuple(authorized)


def dispatch_generated_case(
    case: AuthorizedGeneratedCase,
    *,
    runner: Any = None,
    engine: Any,
    environment: str,
    organization_id: str,
    authorization_request_id: str,
    launcher_session_id: str,
    configuration: Any,
    generation_policy_sha256: str,
    oracle_canary_markers: Sequence[str],
    dispatch: Any,
    transport: Any,
    telemetry: Any,
    judge_calibration: Mapping[str, Any],
    expires_at: Any = None,
) -> Any:
    """Dispatch exactly one authorized generated case through the governed four-role composition.

    Resolves the 0022 runner (or uses an injected one), then calls it with this case's governance
    fields bound. Raises :class:`GovernedRunnerUnavailable` when the 0022 path is absent — after
    the governance checks, never instead of them.
    """

    if not isinstance(case, AuthorizedGeneratedCase):
        raise GeneratedDispatchError("only an authorized generated case may be dispatched")
    resolved = resolve_governed_runner(runner)
    return resolved(
        **case.runner_kwargs(
            engine=engine,
            environment=environment,
            organization_id=organization_id,
            authorization_request_id=authorization_request_id,
            launcher_session_id=launcher_session_id,
            configuration=configuration,
            generation_policy_sha256=generation_policy_sha256,
            oracle_canary_markers=oracle_canary_markers,
            dispatch=dispatch,
            transport=transport,
            telemetry=telemetry,
            judge_calibration=judge_calibration,
            expires_at=expires_at,
        )
    )


__all__ = [
    "GOVERNED_RUNNER_PARAMETERS",
    "SEED_REPLAY_PROJECTION_KEYS",
    "AuthorizedGeneratedCase",
    "GeneratedDispatchError",
    "GovernedAcceptanceRunner",
    "GovernedRunnerIncompatible",
    "GovernedRunnerUnavailable",
    "authorize_generated_cases",
    "dispatch_generated_case",
    "resolve_governed_runner",
]
