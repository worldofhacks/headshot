"""Private durable-queue Runner with network-free preflight and exact-scope dispatch."""

from __future__ import annotations

import argparse
import contextlib
import datetime
import ipaddress
import os
import signal
import socket
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Engine, text

from agentforge.campaign.authorization import RunAuthorization
from agentforge.campaign.binding import TargetBinding
from agentforge.campaign.coordinator import CampaignAbort, RunConfig, SecureCampaignCoordinator
from agentforge.campaign.corpus import MVP_CASE_COUNT, AuthoredCorpus, load_mvp_corpus
from agentforge.campaign.manifest import ManifestStore
from agentforge.campaign.runtime import SystemClock, accounting_from_environment, production_engine
from agentforge.control_plane.store import ControlPlaneStore
from agentforge.policy.gateway import RunPolicy
from agentforge.policy.scoped_credentials import SealedEnvironmentCredentialResolver
from agentforge.readiness import expected_alembic_head
from agentforge.storage.queue import JobRecord, LogicalQueue, PostgresJobQueue
from agentforge.target.cassette_adapter import SyntheticCassetteAdapter
from agentforge.target.catalog import SYNTHETIC_TARGET_ID, CatalogEntry, TrustedTargetCatalog
from agentforge.target.openemr_adapter import OpenEmrAdapter
from agentforge.target.spec import (
    AttackSurfaceDefinition,
    AuthMode,
    AuthorizationScope,
    ExecutionProfile,
)

_PAYLOAD_SCHEMA = "campaign.execute"
_PAYLOAD_VERSION = 1
_DEFAULT_LEASE = datetime.timedelta(minutes=10)
_DEFAULT_POLL_SECONDS = 1.0


class DispatchUnavailable(RuntimeError):
    """Persisted work cannot pass every current dispatch gate."""


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Network-free gate result. Blocker codes are bounded and contain no secret values."""

    blockers: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.blockers

    def require_ready(self) -> None:
        if self.blockers:
            raise DispatchUnavailable("preflight_blocked:" + ",".join(self.blockers))


@dataclass(frozen=True, slots=True)
class PreparedRun:
    authorized: Any
    entry: CatalogEntry
    surface: AttackSurfaceDefinition
    corpus: AuthoredCorpus


def _persisted_identity(job: Any) -> tuple[str, str]:
    run_id = getattr(job, "campaign_run_id", None)
    attempt_id = getattr(job, "attempt_id", None)
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(attempt_id, str)
        or not attempt_id
    ):
        raise DispatchUnavailable("job_identity_invalid")
    return run_id, attempt_id


def _scope_from_authorized(value: Any) -> Any:
    if isinstance(value, Mapping):
        scope = value.get("scope") or value.get("authorization_scope")
    else:
        scope = getattr(value, "scope", None) or getattr(value, "authorization_scope", None)
    if scope is None:
        raise DispatchUnavailable("canonical_scope_unavailable")
    return scope


def process_agent_work(
    job: Any,
    *,
    control_plane: Any,
    adapters: Any,
    executor: Callable[[Any, Any, Any], Any] | None = None,
) -> Any:
    """Compatibility seam proving that adapter construction follows persisted authority."""

    run_id, attempt_id = _persisted_identity(job)
    resolver = getattr(control_plane, "resolve_dispatch", None)
    if callable(resolver):
        authorized = resolver(run_id, attempt_id)
    else:
        loader = getattr(control_plane, "load_run_for_execution", None)
        if not callable(loader):
            raise DispatchUnavailable("control_plane_dispatch_resolver_missing")
        authorized = loader(run_id)
    scope = _scope_from_authorized(authorized)
    if executor is None:
        raise DispatchUnavailable("trusted_execution_composition_missing")
    commit = getattr(control_plane, "record_result_and_complete", None)
    if not callable(commit):
        raise DispatchUnavailable("atomic_result_commit_missing")
    adapter = adapters.resolve(scope)
    result = executor(adapter, authorized, job)
    commit(job, result)
    return result


def _engine(database_url: str) -> Engine:
    return production_engine(database_url)


def _schema_is_current(engine: Engine) -> bool:
    try:
        with engine.connect() as connection:
            current = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
        return current == expected_alembic_head()
    except Exception:
        return False


def _literal_destination_allowed(scope: AuthorizationScope, entry: CatalogEntry) -> bool:
    hostname = (
        scope.exact_host.rsplit(":", 1)[0] if scope.exact_host.count(":") == 1 else scope.exact_host
    )
    lowered = hostname.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return entry.transport_policy.allow_private_destination
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return True
    unsafe = not address.is_global
    return not unsafe or entry.transport_policy.allow_private_destination


def _validate_resolved_destination(base_url: str, *, allow_private: bool) -> None:
    """Resolve immediately before dispatch and refuse every non-global address by default."""

    parts = urlsplit(base_url)
    if not parts.hostname:
        raise DispatchUnavailable("target_destination_invalid")
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(
            parts.hostname,
            parts.port or 443,
            type=socket.SOCK_STREAM,
        )
    }
    if not addresses:
        raise DispatchUnavailable("target_destination_unresolved")
    if not allow_private and any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise DispatchUnavailable("target_destination_private")


def _exact_job_payload(job: JobRecord, authorized: Any) -> bool:
    expected = {
        "authorization_request_id": authorized.run.authorization_request_id,
        "campaign_run_id": authorized.run.run_id,
        "scope_hash": authorized.run.scope_hash,
    }
    return (
        job.payload_schema == _PAYLOAD_SCHEMA
        and job.payload_version == _PAYLOAD_VERSION
        and job.attempt_id == "campaign"
        and job.payload == expected
    )


def _scope_payload_profile(*, relative_path: str, method: str, auth_mode: AuthMode) -> str:
    """Derive request shape only from fields included in the authorization scope hash."""

    if relative_path != "chat":
        return "openemr_turns"
    if method != "POST" or auth_mode is not AuthMode.SESSION:
        raise DispatchUnavailable("copilot_chat_scope_invalid")
    return "copilot_chat"


class DurableCampaignRunner:
    """One concurrency-one worker over the existing PostgreSQL queue."""

    def __init__(
        self,
        *,
        engine: Engine,
        environment: str,
        corpus: AuthoredCorpus | None = None,
        catalog: TrustedTargetCatalog | None = None,
        credentials: SealedEnvironmentCredentialResolver | None = None,
        clock: Any | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        manifest_root: str | os.PathLike[str] | None = None,
    ) -> None:
        self.engine = engine
        self.environment = environment
        self.corpus = corpus or load_mvp_corpus()
        self.catalog = catalog or TrustedTargetCatalog.from_environment(environment)
        self.credentials = credentials or SealedEnvironmentCredentialResolver.from_environment()
        self.clock = clock or SystemClock()
        self.sleeper = sleeper
        self.store = ControlPlaneStore(engine, environment=environment)
        self.queue = PostgresJobQueue(
            engine,
            supported_payload_versions={
                LogicalQueue.AGENT_WORK: {_PAYLOAD_SCHEMA: (_PAYLOAD_VERSION,)}
            },
        )
        selected_root = manifest_root or os.environ.get(
            "AGENTFORGE_MANIFEST_DIR", "/tmp/agentforge-manifests"
        )
        self.manifests = ManifestStore(Path(selected_root))

    def preflight(self, job: JobRecord) -> tuple[PreflightReport, PreparedRun | None]:
        """Report every blocker without constructing an adapter or opening a target socket."""

        blockers: list[str] = []
        if not _schema_is_current(self.engine):
            blockers.append("migration_head_mismatch")
        try:
            self.store.assert_job_lease(job)
        except Exception:
            blockers.append("lease_not_owned")

        authorized: Any | None = None
        try:
            authorized = self.store.load_run_for_execution(job.campaign_run_id)
        except Exception:
            blockers.append("authorization_not_dispatchable")
        if authorized is None:
            return PreflightReport(tuple(dict.fromkeys(blockers))), None

        scope = authorized.scope
        if not _exact_job_payload(job, authorized):
            blockers.append("queue_payload_mismatch")
        if authorized.approval.approver_user_id == authorized.run.launcher_user_id:
            blockers.append("two_person_control_failed")
        if scope.scope_hash() != authorized.run.scope_hash:
            blockers.append("operation_hash_mismatch")
        if (
            scope.corpus_id != self.corpus.corpus_id
            or scope.corpus_hash != self.corpus.content_hash
        ):
            blockers.append("corpus_hash_mismatch")
        if len(self.corpus.cases) != MVP_CASE_COUNT or len(self.corpus.categories) != 3:
            blockers.append("corpus_not_complete")

        entry: CatalogEntry | None = None
        surface: AttackSurfaceDefinition | None = None
        try:
            entry, surface = self.catalog.resolve(
                target_id=scope.target_id,
                surface_id=scope.surface_id,
            )
        except Exception:
            blockers.append("target_catalog_mismatch")
        if entry is not None and surface is not None:
            target = entry.target
            exact = (
                target.version == scope.target_version
                and target.environment is scope.environment
                and target.exact_host == scope.exact_host
                and target.adapter_kind == scope.adapter_kind
                and target.auth_mode is scope.auth_mode
                and target.credential_ref == scope.credential_ref
                and surface.version == scope.surface_version
                and surface.protocol == scope.protocol
                and surface.method == scope.method
                and surface.relative_path == scope.relative_path
                and surface.enabled
            )
            if not exact:
                blockers.append("target_surface_scope_mismatch")
            if not target.synthetic_data_only or not target.synthetic_data_attestation_ref:
                blockers.append("synthetic_data_attestation_missing")
            if not target.canary_refs:
                blockers.append("deterministic_canary_missing")
            if scope.method not in entry.transport_policy.allowed_methods:
                blockers.append("method_not_allowed")
            if not _literal_destination_allowed(scope, entry):
                blockers.append("private_destination_refused")
            try:
                scope_profile = _scope_payload_profile(
                    relative_path=scope.relative_path,
                    method=scope.method,
                    auth_mode=scope.auth_mode,
                )
            except DispatchUnavailable:
                blockers.append("payload_profile_scope_invalid")
            else:
                if entry.transport_policy.payload_profile != scope_profile:
                    blockers.append("payload_profile_scope_mismatch")
            if entry.transport_policy.write_upload_allowed:
                blockers.append("write_upload_policy_not_mvp_safe")
            if scope.execution_profile is ExecutionProfile.SYNTHETIC:
                if self.environment == "production" or scope.target_id != SYNTHETIC_TARGET_ID:
                    blockers.append("synthetic_profile_refused")
            elif scope.target_id == SYNTHETIC_TARGET_ID:
                blockers.append("live_profile_cannot_use_cassette")

        caps = scope.caps
        if caps.max_attempts_per_run < MVP_CASE_COUNT or not caps.is_within(
            entry.target.safety_caps if entry is not None else caps
        ):
            blockers.append("campaign_caps_incompatible")
        if not self.credentials.has(scope.credential_ref):
            blockers.append("credential_reference_unavailable")
        if not all(
            callable(getattr(self.store, name, None))
            for name in ("resolve_dispatch", "append_campaign_state", "complete_campaign_job")
        ):
            blockers.append("abort_or_persistence_control_missing")

        report = PreflightReport(tuple(dict.fromkeys(blockers)))
        prepared = (
            PreparedRun(authorized=authorized, entry=entry, surface=surface, corpus=self.corpus)
            if report.ready and entry is not None and surface is not None
            else None
        )
        return report, prepared

    def _adapter(self, prepared: PreparedRun) -> Any:
        scope = prepared.authorized.scope
        target = prepared.entry.target
        if scope.execution_profile is ExecutionProfile.SYNTHETIC:
            return SyntheticCassetteAdapter.for_cases(
                tuple(case.payload for case in prepared.corpus.cases),
                base_url=target.base_url,
            )
        policy = prepared.entry.transport_policy
        # The Clinical Co-Pilot's reviewed Bruno contract is exactly POST /chat with a
        # patient-pinned SMART session carried as ``session_id`` in the JSON body. The catalog
        # selects the profile, but it must equal the profile derived from fields already bound in
        # the persisted operation hash; an environment change cannot alter shape after approval.
        payload_profile = _scope_payload_profile(
            relative_path=prepared.surface.relative_path,
            method=prepared.surface.method,
            auth_mode=scope.auth_mode,
        )
        if policy.payload_profile != payload_profile:
            raise DispatchUnavailable("payload_profile_scope_mismatch")
        return OpenEmrAdapter(
            base_url=target.base_url,
            timeout_seconds=policy.request_timeout_seconds,
            method=prepared.surface.method,
            relative_path=prepared.surface.relative_path,
            payload_profile=payload_profile,
            redirect_policy=policy.redirect_policy,
            response_size_limit_bytes=policy.response_size_limit_bytes,
            allowed_content_types=policy.allowed_content_types,
            destination_validator=lambda base_url: _validate_resolved_destination(
                base_url,
                allow_private=policy.allow_private_destination,
            ),
        )

    def execute_claimed(self, job: JobRecord) -> None:
        """Execute all nine cases and atomically commit the result before releasing the lease."""

        report, prepared = self.preflight(job)
        report.require_ready()
        if prepared is None:  # defensive: require_ready implies this cannot happen
            raise DispatchUnavailable("preflight_preparation_missing")
        authorized = prepared.authorized
        scope = authorized.scope
        self.store.append_campaign_state(run_id=job.campaign_run_id, state="running")

        attempts = []
        for ordinal, case in enumerate(prepared.corpus.cases):
            payload = case.payload
            attempts.append(
                self.store.ensure_campaign_attempt(
                    run_id=job.campaign_run_id,
                    ordinal=ordinal,
                    case_id=payload["case_id"],
                    case_content_hash=case.content_hash,
                    category=payload["category"],
                    severity=payload["severity"]["rating"],
                    attack_class=payload["test_design"]["classification"],
                    owasp_mappings=payload["owasp"],
                    fixture_provenance=payload["fixture_provenance"],
                )
            )

        binding = TargetBinding(
            target_id=scope.target_id,
            host=scope.exact_host,
            adapter_kind=scope.adapter_kind,
            credential_ref=scope.credential_ref,
            auth_mode=scope.auth_mode.value,
        )
        policy = RunPolicy(**scope.caps.canonical_payload())
        accounting = accounting_from_environment()
        authorization = RunAuthorization(
            operation_hash=authorized.run.scope_hash,
            run_nonce=scope.run_nonce,
            deadline=authorized.expires_at.timestamp(),
        )
        last_dispatch_at: float | None = None

        def revalidate(attempt_id: str) -> None:
            nonlocal last_dispatch_at
            if last_dispatch_at is not None:
                wait = (1.0 / policy.target_requests_per_second) - (
                    self.clock.now() - last_dispatch_at
                )
                if wait > 0:
                    # Epoch-sized floating-point clocks can round an exact interval a fraction
                    # below the policy minimum. A one-microsecond safety margin preserves (and
                    # slightly tightens) the cap instead of allowing a valid throttled run to
                    # abort nondeterministically after the sleep.
                    self.sleeper(wait + 0.000001)
            self.queue.heartbeat(job, extension=_DEFAULT_LEASE)
            self.store.assert_job_lease(job)
            current = self.store.resolve_dispatch(job.campaign_run_id, attempt_id)
            if (
                current.run.scope_hash != authorized.run.scope_hash
                or current.scope.canonical_bytes() != scope.canonical_bytes()
                or current.approval.decision_id != authorized.approval.decision_id
            ):
                raise CampaignAbort("persisted authorization changed", code="authorization_changed")
            last_dispatch_at = self.clock.now()

        provenance = (
            "synthetic_offline"
            if scope.execution_profile is ExecutionProfile.SYNTHETIC
            else "live_target"
        )
        coordinator = SecureCampaignCoordinator(
            config=RunConfig(
                binding=binding,
                authorization=authorization,
                policy=policy,
                run_nonce=scope.run_nonce,
                canary_token="",
                environment=self.environment,
                corpus_id=scope.corpus_id,
                corpus_sha=scope.corpus_hash,
                authorization_operation_hash=authorized.run.scope_hash,
                campaign_run_id=authorized.run.run_id,
                pre_dispatch_gate=revalidate,
                credential_resolver=self.credentials.resolve,
                result_context={
                    "organization_id": authorized.run.organization_id,
                    "target_version": scope.target_version,
                    "surface_id": scope.surface_id,
                    "surface_version": scope.surface_version,
                    "authorization_scope_hash": authorized.run.scope_hash,
                    "execution_profile": scope.execution_profile.value,
                    "evidence_provenance": provenance,
                    "recorder_version": "1",
                    "correlation_id": authorized.run.run_id,
                },
            ),
            adapter=self._adapter(prepared),
            engine=self.engine,
            manifests=self.manifests,
            clock=self.clock,
            accounting=accounting,
        )
        for case, attempt in zip(prepared.corpus.cases, attempts, strict=True):
            outcome = coordinator.run_case(case.payload, attempt_id=attempt.attempt_id)
            if not outcome.integrity_ok:
                raise CampaignAbort("evidence integrity failed", code="evidence_integrity_failed")
            self.store.record_attempt_outcome(
                run_id=authorized.run.run_id,
                attempt_id=attempt.attempt_id,
                verdict=outcome.verdict,
                evidence_content_hash=outcome.result.content_hash,
            )

        self.store.complete_campaign_job(
            job=job,
            request_count=accounting.request_count,
            measured_cost=accounting.spent_usd,
        )

    def run_once(self, *, worker_id: str) -> bool:
        """Claim at most one job. Returns false only when no eligible work exists."""

        job = self.queue.claim(
            LogicalQueue.AGENT_WORK,
            worker_id=worker_id,
            lease_duration=_DEFAULT_LEASE,
        )
        if job is None:
            return False
        try:
            self.execute_claimed(job)
        except Exception as exc:
            code = "campaign_execution_failed"
            if isinstance(exc, DispatchUnavailable):
                code = "preflight_blocked"
            elif isinstance(exc, CampaignAbort):
                code = "campaign_aborted"
            state = "aborted" if code != "campaign_execution_failed" else "failed"
            with contextlib.suppress(Exception):
                self.store.append_campaign_state(
                    run_id=job.campaign_run_id,
                    state=state,
                    reason_code=code,
                )
            with contextlib.suppress(Exception):
                self.queue.fail(job, failure_code=code, retryable=False)
            raise DispatchUnavailable(code) from exc
        return True


def check_runtime(database_url: str | None = None) -> bool:
    """Check DB/schema/config/corpus readiness without binding a socket or contacting a target."""

    url = database_url if database_url is not None else os.environ.get("DATABASE_URL")
    environment = os.environ.get("AGENTFORGE_ENVIRONMENT")
    if not url or environment not in {"local", "staging", "production"}:
        return False
    try:
        engine = _engine(url)
        return _schema_is_current(engine) and len(load_mvp_corpus().cases) == MVP_CASE_COUNT
    except Exception:
        return False


def _worker_id() -> str:
    configured = os.environ.get("AGENTFORGE_RUNNER_WORKER_ID", "").strip()
    if configured:
        return configured[:128]
    return f"runner-{os.getpid()}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentforge-runner")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        return 0 if check_runtime() else 1
    database_url = os.environ.get("DATABASE_URL")
    environment = os.environ.get("AGENTFORGE_ENVIRONMENT")
    if not database_url or environment not in {"local", "staging", "production"}:
        print("runner unavailable: configuration is incomplete", file=sys.stderr)
        return 1
    try:
        runner = DurableCampaignRunner(engine=_engine(database_url), environment=environment)
    except Exception:
        print("runner unavailable: trusted composition failed", file=sys.stderr)
        return 1
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_args: stop.set())
    while not stop.is_set():
        try:
            worked = runner.run_once(worker_id=_worker_id())
        except DispatchUnavailable:
            worked = True
        if args.once:
            return 0
        if not worked:
            stop.wait(_DEFAULT_POLL_SECONDS)
    return 0


if __name__ == "__main__":  # pragma: no cover - subprocess/container smoke owns this path
    raise SystemExit(main())


__all__ = [
    "DispatchUnavailable",
    "DurableCampaignRunner",
    "PreflightReport",
    "check_runtime",
    "main",
    "process_agent_work",
]
