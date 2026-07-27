import type { ApiClient } from "../api/client";
import { RESOURCE_PATHS } from "../api/paths";
import {
  decodeCoverage,
  decodeResilience,
} from "../api/read-models";
import {
  count,
  DistributionBars,
  MetricStrip,
  Panel,
  percent,
  ScreenHeading,
  TagMatrix,
  Timeline,
} from "../components/Analytics";
import {
  RecordTable,
  ResourceView,
  StateNotice,
} from "../components/ResourceView";
import {
  LIVE_RESOURCE_POLL_INTERVAL_MS,
  useResource,
} from "../hooks/useResource";
import type {
  CoverageReadModel,
  ResilienceReadModel,
} from "../types";

const unique = (values: string[]) => [...new Set(values)].sort();

const toneFor = (
  value: string,
): "success" | "queued" | "failure" | "brand" => {
  const normalized = value.toLowerCase();
  if (
    ["blocked", "complete", "covered", "no_exploit_observed", "pass", "passed", "safe"]
      .some((candidate) => normalized.includes(candidate))
  ) {
    return "success";
  }
  if (
    ["critical", "degraded", "error", "exploit", "fail", "regressed"]
      .some((candidate) => normalized.includes(candidate))
  ) {
    return "failure";
  }
  if (
    ["indeterminate", "partial", "pending", "queued", "review"]
      .some((candidate) => normalized.includes(candidate))
  ) {
    return "queued";
  }
  return "brand";
};

const regressionTone = (
  value: string,
): "success" | "queued" | "failure" => {
  const tone = toneFor(value);
  return tone === "brand" ? "queued" : tone;
};

function CoverageEvidence({ data }: { data: CoverageReadModel[] }) {
  const verifiedAttempts = data.reduce(
    (total, record) => total + record.verified_attempt_count,
    0,
  );
  const cases = data.reduce(
    (total, record) => total + record.total_case_count,
    0,
  );
  const covered = data.filter((record) => record.covered).length;
  const verdicts = new Map<string, number>();
  for (const record of data) {
    for (const [verdict, rawCount] of Object.entries(record.verdict_counts)) {
      if (typeof rawCount === "number") {
        verdicts.set(verdict, (verdicts.get(verdict) ?? 0) + rawCount);
      }
    }
  }

  return (
    <>
      <MetricStrip
        label="Coverage summary"
        values={[
          {
            label: "Verified attempts",
            value: count(verifiedAttempts),
            note: `${count(cases)} authorized cases`,
          },
          {
            label: "Attempts per authorized case",
            value: cases ? `${(verifiedAttempts / cases).toFixed(2)}×` : "—",
            note: "can exceed 1× when cases are retried",
          },
          {
            label: "Covered versions",
            value: `${covered}/${data.length}`,
            note: "server coverage decision",
          },
          {
            label: "Mapped controls",
            value: count(unique(data.flatMap(
              (record) => [...record.owasp_web, ...record.owasp_llm],
            )).length),
            note: "OWASP Web + LLM",
          },
        ]}
      />
      <div className="panel-grid analytical-grid">
        <Panel
          title="Execution by target version"
          meta="verified attempts / authorized cases"
          eyebrow="COVERAGE POSTURE"
        >
          <DistributionBars rows={data.map((record) => ({
            label: record.target_version,
            value: record.verified_attempt_count,
            display: `${record.verified_attempt_count} / ${record.total_case_count}`,
            tone: record.covered ? "success" : "queued",
          }))} />
        </Panel>
        <Panel
          title="Verdict distribution"
          meta="verified attempts"
          eyebrow="COVERAGE POSTURE"
        >
          {verdicts.size > 0 ? (
            <DistributionBars rows={[...verdicts.entries()]
              .sort(([left], [right]) => left.localeCompare(right))
              .map(([label, value]) => ({
                label,
                value,
                tone: toneFor(label),
              }))} />
          ) : (
            <StateNotice
              state="empty"
              detail="No verdict counts are present in the coverage projection."
            />
          )}
        </Panel>
      </div>
      <Panel
        title="Taxonomy coverage"
        meta="deduplicated mappings"
        eyebrow="COVERAGE POSTURE"
      >
        <TagMatrix groups={[
          {
            label: "Classifications",
            values: unique(data.flatMap((record) => record.classifications)),
          },
          {
            label: "OWASP Web Top 10",
            values: unique(data.flatMap((record) => record.owasp_web)),
          },
          {
            label: "OWASP LLM Top 10",
            values: unique(data.flatMap((record) => record.owasp_llm)),
          },
          {
            label: "Evidence provenance",
            values: unique(data.map((record) => record.evidence_provenance)),
          },
        ]} />
      </Panel>
      <Panel title="Coverage ledger" meta="authoritative snapshots">
        <RecordTable
          data={data}
          identityKeys={["target_version"]}
          columns={[
            { key: "target_version", label: "Target version", mono: true },
            { key: "verified_attempt_count", label: "Verified", mono: true },
            { key: "total_case_count", label: "Cases", mono: true },
            { key: "category_count", label: "Categories", mono: true },
            { key: "execution_profile", label: "Profile" },
            { key: "covered", label: "Coverage decision" },
            { key: "as_of", label: "As of", mono: true, timestamp: true },
          ]}
        />
      </Panel>
    </>
  );
}

function RegressionEvidence({ data }: { data: ResilienceReadModel[] }) {
  const passing = data.filter(
    (record) => regressionTone(record.status) === "success",
  ).length;
  const failing = data.filter(
    (record) => regressionTone(record.status) === "failure",
  ).length;
  const latest = [...data].sort(
    (left, right) => Date.parse(right.recorded_at) - Date.parse(left.recorded_at),
  )[0];

  return (
    <>
      <MetricStrip
        label="Regression summary"
        values={[
          {
            label: "Regression checks",
            value: count(data.length),
            note: `${unique(data.map((record) => record.version)).length} target versions`,
          },
          {
            label: "Passing",
            value: count(passing),
            note: `${percent(data.length ? passing / data.length : 0)} of history`,
          },
          {
            label: "Regressions",
            value: count(failing),
            note: "failed or degraded states",
          },
          {
            label: "Latest version",
            value: latest?.version ?? "—",
            note: latest?.status ?? "No status",
          },
        ]}
      />
      <div className="panel-grid analytical-grid">
        <Panel
          title="Regression posture"
          meta="all recorded checks"
          eyebrow="REGRESSION POSTURE"
        >
          <DistributionBars rows={unique(data.map((record) => record.status))
            .map((status) => ({
              label: status,
              value: data.filter((record) => record.status === status).length,
              tone: regressionTone(status),
            }))} />
        </Panel>
        <Panel
          title="Version activity"
          meta="checks per version"
          eyebrow="REGRESSION POSTURE"
        >
          <DistributionBars rows={unique(data.map((record) => record.version))
            .map((version) => ({
              label: version,
              value: data.filter((record) => record.version === version).length,
              tone: "brand",
            }))} />
        </Panel>
      </div>
      <Panel
        title="Regression timeline"
        meta="newest first"
        eyebrow="REGRESSION POSTURE"
      >
        <Timeline rows={[...data]
          .sort(
            (left, right) =>
              Date.parse(right.recorded_at) - Date.parse(left.recorded_at),
          )
          .map((record) => ({
            id: `${record.regression_id}:${record.version}:${record.recorded_at}`,
            title: `${record.version} · ${record.status}`,
            detail: record.regression_id,
            at: record.recorded_at,
            tone: regressionTone(record.status),
          }))} />
      </Panel>
      <Panel title="Regression ledger" meta="authoritative history">
        <RecordTable
          data={data}
          identityKeys={["regression_id", "version", "recorded_at"]}
          columns={[
            { key: "version", label: "Version", mono: true },
            { key: "regression_id", label: "Regression", mono: true },
            { key: "status", label: "Status" },
            { key: "recorded_at", label: "Recorded", mono: true, timestamp: true },
          ]}
        />
      </Panel>
    </>
  );
}

export function CoverageRegressionScreen({ client }: { client: ApiClient }) {
  const coverage = useResource<CoverageReadModel[]>(
    client,
    RESOURCE_PATHS.coverage,
    decodeCoverage,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );
  const regression = useResource<ResilienceReadModel[]>(
    client,
    RESOURCE_PATHS.resilience,
    decodeResilience,
    { pollIntervalMs: LIVE_RESOURCE_POLL_INTERVAL_MS },
  );

  return (
    <div className="screen-stack">
      <ScreenHeading
        title="Coverage & Regression"
        detail="Hash-verified coverage snapshots and authoritative regression history, updated from the live read projections."
      />
      <ResourceView
        result={coverage.result}
        emptyLabel="No verified coverage records are available."
      >
        {(data) => <CoverageEvidence data={data} />}
      </ResourceView>
      <ResourceView
        result={regression.result}
        emptyLabel="No regression history is recorded."
      >
        {(data) => <RegressionEvidence data={data} />}
      </ResourceView>
    </div>
  );
}
