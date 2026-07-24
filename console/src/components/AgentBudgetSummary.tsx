import type { AgentBudgetReadModel } from "../types";
import { count, money } from "./Analytics";
import { StateNotice } from "./ResourceView";

const remainingLabel = (
  budget: AgentBudgetReadModel,
  scope: "Role" | "Global",
  unit: "USD" | "calls",
) => (
  budget.status === "historical"
    ? `${scope} ${unit} unused at close`
    : `${scope} ${unit} remaining`
);

export function AgentBudgetSummary({
  budget,
}: {
  budget: AgentBudgetReadModel;
}) {
  if (budget.status === "unavailable") {
    return (
      <div className="evidence-stack">
        <p className="field-label">Provider budget guard</p>
        <StateNotice
          state="unavailable"
          detail="No authorized hosted subcap is active, staged, or historically bound for this role."
        />
      </div>
    );
  }

  return (
    <div className="evidence-stack">
      <p className="field-label">Provider budget guard</p>
      {budget.status === "historical" && (
        <StateNotice
          state="empty"
          detail="Historical authorization snapshot. Unused amounts were available at close but cannot authorize new provider calls."
        />
      )}
      <dl className="agent-ledger-summary">
        <div>
          <dt>Budget state</dt>
          <dd className="mono">
            {budget.status === "historical"
              ? "historical · closed"
              : budget.status.replaceAll("_", " ")}
          </dd>
        </div>
        <div>
          <dt>Role known spend</dt>
          <dd className="mono">{money(budget.role_usd_spent)}</dd>
        </div>
        <div>
          <dt>Role unresolved USD exposure</dt>
          <dd className="mono">{money(budget.role_unresolved_usd_exposure)}</dd>
        </div>
        <div>
          <dt>{remainingLabel(budget, "Role", "USD")}</dt>
          <dd className="mono">
            {money(budget.role_usd_remaining ?? 0)} / {money(budget.role_usd_cap ?? 0)}
          </dd>
        </div>
        <div>
          <dt>Role observed provider calls</dt>
          <dd className="mono">{count(budget.role_physical_calls)}</dd>
        </div>
        <div>
          <dt>Role unresolved provider calls</dt>
          <dd className="mono">{count(budget.role_unresolved_physical_calls)}</dd>
        </div>
        <div>
          <dt>{remainingLabel(budget, "Role", "calls")}</dt>
          <dd className="mono">
            {count(budget.role_calls_remaining ?? 0)} / {count(budget.role_call_cap ?? 0)}
          </dd>
        </div>
        <div>
          <dt>Global known spend</dt>
          <dd className="mono">{money(budget.global_usd_spent)}</dd>
        </div>
        <div>
          <dt>Global unresolved USD exposure</dt>
          <dd className="mono">{money(budget.global_unresolved_usd_exposure)}</dd>
        </div>
        <div>
          <dt>{remainingLabel(budget, "Global", "USD")}</dt>
          <dd className="mono">
            {money(budget.global_usd_remaining ?? 0)} / {money(budget.global_usd_cap ?? 0)}
          </dd>
        </div>
        <div>
          <dt>Global observed provider calls</dt>
          <dd className="mono">{count(budget.global_physical_calls)}</dd>
        </div>
        <div>
          <dt>Global unresolved provider calls</dt>
          <dd className="mono">{count(budget.global_unresolved_physical_calls)}</dd>
        </div>
        <div>
          <dt>{remainingLabel(budget, "Global", "calls")}</dt>
          <dd className="mono">
            {count(budget.global_calls_remaining ?? 0)} / {count(budget.global_call_cap ?? 0)}
          </dd>
        </div>
      </dl>
      <p className="data-note">
        Remaining headroom already subtracts known spend or calls and unresolved provider
        exposure. It is not a tokens × rate estimate.
      </p>
    </div>
  );
}
