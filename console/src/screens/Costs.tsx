/*
 * Costs.tsx — "Cost & budget" screen.
 * Faithful 1:1 port of Headshot Console.dc.html template lines 1217–1260.
 *
 * Two scenario branches (honest Demo ⇄ Integration split):
 *  - Integration ({{ integ }}): fabricated live cost numbers are dropped; an honest
 *    "No live projection" empty-state is shown (no metering projection exists yet).
 *  - Demo ({{ notInteg }}): the real modeled figures from app.costsVM() / app.COSTS —
 *    budget, burn, spend-by-agent, spend-by-model, and the policy card
 *    (cached / batch / hosted %, retry, low-signal). Cost is NEVER tokens×N.
 *
 * Data comes from app.costsVM() (co* fields) and app.core() ({{ integ }}, {{ notInteg }},
 * {{ setDemo }}) — never duplicated here.
 */
import type { ScreenProps } from "../types";
import { Lab } from "../components/primitives";

interface Agent { k: string; v: string; w: string; c: string }
interface Model { k: string; v: string; w: string }

export function Costs({ app }: ScreenProps) {
  const vm = app.costsVM();
  const core = app.core();
  const integ: boolean = core.integ;
  const notInteg: boolean = core.notInteg;
  const setDemo: () => void = core.setDemo;

  const coAgents: Agent[] = vm.coAgents;
  const coModels: Model[] = vm.coModels;

  return (
    <>
      {/* ===== COSTS ===== */}
      {integ && (
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto", display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 24px" }}>
          <div style={{ maxWidth: "540px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: "13px" }}>
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="var(--tx3)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z" opacity=".45"></path><path d="M8.5 12h7"></path></svg>
            <div style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, color: "var(--tx)", letterSpacing: "-.01em" }}>No live projection</div>
            <div style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", lineHeight: 1.55 }}>No authoritative cost source is wired. Per-agent and per-model spend require a metering projection that does not exist yet.</div>
            <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-pill)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>cost metering PROPOSED</span>
            <button onClick={setDemo} style={{ marginTop: "4px", height: "32px", padding: "0 15px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>View demo scenario</button>
          </div>
        </div>
      )}
      {notInteg && (
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
          <div style={{ maxWidth: "1100px", margin: "0 auto", padding: "20px 24px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
              <span style={{ fontSize: "var(--fs-3xl)", fontWeight: 600 }}>Cost &amp; budget</span>
              <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "3px 10px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-xs)", fontWeight: 600, color: vm.coStateColor, border: "1px solid " + vm.coStateColor }}>
                <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: vm.coStateColor }}></span>{vm.coState}
              </span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr 1fr", gap: "12px", marginBottom: "14px" }}>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "14px 16px" }}>
                <Lab>Budget consumed</Lab>
                <div style={{ display: "flex", alignItems: "baseline", gap: "8px", margin: "6px 0 9px" }}>
                  <span className="mono" style={{ fontSize: "var(--fs-4xl)", fontWeight: 600, color: vm.coBudgetColor }}>{vm.coUsed}</span>
                  <span className="mono" style={{ fontSize: "var(--fs-base)", color: "var(--tx3)" }}>/ {vm.coCap} · {vm.coPct}</span>
                </div>
                <div style={{ height: "6px", borderRadius: "3px", background: "var(--bg-inset)", overflow: "hidden" }}><div style={{ height: "100%", width: vm.coPct, background: vm.coBudgetColor }}></div></div>
              </div>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "14px 16px" }}>
                <Lab>Burn rate</Lab>
                <div className="mono" style={{ fontSize: "var(--fs-4xl)", fontWeight: 600, marginTop: "6px" }}>{vm.coBurn}<span style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)", fontWeight: 400 }}> /hr</span></div>
              </div>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "14px 16px" }}>
                <Lab>Projected cap</Lab>
                <div className="mono" style={{ fontSize: "var(--fs-4xl)", fontWeight: 600, marginTop: "6px", color: "var(--warn)" }}>{vm.coProj}</div>
              </div>
            </div>
            <div style={{ border: "1px solid var(--warn-line)", borderRadius: "var(--r-md)", padding: "12px 15px", background: "var(--warn-t)", marginBottom: "16px", display: "flex", gap: "11px" }}>
              <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="var(--warn)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "0 0 auto", marginTop: "1px" }}><path d="M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01"></path></svg>
              <div>
                <div style={{ fontSize: "var(--fs-base)", fontWeight: 600, color: "var(--warn)" }}>Policy action at cap</div>
                <div style={{ fontSize: "var(--fs-sm)", color: "var(--tx2)", lineHeight: 1.5, marginTop: "2px" }}>At the cap the cost circuit-breaker <b>pauses</b> new campaigns; in-flight attempts finish and record. Queued work accumulates durably in Postgres — nothing is dropped. The Orchestrator throttles as the cap approaches.</div>
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "14px" }}>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "14px 16px" }}>
                <Lab>Spend by agent</Lab>
                <div style={{ display: "flex", flexDirection: "column", gap: "9px", marginTop: "11px" }}>
                  {coAgents.map((a, i) => (
                    <div key={i}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-sm)", marginBottom: "4px" }}><span>{a.k}</span><span className="mono" style={{ color: "var(--tx2)" }}>{a.v}</span></div>
                      <div style={{ height: "6px", borderRadius: "3px", background: "var(--bg-inset)", overflow: "hidden" }}><div style={{ height: "100%", width: a.w, background: a.c }}></div></div>
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "14px 16px" }}>
                <Lab>Spend by model</Lab>
                <div style={{ display: "flex", flexDirection: "column", gap: "9px", marginTop: "11px" }}>
                  {coModels.map((m, i) => (
                    <div key={i}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--fs-sm)", marginBottom: "4px" }}><span className="mono" style={{ fontSize: "var(--fs-xs)" }}>{m.k}</span><span className="mono" style={{ color: "var(--tx2)" }}>{m.v}</span></div>
                      <div style={{ height: "6px", borderRadius: "3px", background: "var(--bg-inset)", overflow: "hidden" }}><div style={{ height: "100%", width: m.w, background: "var(--brand)" }}></div></div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "12px" }}>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 15px" }}>
                <Lab>Cached input</Lab>
                <div className="mono" style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginTop: "5px", color: "var(--phos)" }}>{vm.coCached}</div>
                <Lab style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Batch API {vm.coBatch}</Lab>
              </div>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 15px" }}>
                <Lab>Hosted inference</Lab>
                <div className="mono" style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginTop: "5px" }}>{vm.coHosted}</div>
                <Lab style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Local 0% · dev switch</Lab>
              </div>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 15px" }}>
                <Lab>Retry cost</Lab>
                <div className="mono" style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginTop: "5px", color: "var(--warn)" }}>{vm.coRetry}</div>
                <Lab style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>Backoff + re-exec</Lab>
              </div>
              <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "13px 15px" }}>
                <Lab>Low-signal cost</Lab>
                <div className="mono" style={{ fontSize: "var(--fs-3xl)", fontWeight: 600, marginTop: "5px", color: "var(--tx2)" }}>{vm.coLow}</div>
                <Lab style={{ color: "var(--tx3)", fontSize: "var(--fs-2xs)" }}>No-finding windows</Lab>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
