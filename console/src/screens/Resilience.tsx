/*
 * Resilience.tsx — faithful 1:1 translation of the prototype template lines 1083–1141.
 *
 * "Is this target getting harder to break across versions?" — version bars (Confirmed /
 * Likely exploit rate per target version) plus a per-category change table (prev → now,
 * change delta, confidence). Data comes from app.resilienceVM() → { resVersions, resCats }.
 *
 * Demo ⇄ Integration honesty (rule 4): in Integration state (`integ`) fabricated live
 * projections are dropped and an honest "No live projection" empty-state is shown; the
 * bars/table render only in Demo state (`notInteg`). The outer isResilience router gate
 * lives at the App level, so this component renders the inner integ / notInteg branches.
 */
import type { ScreenProps } from "../types";

interface ResVersion {
  v: string;
  conf: string;
  likely: string;
  confH: string;
  likelyH: string;
  n: number;
  nColor: string;
  note: string;
  noteColor: string;
  noteLabel: string;
  hasNote: boolean;
}

interface ResCat {
  name: string;
  prev: string;
  now: string;
  delta: string;
  deltaColor: string;
  confLabel: string;
  confColor: string;
}

export function Resilience({ app }: ScreenProps) {
  const integ = app.state.scenario === "integration";
  const notInteg = app.state.scenario !== "integration";
  const { resVersions, resCats } = app.resilienceVM() as {
    resVersions: ResVersion[];
    resCats: ResCat[];
  };

  return (
    <>
      {integ && (
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto", display: "flex", alignItems: "center", justifyContent: "center", padding: "48px 24px" }}>
          <div style={{ maxWidth: "540px", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center", gap: "13px" }}>
            <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="var(--tx3)" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z" opacity=".45"></path><path d="M8.5 12h7"></path></svg>
            <div style={{ fontSize: "var(--fs-2xl)", fontWeight: 600, color: "var(--tx)", letterSpacing: "-.01em" }}>No live projection</div>
            <div style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", lineHeight: 1.55 }}>Cross-version resilience needs the coverage and findings projections tracked over time. Neither is exposed to the console today.</div>
            <span className="lab" style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "4px 11px", border: "1px solid var(--bd)", borderRadius: "var(--r-pill)", color: "var(--tx2)", fontSize: "var(--fs-2xs)" }}>INTERNAL ONLY → projection PROPOSED</span>
            <button onClick={() => app.setDemo()} style={{ marginTop: "4px", height: "32px", padding: "0 15px", border: "1px solid var(--bd)", borderRadius: "var(--r-sm)", background: "transparent", color: "var(--tx2)", fontSize: "var(--fs-sm)", fontWeight: 600 }}>View demo scenario</button>
          </div>
        </div>
      )}
      {notInteg && (
        <div style={{ flex: 1, minHeight: 0, overflowY: "auto" }}>
          <div style={{ maxWidth: "1040px", margin: "0 auto", padding: "20px 24px" }}>
            <div style={{ marginBottom: "16px" }}>
              <div style={{ fontSize: "var(--fs-3xl)", fontWeight: 600 }}>Resilience</div>
              <div style={{ fontSize: "var(--fs-base)", color: "var(--tx2)", marginTop: "2px" }}>Is this target getting harder to break across versions?</div>
            </div>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", padding: "16px 18px", marginBottom: "16px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "14px", marginBottom: "16px" }}>
                <span style={{ fontSize: "var(--fs-base)", fontWeight: 600 }}>Exploit rate by target version</span>
                <div style={{ flex: 1 }}></div>
                <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}><span style={{ width: "9px", height: "9px", borderRadius: "2px", background: "var(--v-conf)" }}></span>Confirmed</span>
                <span style={{ display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "var(--fs-xs)", color: "var(--tx2)" }}><span style={{ width: "9px", height: "9px", borderRadius: "2px", background: "var(--v-likely)" }}></span>Likely</span>
              </div>
              <div style={{ display: "flex", alignItems: "flex-end", gap: 0, height: "170px", borderBottom: "1px solid var(--bd)", paddingBottom: 0 }}>
                {resVersions.map((v, i) => (
                  <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "flex-end", height: "100%", position: "relative" }}>
                    {v.hasNote && (
                      <span className="lab" style={{ position: "absolute", top: 0, padding: "2px 6px", borderRadius: "var(--r-xs)", fontSize: "var(--fs-2xs)", color: v.noteColor, border: "1px solid " + v.noteColor }}>{v.noteLabel} · {v.note}</span>
                    )}
                    <div style={{ display: "flex", alignItems: "flex-end", gap: "5px", height: "130px" }}>
                      <div style={{ width: "22px", height: v.confH, background: "var(--v-conf)", borderRadius: "3px 3px 0 0" }} title={"Confirmed " + v.conf}></div>
                      <div style={{ width: "22px", height: v.likelyH, background: "var(--v-likely)", borderRadius: "3px 3px 0 0" }} title={"Likely " + v.likely}></div>
                    </div>
                  </div>
                ))}
              </div>
              <div style={{ display: "flex", gap: 0 }}>
                {resVersions.map((v, i) => (
                  <div key={i} style={{ flex: 1, textAlign: "center", paddingTop: "8px" }}>
                    <div className="mono" style={{ fontSize: "var(--fs-sm)", fontWeight: 600 }}>{v.v}</div>
                    <div className="mono" style={{ fontSize: "var(--fs-2xs)", color: v.nColor, marginTop: "2px" }}>n={v.n}</div>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: "12px", fontSize: "var(--fs-xs)", color: "var(--tx3)", display: "flex", alignItems: "center", gap: "7px" }}><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 8v5 M12 16h.01"></path></svg>v1.4.2 sample is smaller (n=96) — the downward trend is directional, not yet conclusive.</div>
            </div>
            <div style={{ border: "1px solid var(--bd)", borderRadius: "var(--r-md)", overflow: "hidden" }}>
              <div style={{ padding: "11px 16px", borderBottom: "1px solid var(--sep)", fontSize: "var(--fs-base)", fontWeight: 600 }}>Category-level change <span className="mono" style={{ fontSize: "var(--fs-xs)", color: "var(--tx3)", fontWeight: 400 }}>v1.4.1 → v1.4.2</span></div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 80px 80px 96px 150px", gap: "8px", padding: "8px 16px", background: "var(--bg-head)", borderBottom: "1px solid var(--sep)" }}><span className="lab">Category</span><span className="lab" style={{ textAlign: "right" }}>Prev</span><span className="lab" style={{ textAlign: "right" }}>Now</span><span className="lab" style={{ textAlign: "right" }}>Change</span><span className="lab">Confidence</span></div>
              {resCats.map((c, i) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "1fr 80px 80px 96px 150px", gap: "8px", padding: "10px 16px", alignItems: "center", borderBottom: "1px solid var(--sep)" }}>
                  <span style={{ fontSize: "var(--fs-base)" }}>{c.name}</span>
                  <span className="mono" style={{ fontSize: "var(--fs-sm)", textAlign: "right", color: "var(--tx3)" }}>{c.prev}</span>
                  <span className="mono" style={{ fontSize: "var(--fs-sm)", textAlign: "right", color: "var(--tx)" }}>{c.now}</span>
                  <span className="mono" style={{ fontSize: "var(--fs-sm)", textAlign: "right", fontWeight: 600, color: c.deltaColor }}>{c.delta}</span>
                  <span className="mono" style={{ fontSize: "var(--fs-xs)", color: c.confColor }}>{c.confLabel}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
