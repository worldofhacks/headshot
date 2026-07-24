# WP-20C — Integrate the console, workbench, and report drafts

**Branch:** `rtg/wp20c-console-report-integration`

**Model:** capable

**Depends on:** WP-19B

**Implements toward (live validation pending):** console/report portions of RT-01–RT-14

Use frozen contracts and read-model shapes. Treat every target/model/tool/operator string
as hostile.

**Implementation writes only**

- `console/src/api/**`
- `console/src/screens/AgentToolScreens.tsx`
- `console/src/screens/ObservabilityScreens.tsx`
- `console/src/components/**`
- `console/src/styles/console.css`
- `docs/security/LLM_SECURITY_WORKBENCH.md`
- `docs/security/LLM_TOOLCHAIN.md`
- `docs/security/SECURITY_REPORTING.md`

**Test writes only**

- `console/tests/red-team-workbench.test.tsx`
- `console/tests/red-team-reporting.test.tsx`
- `console/tests/browser/red-team-workbench.spec.ts`

## Required result

Show evidence stages and blockers separately; sanitized workbench projections with
protected fields locked; immutable intercept/drop/forward-as-new-plan decisions; literal
diffs and fuzz caps; site map/API/auth/ZAP/OAST/stream/browser/process-isolation states;
tool capability/artifact/review/evidence stages; regressions; and approved report drafts.

Use exact honest labels. Proxy and Repeater remain governed analogues/partial, active
scanner/browser/OAST stay blocked without evidence, unsupported Burp features remain
unsupported, and advisory/simulated/indeterminate data never becomes security success.
Display `implementation_precheck` separately from `approved_live_evidence`; a local browser
test, fixture/cassette, fake target, simulated artifact, or tool configuration can never
render as live, operational, regression-protected, or closed.
No unsafe HTML/Markdown, formula injection, secret reconstruction, client-side authority,
or action hidden behind a display-only permission check.

**Focused verifier**

```bash
cd console && npm test -- red-team-workbench.test.tsx red-team-reporting.test.tsx
cd console && npm run test:browser -- red-team-workbench.spec.ts
```

Then run the console build and source/bundle policy gates. No deployment, browser target
navigation, publication, push, or merge. Deployed UI behavior remains
`LIVE_EVIDENCE_REQUIRED` for WP-21B–E.

**Handoff:** WP-20 final integration routes console/report defects back here.
