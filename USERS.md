# USERS.md — AgentForge / Adversarial Machine

Who the **adversarial evaluation platform** serves, the workflows it runs for them, and — the part
the PRD grades hardest — *why autonomous multi-agent automation is the right solution and not
over-engineering*. (These are the platform's users. The Co-Pilot's clinical end-users appear only as
context for what an exploit puts at risk.)

---

## 1. Primary users

### 1.0 Invitation-only access and authenticated roles

All human users enter through **Clerk** and must be invited into the exact required **Headshot**
Organization for the environment. Personal accounts and user-created organizations are disabled. MFA is
mandatory for every member, with TOTP plus backup codes preferred; SMS is not the only factor. Clerk and
authenticated Railway integration are selected/planned and are not yet claimed deployed.

The backend authorizes the following custom organization permissions from verified Clerk session claims.
Frontend role labels and client-supplied roles/permissions are display data only and create no authority.

| Authenticated workflow | Clerk role | Backend-authoritative permissions | What the user does |
|---|---|---|---|
| **Observer** | `org:observer` | `org:console:read`, `org:findings:read`, `org:evidence:read` | Reviews posture, findings, and approved evidence without mutating platform state. |
| **Operator** | `org:operator` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:campaign:launch`, `org:campaign:abort`, `org:targets:manage`, `org:config:manage` | Configures an allowed target, proposes/launches an authorized workflow, monitors it, and can abort it. |
| **Approver** | `org:approver` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:campaign:authorize`, `org:findings:approve`, `org:findings:resolve` | Independently authorizes a launch, approves a critical finding, and resolves findings/remediation decisions. |
| **Auditor** | `org:auditor` | `org:console:read`, `org:findings:read`, `org:evidence:read`, `org:audit:read` | Reconstructs who launched, authorized, aborted, approved, or resolved an operation and reviews evidence. |

**Separation of launcher and approver is an identity invariant, not a role convention.** An Operator's
operation requires a different authenticated Approver: `approver.user_id != launcher_user_id`. The
launcher cannot approve their own operation even if they also possess an Approver role or permission;
there is no solo or emergency self-approval bypass. Both identities are recorded in the append-only audit
trail.

Authentication controls who may ask the application to act. It does **not** authorize a live attack by
itself: the Policy Gateway must still validate exact target authorization, environment allowlist,
target-scoped credentials, synthetic-data-only status, budget/rate caps, timeout/monitoring, and hard abort.

### 1.1 AI Security Engineer / Red-Teamer (primary operator)
Owns the security posture of an LLM application wired into clinical workflows. Today they test by
hand: craft a prompt, try it, eyeball the response, maybe save the good ones in a doc.

**Workflows the platform gives them**
- **Author + seed** attack cases across categories (injection, PHI exfiltration, state corruption,
  tool misuse, DoS, identity/role) — tagged boundary/invariant/regression and mapped to OWASP.
- As an authenticated **Operator**, request/launch a campaign against an allowlisted target under budget
  + rate caps, with synthetic data only and a hard abort. Launch permission does not bypass the separate
  campaign authorization gate.
- As a **different authenticated Approver**, independently authorize the operation and approve or deny
  publication of critical reports and remediation. The launcher can never approve their own operation.
- **Read the posture over time**: which categories are covered, pass/fail trend, is the target
  getting more or less resilient, what's open vs resolved, what it cost.

**Pain today:** manual prompting doesn't scale, findings don't reproduce, fixes are validated once
and silently regress, and coverage is invisible.

### 1.2 Application / Platform Security Team (consumer of output)
Consumes the Documentation Agent's vulnerability reports and the triage report. They need each
finding to be reproducible, actionable, and usable by an engineer *who was not present when the
exploit was found* — a unique ID, clinical impact, a minimal reproducible sequence, observed vs
expected, and a remediation.

**Workflow:** receive report → reproduce from the sequence alone → validate the fix → confirm the
regression harness now guards it.

### 1.3 Hospital CISO / Compliance & Risk (the trust authority)
Does not operate the platform; *decides whether to trust it* with continuous testing of systems
physicians depend on. Consumes trust boundaries, the human-approval model, deploy/rollback, cost
governance, the ATO-style evidence packet, and the AI-use disclosure (where AI was used, what was
independently verified, what stays risky, and how a drifting Judge is detected and corrected).

**Workflow:** review the evidence packet → interrogate the trust boundaries → grant or withhold
authorization to operate.

---

## 2. The system as its own operator (why "autonomous" is a user requirement, not a flourish)
The PRD's north star — *"adapting as attackers adapt, without a human in the loop for every step"* —
makes autonomous operation a stated requirement. The Orchestrator is effectively a machine user: it
reads the system's own state and decides what to test next, so that overnight and continuous runs
produce learning, not just noise. The human stays in the loop for **judgment gates** (approve
critical findings, approve remediation), not for **every step**.

That machine user is not a Clerk user. Agents use service identity, per-agent database roles, provider
credentials, and target-scoped credential bindings. Human session tokens are never workload credentials,
and an agent cannot acquire a human permission by emitting role or permission text.

---

## 3. Why automation is the right solution (explicit justification)

The PRD demands this justification, and it is defensible line by line:

1. **Attacks mutate; static suites rot.** "Defenses built around a small number of known examples
   rarely hold as attackers adapt." A human-maintained payload list is outdated the day after it's
   written. An agent that takes a *partial* success and autonomously generates ten variants to find
   the one that breaks through is doing work a static runner structurally cannot.
2. **Continuous ≠ occasional, and humans are the bottleneck.** The goal is *continuous* stress
   testing across every target version. A human in the loop for every prompt caps throughput at
   human speed; the value is precisely in the runs that happen while no one is watching.
3. **Reproducibility and regression are automation problems.** "Finding a vulnerability once is not
   enough." Converting an exploit into a deterministic, replayable test and re-running it on every
   target change is mechanical, high-volume, and exactly what machines are good at — and what humans
   reliably skip.
4. **Coverage visibility requires instrumentation, not memory.** Knowing which categories are tested
   and whether resilience is trending up requires an observability substrate feeding an orchestrator
   — impossible to hold in a person's head across thousands of runs.
5. **The conflict-of-interest split needs distinct agents.** Attack generation and attack evaluation
   are different jobs; "a system that does both in the same context has a conflict of interest by
   design." Separating them into an untrusted Red Team and an **independent** Judge is a security
   property you get from multi-agent structure, not from one bigger prompt.

## 4. Where automation deliberately stops (so it stays trustworthy)
Automation earns trust by knowing its limits. AgentForge stops for a distinct authenticated Approver
before **authorizing a live operation**, before **publishing a critical-severity finding**, and before
**any remediation** — because "an agent that confidently
documents a false positive wastes engineering time" and "an agent with the ability to push fixes
without review can introduce entirely new vulnerabilities." Autonomy covers discovery, evaluation,
regression, and drafting; humans own the gates where a wrong call has real cost. Role or permission
alone cannot waive launcher/approver identity separation. This boundary is
the answer to the CISO's core question — *where does it proceed on its own, and where does it stop?*
