/*
 * Headshot Operator Console — shared types (the coordination contract).
 *
 * AppState mirrors the prototype's `this.state = { ... }` initializer exactly (field-for-field).
 * Scalars/unions are precise so screens get real type-checking on the common paths; deeply nested
 * transient objects (drafts, dialog payloads) stay permissive to keep the faithful port tractable.
 *
 * ConsoleApp is the interface every screen/overlay consumes: `app.state` (precise) + `app.setState`
 * + every ported method/data-field (via the index signature). The root `App` React.Component class
 * implements this. Colors come from CSS vars (DESIGN_SYSTEM.md §3) via inline styles — never literals.
 */
import type { ReactNode } from "react";

/* ----- four independent semantic channels (DESIGN_SYSTEM.md §5) ----- */
export type Verdict =
  | "EXPLOIT_CONFIRMED"
  | "EXPLOIT_LIKELY"
  | "NO_EXPLOIT_OBSERVED"
  | "INDETERMINATE"
  | "ERROR";
export type Severity = "critical" | "high" | "medium" | "low";
export type TrustZone = "trust" | "gov" | "quar" | "ext" | "data" | "human";
export type Provenance = "oracle" | "human" | null;

/* ----- routing / shell ----- */
export type Screen =
  | "live"
  | "findings"
  | "approvals"
  | "coverage"
  | "resilience"
  | "traces"
  | "costs"
  | "targets"
  | "config"
  | "more";
export type Theme = "dark" | "light";
export type Density = "compact" | "comfortable";
export type Surface = "desktop" | "tablet" | "mobile";
export type Breakpoint = "xl" | "lg" | "md" | "sm";
export type Scenario = "demo" | "integration";
export type LiveMode = "birdseye" | "stream";

/* ----- state machines ----- */
export type CampaignState = "running" | "aborting" | "aborted";
export type AbortStage = "confirm" | "propagating" | "aborted" | "error";
export type DecisionStage = "form" | "submitting" | "acknowledged" | "error";
export type TargetLife = "draft" | "validating" | "ready" | "disabled" | "archived";
export type PublishStage = "idle" | "validating" | "review" | "published" | "active" | "error";
export type JudgeCalib = "passing" | "failed" | "invalidated" | "pending";

/* ----- domain records (fixtures in data.ts conform to these) ----- */
export interface Attempt {
  id: string;
  seq: number;
  t: string;
  cat: string;
  st: number; // stage index 0..5 into STAGES
  v: Verdict | null;
  planned: Verdict | null;
  strat: string;
  cost: number;
  attn: string | null;
  prov?: Provenance;
  repro?: number;
  human?: string;
  js?: number;
  err?: string;
  hashState?: string;
  [k: string]: unknown;
}

export interface Finding {
  id: string;
  sev: Severity;
  v: Verdict;
  prov: Provenance;
  cat: string;
  status: string;
  owner: string;
  age: string;
  reg: string;
  att: string;
}

export interface Approval {
  id: string;
  kind: "publication" | "indeterminate" | "escalation" | "remediation";
  fid: string;
  action: string;
  sla: string;
  esc: "none" | "raised";
}

export interface AuditEntry {
  t: string;
  who: string;
  ev: string;
}

export interface AttackSurface {
  id: string;
  name: string;
  type: string;
  ver: number;
  locator: string;
  trust: string;
  auth: string;
  risk: string;
  ow: string;
  ol: string;
  enabled: boolean;
  cats: string;
  valid: string;
  tested: string;
  history?: unknown[];
  [k: string]: unknown;
}

export interface TargetState {
  id: string;
  name: string;
  env: string;
  adapter: string;
  ver: string;
  allow: string;
  cred: string;
  synth: string;
  owner: string;
  elig: boolean;
  active: boolean;
  checks: string[][];
  life: TargetLife | string;
  baseUrl: string;
  hosts: string[];
  budget: string;
  rate: string;
  attemptCap: number;
  timeout: string;
  verified: string;
  structural: string;
  connectivity: string;
  fixture: string;
  canary: string;
  blockers: string[];
  surfaces: AttackSurface[];
  audit: string[][];
  [k: string]: unknown;
}

export interface Budget {
  cap: number;
  used: number;
  burn: number;
}

/* ----- the full application state (mirrors the prototype constructor 1:1) ----- */
export interface AppState {
  theme: Theme;
  density: Density;
  surface: Surface;
  screen: Screen;

  // selections
  selA: string;
  selF: string;
  fTab: string;
  fQuery: string;
  selT: string;
  selSpan: string;
  mTab: string;
  mView: string | null;

  // live stream
  paused: boolean;
  atEdge: boolean;
  newCount: number;

  // command palette
  palOpen: boolean;
  palQ: string;
  palIdx: number;

  // abort dialog
  abortOpen: boolean;
  abortStage: AbortStage;
  abortAck: boolean;

  // approvals / decision sheet
  apprId: string;
  apprMobile: boolean;
  decision: Record<string, unknown> | null;
  decisionStage: DecisionStage;
  decisionNote: string;
  noteError: boolean;

  campaignState: CampaignState;
  bp: Breakpoint;
  principalIdx: number;
  roleMenu: boolean;
  simFail: boolean;
  live: string; // aria-live announcement text
  inspectorTab: "attempt" | "evidence";
  liveMode: LiveMode;
  scenario: Scenario;

  // birdseye war-room
  beNode: string | null;
  beFollow: boolean;
  beCollapsed: boolean;
  beTLCollapsed: boolean;
  beAttnAll: boolean;
  beAttnRailOpen: boolean;
  beMPhase: string | null;

  // configuration
  cfgAgent: string;
  cfgScope: string;
  agentModel: Record<string, string>;
  judgeCalib: JudgeCalib | string;
  cfgDirty: Record<string, unknown>;
  cfgPublish: { stage: PublishStage | string; rationale: string; err: boolean };
  calibReview: boolean;

  // model catalog
  catalogOpen: boolean;
  catalogFor: string | null;
  catalogQ: string;
  catalogProv: string;
  catalogSort: string;
  catalogState: string;
  catalogCompare: string[];

  // targets management
  tStore: TargetState[];
  editT: Record<string, unknown> | null;
  surfaceDraft: Record<string, unknown> | null;
  surfaceEdit: Record<string, unknown> | null;
  authProbe: Record<string, unknown> | null;
  tTab: string;
  tQuery: string;
  tFilter: string;
  newT: Record<string, unknown> | null;
  tLife: Record<string, unknown>;
  probeAuth: Record<string, unknown>;
  sfToggle: Record<string, unknown>;

  // quarantine reveal + toast
  quar: Record<string, boolean>;
  toast: { msg: string; kind?: string } | null;

  budget: Budget;
  attempts: Attempt[];
  pending: Attempt[];
  findings: Finding[];
  approvals: Approval[];
  audit: AuditEntry[];

  [k: string]: unknown;
}

/* Loose partial-state patch accepted by setState (mirrors React.Component.setState). */
export type StatePatch = Partial<AppState> | ((s: AppState) => Partial<AppState>);

/**
 * ConsoleApp — the contract screens/overlays consume. The root `App` class implements it.
 * `state` is precise; `setState` mirrors React; the index signature exposes every ported
 * method (go, toast, openAbort, openDecision, birdseyeVM, targetsVM, …) and data field
 * (VMETA, SEVMETA, CAT, MODEL_CATALOG, ic, nav, …) without enumerating all ~150 here.
 */
export interface ConsoleApp {
  state: AppState;
  setState(patch: StatePatch, cb?: () => void): void;
  [key: string]: any;
}

/** Standard prop shape for every screen/overlay component. */
export interface ScreenProps {
  app: ConsoleApp;
}

export type { ReactNode };
