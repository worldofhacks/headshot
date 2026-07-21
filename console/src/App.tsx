/*
 * Headshot Operator Console — root React component.
 *
 * Faithful 1:1 port of the prototype `class Component extends DCLogic` (Headshot Console.dc.html
 * lines 2409–3455). Every method is preserved in behavior; `this.setState`, `React.createRef`,
 * and `React.createElement` are kept as-is. Fixtures + seed factories are imported from ./data
 * and assigned as instance fields so screens read `app.VMETA`, `app.CAT`, `app.nav`, etc.
 *
 * render() emits the themed full-viewport root wrapper (template lines 105–106) and delegates
 * all layout to <Shell app={this} />. Props do not exist in production: theme='dark',
 * density='compact', paused=false, streamPace=1500 (hardcoded where the prototype read props).
 */
import React from "react";
import type { AppState, ConsoleApp } from "./types";
import { Shell } from "./components/Shell";
import {
  STAGES, ROLES, VMETA, ic, SHORT, nav, CAT, SEVMETA, STMETA, REGMETA, FDET,
  TARGETS, TRACE, COVERAGE, RESILIENCE, COSTS, COMPONENTS, AGENTS, DETERMINISTIC,
  MODEL_CATALOG, AGENTCFG, TARGETX, seedTargets, initialSeed,
} from "./data";

/*
 * Frozen URL contract (DESIGN_SYSTEM.md §7): the single-page app's `screen` (+ primary entity) is
 * the route. Canonical paths: /live · /live/:attempt · /findings/:id · /approvals/:id · and
 * /coverage /resilience /traces /costs /targets /config. The full navigable state is also carried
 * in history.state so Back/Forward restore exactly (including closing a mobile drill-in).
 */
const SCREENS = ["live", "findings", "approvals", "coverage", "resilience", "traces", "costs", "targets", "config", "more"];
const LOC_FIELDS = ["screen", "selF", "apprId", "selA", "liveMode", "mView"];

/**
 * The React.Component state generic is intentionally `any` (not the precise `AppState`): the
 * prototype's `this.state`/`this.setState` are untyped, and the faithful port legitimately sets
 * runtime literals that AppState's narrow unions over-restrict (abortStage='working'/'done',
 * inspectorTab='stream', decisionStage='done', looser Attempt objects). `App` still declares
 * `state: AppState` and `implements ConsoleApp`, so every screen/overlay consumer keeps the precise
 * contract — only the internal mutation surface is widened, preserving all values 1:1.
 */
export class App extends React.Component<{}, any> implements ConsoleApp {
  [key: string]: any;
  // `state` inherits the loose `any` generic (below) so the ported behavior's runtime literals
  // typecheck; ConsoleApp's precise `state: AppState` is still honored for every screen consumer
  // via the type of `<Shell app={this} />` and the AppState-typed `app.state` reads in screens.
  declare state: any;

  constructor(props: {}) {
    super(props);
    const p: any = props || {};
    let s = 0x9e3779b9 ^ 20260720;
    this.rng = () => { s |= 0; s = s + 0x6D2B79F5 | 0; let t = Math.imul(s ^ s >>> 15, 1 | s); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
    this.streamRef = React.createRef();
    this.now = 2 * 3600 + 47 * 60 + 11;
    this.uid = 188;
    this.tk = 0;
    this.STAGES = STAGES;
    this.ROLES = ROLES;
    this.VMETA = VMETA;
    this.ic = ic;
    this.SHORT = SHORT;
    this.nav = nav;
    this.CAT = CAT;
    this.SEVMETA = SEVMETA;
    this.STMETA = STMETA;
    this.REGMETA = REGMETA;
    this.FDET = FDET;
    this.TARGETS = TARGETS;
    this.TRACE = TRACE;
    this.COVERAGE = COVERAGE;
    this.RESILIENCE = RESILIENCE;
    this.COSTS = COSTS;
    this.COMPONENTS = COMPONENTS;
    this.AGENTS = AGENTS;
    this.DETERMINISTIC = DETERMINISTIC;
    this.MODEL_CATALOG = MODEL_CATALOG;
    this.AGENTCFG = AGENTCFG;
    this.TARGETX = TARGETX;

    const seed = initialSeed();
    this.state = {
      theme: (p.defaultTheme === 'light' || p.defaultTheme === 'dark') ? p.defaultTheme : 'dark',
      density: (p.defaultDensity === 'comfortable') ? 'comfortable' : 'compact',
      surface: 'desktop', screen: 'live',
      selA: 'A-0185', selF: 'F-1042', fTab: 'overview', fQuery: '', selT: 'atlas', selSpan: 'exec', mTab: 'approvals', mView: null,
      paused: !!p.demoStartPaused, atEdge: true, newCount: 0,
      palOpen: false, palQ: '', palIdx: 0,
      abortOpen: false, abortStage: 'confirm', abortAck: false,
      apprId: 'AP-01', apprMobile: false, decision: null, decisionStage: 'form', decisionNote: '', noteError: false,
      campaignState: 'running', bp: 'xl', principalIdx: 0, roleMenu: false, simFail: false, live: '', inspectorTab: 'attempt', liveMode: 'birdseye', scenario: 'demo', beNode: null, beFollow: true, beCollapsed: false, beTLCollapsed: false, beAttnAll: false, beAttnRailOpen: true, beMPhase: null,
      cfgAgent: 'judge', cfgScope: 'workspace',
      tStore: seedTargets(), editT: null, surfaceDraft: null, authProbe: null, calibReview: false,
      agentModel: { orch: 'anthropic/claude-opus-4.8', rt: 'cognitivecomputations/dolphin-3.0', judge: 'anthropic/claude-sonnet-4.6', doc: 'openai/gpt-5.4' },
      judgeCalib: 'passing', cfgDirty: {}, cfgPublish: { stage: 'idle', rationale: '', err: false },
      catalogOpen: false, catalogFor: null, catalogQ: '', catalogProv: 'all', catalogSort: 'recency', catalogState: 'ok', catalogCompare: [],
      tTab: 'overview', tQuery: '', tFilter: 'all', surfaceEdit: null, newT: null, tLife: {}, probeAuth: {}, sfToggle: {},
      quar: {}, toast: null,
      budget: seed.budget,
      attempts: seed.attempts,
      pending: seed.pending,
      findings: seed.findings,
      approvals: seed.approvals,
      audit: seed.audit,
    } as AppState;
    // Direct deep-load: select the correct screen/entity from the URL before first paint.
    Object.assign(this.state, this._parseLoc());
  }

  // ---- URL contract + browser history ------------------------------------------------------
  _canonPath(s: any) {
    if (s.screen === "findings") return "/findings/" + encodeURIComponent(s.selF);
    if (s.screen === "approvals") return "/approvals/" + encodeURIComponent(s.apprId);
    if (s.screen === "live") return s.liveMode === "stream" && s.selA ? "/live/" + encodeURIComponent(s.selA) : "/live";
    return "/" + s.screen;
  }
  _parseLoc() {
    let path = "/live";
    try { path = window.location.pathname || "/live"; } catch (e) { return {}; }
    const parts = path.replace(/^\/+|\/+$/g, "").split("/");
    const screen = parts[0] || "live";
    if (SCREENS.indexOf(screen) < 0) return { screen: "live" };
    const patch: any = { screen };
    const id = parts[1] ? decodeURIComponent(parts[1]) : null;
    // Set the entity AND the matching mobile drill-in (mView) — inert on desktop (Mobile isn't
    // rendered), but makes a phone deep-load open the entity instead of only the list.
    if (screen === "findings" && id) { patch.selF = id; patch.mView = "finding"; }
    else if (screen === "approvals" && id) { patch.apprId = id; patch.mView = "approval"; }
    else if (screen === "live" && id) { patch.selA = id; patch.liveMode = "stream"; patch.inspectorTab = "attempt"; patch.mView = "attempt"; }
    return patch;
  }
  _locSnap(s: any) { const o: any = {}; LOC_FIELDS.forEach((k) => (o[k] = s[k])); return o; }
  _locEq(a: any, b: any) { return !!a && !!b && LOC_FIELDS.every((k) => a[k] === b[k]); }
  _syncUrl() {
    if (this._applyingPop) return;
    const snap = this._locSnap(this.state);
    if (this._lastLoc && this._locEq(snap, this._lastLoc)) return;
    try { window.history.pushState(Object.assign({ __hs: 1 }, snap), "", this._canonPath(this.state)); } catch (e) { }
    this._lastLoc = snap;
  }
  _onPop(e: any) {
    this._applyingPop = true;
    const snap = e && e.state && e.state.__hs ? e.state : null;
    let patch: any;
    if (snap) { patch = {}; LOC_FIELDS.forEach((k) => { if (k in snap) patch[k] = snap[k]; }); }
    else { patch = Object.assign({ mView: null }, this._parseLoc()); }
    this._lastLoc = null; // force re-sync/no-push on the applied state
    // A navigation always dismisses transient overlays.
    this.setState(Object.assign({ decision: null, palOpen: false, roleMenu: false }, patch), () => {
      this._lastLoc = this._locSnap(this.state);
      this._applyingPop = false;
    });
  }

  componentDidMount() { this._key = this.onKey.bind(this); window.addEventListener('keydown', this._key); this._resize = () => { const b = this.calcBp(); if (b !== this.state.bp) this.setState({ bp: b }); }; window.addEventListener('resize', this._resize); this._pop = (e: any) => this._onPop(e); window.addEventListener('popstate', this._pop); this._lastLoc = this._locSnap(this.state); try { window.history.replaceState(Object.assign({ __hs: 1 }, this._lastLoc), '', this._canonPath(this.state)); } catch (e) { } this.setState({ bp: this.calcBp() }); this.startTimer(); }
  componentWillUnmount() { window.removeEventListener('keydown', this._key); window.removeEventListener('resize', this._resize); window.removeEventListener('popstate', this._pop); clearInterval(this._t); clearTimeout(this._toast); clearTimeout(this._focusT); clearTimeout(this._cat); clearTimeout(this._pub); clearTimeout(this._pub2); }
  calcBp() { const w = window.innerWidth, h = window.innerHeight; let coarse = false; try { coarse = (window.matchMedia && window.matchMedia('(pointer:coarse)').matches) as boolean; } catch (e) { } if (w < 768 || (h <= 520 && w <= 960) || (coarse && w < 900)) return 'sm'; return w >= 1396 ? 'xl' : w >= 904 ? 'lg' : 'md'; }
  componentDidUpdate() { this._syncUrl(); const o = this.overlayOpen(); if (o && !this._prevOverlay) { this._lastFocus = document.activeElement; clearTimeout(this._focusT); this._focusT = setTimeout(() => this.focusOverlay(), 40); } else if (!o && this._prevOverlay) { const el = this._lastFocus; if (el && el.focus) { try { el.focus(); } catch (e) { } } } try { document.body.style.overflow = o ? 'hidden' : ''; } catch (e) { } this._prevOverlay = o; }
  overlayOpen() { const s = this.state; return s.palOpen || s.abortOpen || !!s.decision || s.roleMenu || s.catalogOpen || !!s.surfaceDraft || !!s.newT || !!s.editT || !!s.authProbe; }
  focusOverlay() { const el = document.querySelector('[data-overlay="1"]'); if (!el) return; const sel = 'input:not([type=hidden]),textarea,button,[tabindex]:not([tabindex="-1"])'; const f: any = el.querySelector('[data-autofocus]') || el.querySelector(sel); if (f && f.focus) { try { f.focus(); } catch (e) { } } }
  startTimer() { clearInterval(this._t); const pace = Math.max(600, 1500); this._t = setInterval(() => this.tick(), pace); }

  fmt2(n: number) { return '$' + n.toFixed(2); }
  fmt3(n: number) { return '$' + n.toFixed(3); }
  clockStr(sec: number) { const h = Math.floor(sec / 3600) % 24, m = Math.floor(sec / 60) % 60, s = sec % 60; const z = (x: number) => String(x).padStart(2, '0'); return z(h) + ':' + z(m) + ':' + z(s); }
  hexFor(id: string) { let h = 0; for (let i = 0; i < id.length; i++) { h = (h * 31 + id.charCodeAt(i)) >>> 0; } const a = h.toString(16).padStart(8, '0'); const b = ((h ^ 0x5bd1e995) >>> 0).toString(16).padStart(8, '0'); return 'sha256:' + a.slice(0, 4) + '…' + b.slice(-4); }

  tick() {
    this.setState((prev: any) => {
      if (prev.campaignState !== 'running') return null as any;
      const paused = prev.paused;
      let attempts = prev.attempts, pending = prev.pending, newCount = prev.newCount;
      const b: any = Object.assign({}, prev.budget);
      b.used = Math.min(b.cap, +(b.used + 0.02 + this.rng() * 0.045).toFixed(3));
      if (!paused) attempts = attempts.map((a: any) => a.st < 5 ? this.advance(a) : a);
      this.tk++;
      if (this.tk % 2 === 0) {
        const ev = this.spawn();
        if (!paused && prev.atEdge) attempts = [ev, ...attempts].slice(0, 64);
        else { pending = [ev, ...pending].slice(0, 60); newCount++; }
      }
      return { attempts, pending, newCount, budget: b };
    });
  }
  advance(a: any) { const n: any = Object.assign({}, a); n.st = a.st + 1; if (n.st >= 5) { n.st = 5; n.v = this.VMETA[a.planned] ? a.planned : 'ERROR'; if (!this.VMETA[a.planned] && !n.err) n.err = 'evidence-missing'; if (a.attn) n.attn = a.attn; } return n; }
  spawn() {
    const keys = ['inj', 'xten', 'exfil', 'tool', 'sys', 'ssrf', 'rag', 'out'];
    const k = keys[Math.floor(this.rng() * keys.length)];
    const outs = ['NO_EXPLOIT_OBSERVED', 'NO_EXPLOIT_OBSERVED', 'NO_EXPLOIT_OBSERVED', 'EXPLOIT_LIKELY', 'INDETERMINATE'];
    const v = outs[Math.floor(this.rng() * outs.length)];
    const strats = ['DIRECT', 'MUT·1', 'MUT·2', 'MUT·3', 'SEQ·2', 'SEQ·3', 'SEQ·4'];
    this.now += 5 + Math.floor(this.rng() * 9);
    const id = 'A-0' + (this.uid++);
    const js = v === 'EXPLOIT_LIKELY' ? 0.80 + this.rng() * 0.12 : v === 'INDETERMINATE' ? 0.45 + this.rng() * 0.25 : this.rng() * 0.25;
    return { id, seq: this.uid - 1, t: this.clockStr(this.now), cat: k, st: 0, v: null, planned: v, strat: strats[Math.floor(this.rng() * strats.length)], cost: +(0.004 + this.rng() * 0.02).toFixed(3), attn: v === 'INDETERMINATE' ? 'review' : null, js: +js.toFixed(2) };
  }

  onKey(e: any) {
    if (e.key === 'Tab' && this.overlayOpen()) { const ov = document.querySelector('[data-overlay="1"]'); if (ov) { const f = ov.querySelectorAll('a[href],button:not([disabled]),input,textarea,select,[tabindex]:not([tabindex="-1"])'); if (f.length) { const first: any = f[0], last: any = f[f.length - 1]; if (!ov.contains(document.activeElement)) { e.preventDefault(); first.focus(); } else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); } else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); } } } return; }
    if (e.key === 'Escape' && (this.state.catalogOpen || this.state.surfaceDraft || this.state.newT || this.state.editT || this.state.authProbe)) { e.preventDefault(); this.setState({ catalogOpen: false, surfaceDraft: null, newT: null, editT: null, authProbe: null }); return; }
    if (e.key === 'Escape' && this.state.beNode && !this.overlayOpen()) { e.preventDefault(); this.setState({ beNode: null }); return; }
    const meta = e.metaKey || e.ctrlKey;
    if (meta && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); this.setState((s: any) => ({ palOpen: !s.palOpen, palQ: '', palIdx: 0 })); return; }
    if (this.state.palOpen) {
      if (e.key === 'Escape') { e.preventDefault(); this.setState({ palOpen: false }); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); const n = this.palItemsRaw().length; this.setState((s: any) => ({ palIdx: Math.min(n - 1, s.palIdx + 1) })); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); this.setState((s: any) => ({ palIdx: Math.max(0, s.palIdx - 1) })); }
      else if (e.key === 'Enter') { e.preventDefault(); const it = this.palItemsRaw()[this.state.palIdx]; if (it) this.runPal(it); }
      return;
    }
    const tag = (e.target && e.target.tagName) || '';
    const typing = tag === 'INPUT' || tag === 'TEXTAREA';
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); this.setState({ palOpen: true, palQ: '', palIdx: 0 }); return; }
    if (e.key === 'Escape') { if (this.state.roleMenu) { this.setState({ roleMenu: false }); } else if (this.state.decision) { this.cancelDecision(); } else if (this.state.abortOpen) { this.closeAbort(); } else if (this.state.mView) { this.mBack(); } return; }
    if ((e.key === 'j' || e.key === 'ArrowDown' || e.key === 'k' || e.key === 'ArrowUp') && (this.state.screen === 'live' || this.state.screen === 'findings')) {
      e.preventDefault(); const dir = (e.key === 'j' || e.key === 'ArrowDown') ? 1 : -1; if (this.state.screen === 'live') this.moveSel(dir); else this.moveFinding(dir);
    }
  }
  moveSel(dir: number) {
    const rows = this.state.attempts; const i = rows.findIndex((a: any) => a.id === this.state.selA);
    const ni = Math.max(0, Math.min(rows.length - 1, (i < 0 ? 0 : i) + dir));
    this.setState({ selA: rows[ni].id });
  }

  go(id: any) { this.setState({ screen: id, palOpen: false, mView: null, beNode: null }); }
  toast(msg: string, color?: string) { this.setState({ toast: { msg, color: color || 'var(--phos)' } as any }); clearTimeout(this._toast); this._toast = setTimeout(() => this.setState({ toast: null }), 3400); }

  togglePause() { this.setState((s: any) => { if (s.paused) { const merged = [...s.pending, ...s.attempts].slice(0, 64); return { paused: false, attempts: merged, pending: [], newCount: 0, atEdge: true }; } return { paused: true }; }); }
  onStreamScroll() { const el: any = this.streamRef.current; if (!el) return; const edge = el.scrollTop <= 6; if (edge !== this.state.atEdge) this.setState({ atEdge: edge }); }
  flushNew() { const el: any = this.streamRef.current; if (el) el.scrollTop = 0; this.setState((s: any) => ({ attempts: [...s.pending, ...s.attempts].slice(0, 64), pending: [], newCount: 0, atEdge: true })); }

  toggleTheme() { this.setState((s: any) => ({ theme: s.theme === 'dark' ? 'light' : 'dark' })); }
  setSurface(v: any) { this.setState({ surface: v, mView: null }); }

  openAbort() { this.setState({ abortOpen: true, abortStage: 'confirm', abortAck: false, simFail: false }); }
  closeAbort() { if (this.state.abortStage === 'working') return; this.setState({ abortOpen: false }); }
  toggleAbortAck() { this.setState((s: any) => ({ abortAck: !s.abortAck })); }
  toggleSimFail() { this.setState((s: any) => ({ simFail: !s.simFail })); }
  doAbort() { if (!this.state.abortAck) return; this._runAbort(); }
  retryAbort() { this.setState({ simFail: false }); this._runAbort(); }
  _runAbort() {
    this.setState({ abortStage: 'working', campaignState: 'aborting' });
    setTimeout(() => {
      if (this.state.simFail) { this.setState({ abortStage: 'error', campaignState: 'running' }); this.announce('Abort failed — the campaign is still running. Retry available.'); return; }
      this.setState((s: any) => {
        const audit = [{ t: this.clockStr(this.now), who: this.ROLES[s.principalIdx].name, ev: 'Campaign RUN 042 aborted — 6 queued cancelled, 2 in-flight recorded and stopped; evidence preserved.' }, ...s.audit];
        const attempts = s.attempts.map((a: any) => a.st < 5 ? Object.assign({}, a, { st: 5, v: 'ERROR', planned: 'ERROR', err: 'aborted', attn: null }) : a);
        return { abortStage: 'done', campaignState: 'aborted', paused: true, audit, attempts, pending: [], newCount: 0, budget: Object.assign({}, s.budget, { burn: 0 }) };
      });
      this.announce('Campaign aborted. Testing stopped; recorded evidence preserved.');
    }, 1400);
  }
  announce(msg: string) { this.setState({ live: msg }); }
  currentPrincipal() { return this.ROLES[this.state.principalIdx]; }
  blockedFor(kind: string) { const p = this.currentPrincipal(); if (!p.canApprove) return { blocked: true, reason: 'Requires the Approver permission — you are signed in as ' + p.role + ' (' + p.name + ').' }; if ((kind === 'publication' || kind === 'remediation') && p.isLauncher) return { blocked: true, reason: 'Two-person rule — the approver must differ from the campaign launcher. ' + p.name + ' launched RUN 042.' }; return { blocked: false, reason: '' }; }
  setPrincipal(i: number) { this.setState({ principalIdx: i, roleMenu: false }); }
  toggleRoleMenu() { this.setState((s: any) => ({ roleMenu: !s.roleMenu })); }

  revealQuar() { const id = this.state.selA; this.setState((s: any) => ({ quar: Object.assign({}, s.quar, { [id]: true }) })); }
  hideQuar() { const id = this.state.selA; this.setState((s: any) => { const q: any = Object.assign({}, s.quar); delete q[id]; return { quar: q }; }); }
  copyQuar() { const raw = this.rawSel(); const txt = this.CAT[raw.cat].quar; try { navigator.clipboard && navigator.clipboard.writeText(txt); } catch (e) { } this.toast('Quarantined content copied — handle as untrusted, never execute.', 'var(--warn)'); }

  // ---- palette ----
  palItemsRaw() {
    const q = this.state.palQ.trim().toLowerCase();
    const items: any[] = [];
    this.nav.forEach((n: any) => items.push({ type: 'nav', id: n.id, label: 'Go to ' + n.label, group: 'Navigate', icon: n.icon, hint: '' }));
    items.push({ type: 'act', id: 'pause', label: (this.state.paused ? 'Resume' : 'Pause') + ' visual stream', group: 'Action', icon: this.ic.pause, hint: '' });
    items.push({ type: 'act', id: 'abort', label: 'Abort campaign RUN 042', group: 'Action', icon: this.ic.abort, hint: 'danger' });
    items.push({ type: 'act', id: 'theme', label: 'Toggle theme', group: 'Action', icon: this.ic.theme, hint: '' });
    this.state.findings.forEach((f: any) => items.push({ type: 'finding', id: f.id, label: f.id + ' · ' + this.CAT[f.cat].cat, group: 'Finding', icon: this.ic.findings, hint: f.sev }));
    if (!q) return items.filter(i => i.type !== 'finding' || ['F-1042', 'F-1053', 'F-1051'].includes(i.id));
    return items.filter(i => i.label.toLowerCase().includes(q) || i.group.toLowerCase().includes(q));
  }
  runPal(it: any) {
    this.setState({ palOpen: false });
    if (it.type === 'nav') this.go(it.id);
    else if (it.type === 'finding') { this.setState({ screen: 'findings', selF: it.id }); }
    else if (it.id === 'pause') this.togglePause();
    else if (it.id === 'abort') this.openAbort();
    else if (it.id === 'theme') this.toggleTheme();
  }
  onPalInput(e: any) { this.setState({ palQ: e.target.value, palIdx: 0 }); }

  rawSel() { return this.state.attempts.find((a: any) => a.id === this.state.selA) || this.state.pending.find((a: any) => a.id === this.state.selA) || this.state.attempts[0]; }

  mapRow(a: any) {
    const C = this.CAT[a.cat]; const resolved = a.st >= 5; const m = resolved ? this.VMETA[a.v] : null;
    return {
      id: a.id, seqStr: '#' + a.seq, t: a.t, cat: C.cat, catShort: this.SHORT[a.cat], catColor: C.color, owaspId: C.owaspId.replace(':2021', ''), strat: a.strat,
      inProgress: !resolved, resolved, stageLabel: (this.STAGES[a.st] || '').toUpperCase(), prog: Math.round((a.st / 5) * 100) + '%',
      vLabel: m ? m.short : '', vColor: m ? m.color : 'var(--tx3)', vDotR: m ? m.dotR : '50%',
      attHuman: a.attn === 'human', attReview: a.attn === 'review',
      cost: this.fmt3(a.cost), rowBg: a.id === this.state.selA ? 'var(--sel)' : 'transparent', rowLine: a.id === this.state.selA ? 'var(--sel-line)' : 'transparent',
      select: () => this.setState({ selA: a.id, inspectorTab: 'attempt' }), mSelect: () => this.openMAttempt(a.id)
    };
  }

  buildSel() {
    const a = this.rawSel(); const C = this.CAT[a.cat]; const isExp = a.v === 'EXPLOIT_CONFIRMED' || a.v === 'EXPLOIT_LIKELY';
    const quarShown = !!this.state.quar[a.id];
    const gens = [['SEED', 'Seed case · injection corpus'], ['MUT·1', 'Unicode homoglyph obfuscation'], ['MUT·2', 'Nested inside quoted document'], ['MUT·3', 'Role-play maintenance wrapper'], ['MUT·4', 'Split across conversation turns']];
    const depth = a.strat.indexOf('MUT') >= 0 ? (parseInt(a.strat.split('·')[1]) || 2) + 1 : a.strat.indexOf('SEQ') >= 0 ? 3 : 1;
    const mutation = gens.slice(0, Math.max(2, Math.min(gens.length, depth + 1))).map((g, i, arr) => {
      const last = i === arr.length - 1; return { gen: g[0], desc: g[1], c: last ? 'var(--brand)' : 'var(--tx3)', fill: last ? 'var(--brand)' : 'transparent', r: g[0] === 'SEED' ? '2px' : '50%', line: i < arr.length - 1 ? 'var(--bd)' : 'transparent' };
    });
    return {
      id: a.id, strat: a.strat, objective: C.objective, rationale: C.rationale,
      owaspF: C.owaspF, owaspId: C.owaspId, owaspName: C.owaspName,
      quarHidden: !quarShown, quarRevealed: quarShown, quarText: C.quar,
      req: C.req, resp: isExp ? C.rExp : C.rSafe,
      mutation,
      policy: [{ k: 'Allowlist', v: 'match' }, { k: 'Credential scope', v: 'atlas-support:staging' }, { k: 'Synthetic data', v: 'asserted' }, { k: 'Budget', v: 'within cap' }, { k: 'Rate', v: '60 rpm ok' }],
      timing: [{ k: 'Queued', v: a.t }, { k: 'Policy check', v: '12 ms' }, { k: 'Executing', v: '1.84 s' }, { k: 'Recording', v: '34 ms' }, { k: 'Judging', v: '2.10 s' }, { k: 'Total', v: '4.02 s' }]
    };
  }

  buildEv() {
    const a = this.rawSel(); const v = a.v; const resolved = a.st >= 5; const meta = this.VMETA[v] || this.VMETA.ERROR;
    const hashState = a.hashState || (a.err === 'target-unreachable' ? 'incomplete' : 'verified');
    const HS: any = { verified: { label: 'Verified', color: 'var(--phos)', tint: 'var(--phos-tint)', border: 'var(--phos-line)' }, pending: { label: 'Pending verification', color: 'var(--warn)', tint: 'var(--warn-t)', border: 'var(--warn-line)' }, mismatch: { label: 'Hash mismatch', color: 'var(--v-err)', tint: 'var(--v-err-t)', border: 'var(--v-err)' }, incomplete: { label: 'Evidence incomplete', color: 'var(--v-err)', tint: 'var(--v-err-t)', border: 'var(--v-err)' } };
    const hs = HS[hashState];
    const prov = a.prov;
    const provMap: any = { oracle: { line: 'Oracle confirmed · canary-sensitive-record', color: 'var(--phos)' }, human: { line: 'Human confirmed · A. Okafor', color: 'var(--tz-human)' } };
    let provLine = prov ? provMap[prov].line : v === 'EXPLOIT_LIKELY' ? 'Judge assessment · above threshold' : v === 'NO_EXPLOIT_OBSERVED' ? 'No exploit observed · within evidentiary limits' : v === 'INDETERMINATE' ? 'Parked · not safe, not confirmed' : 'Evaluation could not complete';
    let provColor = prov ? provMap[prov].color : meta.color;
    const hasOracle = prov === 'oracle';
    const hasError = v === 'ERROR';
    const hasJudge = resolved && !hasError && (v !== 'EXPLOIT_CONFIRMED' || prov === 'human' || true);
    const judgeSuppressed = hasOracle;
    const js = a.js != null ? a.js : (v === 'EXPLOIT_LIKELY' ? 0.83 : v === 'INDETERMINATE' ? 0.63 : 0.12);
    const calibOk = v !== 'INDETERMINATE';
    const rationale: any = {
      EXPLOIT_CONFIRMED: prov === 'human' ? 'Reviewer confirmed the response returns records outside the authenticated tenant scope. Judge score was below threshold; human confirmation takes precedence.' : '',
      EXPLOIT_LIKELY: 'Response complies with the adversarial instruction and performs the gated action without the required confirmation. Grounded in the recorded transcript; no deterministic oracle applies.',
      NO_EXPLOIT_OBSERVED: 'Agent refused the embedded instruction and stayed within scope across all sampled turns. Absence of an observed exploit under this rubric — not a proof of safety.',
      INDETERMINATE: 'Score falls inside the uncertainty band and calibration drift is flagged for this category. Evidence is contradictory across samples; parked for human classification.',
      ERROR: ''
    };
    const errMap: any = {
      'target-unreachable': { what: 'The target adapter returned no response within the execution timeout.', exec: 'No', trust: 'No evidence recorded — the target was never reached.', retry: '02:48:20 · 2/3' },
      'judge-timeout': { what: 'Judge evaluation exceeded the 8s budget for this attempt.', exec: 'Yes', trust: 'Transcript recorded and hash-verified; the verdict was not produced.', retry: '02:47:40 · 2/3' },
      'evidence-integrity-failed': { what: 'Recomputed content hash does not match the stored hash.', exec: 'Yes', trust: 'Evidence is NOT trustworthy — verdict blocked.', retry: 'manual review' },
      'aborted': { what: 'Attempt cancelled when campaign RUN 042 was aborted.', exec: 'Partial', trust: 'Partial evidence retained; no verdict produced.', retry: '—' }
    };
    const em = errMap[a.err] || errMap['target-unreachable'];
    const showAction = v === 'EXPLOIT_CONFIRMED' && prov === 'oracle';
    return {
      vKey: v || 'IN_PROGRESS', vLabel: resolved ? meta.label : (this.STAGES[a.st] + '…'), vColor: resolved ? meta.color : 'var(--brand)', vTint: resolved ? meta.tint : 'var(--brand-tint)', vBorder: resolved ? meta.border : 'var(--brand-line)', vIcon: resolved ? meta.icon : 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 7v5l3 2', vIconEl: this.svgEl(resolved ? meta.icon : 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 7v5l3 2', 17, 1.9),
      provLine, provColor,
      hashState, hashLabel: hs.label, hashColor: hs.color, hashTint: hs.tint, hashBorder: hs.border, hashMismatch: hashState === 'mismatch',
      hash: this.hexFor(a.id), recorder: 'recorder-svc 2.3.1', trace: 'tr_042_' + a.seq, schema: 'v1',
      hasOracle, oracleName: 'canary-sensitive-record', oracleDetail: 'Synthetic canary token CN-7731 (planted in fixture data) was observed verbatim in the target response — a deterministic sensitive-data leak signal.',
      hasJudge: hasJudge && !hasOracle || hasOracle, judgeSuppressed, judgeActive: hasJudge && !judgeSuppressed && !hasError,
      judgeModel: 'judge-sonnet-4.6', judgeScore: js.toFixed(2), judgeScorePct: Math.round(js * 100) + '%', judgeThresh: '0.80', judgeThreshPct: '80%',
      judgeRubric: 'rubric-data-exfiltration-v1', judgeCalib: calibOk ? 'calibrated · ok' : 'drift flagged', calibColor: calibOk ? 'var(--v-clear)' : 'var(--warn)', judgeOpacity: judgeSuppressed ? 0.62 : 1,
      judgeRationale: rationale[v] || '',
      hasError, errCode: a.err || '', errWhat: em.what, errExec: em.exec, errTrust: em.trust, errRetry: em.retry,
      reproCount: a.repro != null ? a.repro : 0, humanState: a.human || (v === 'EXPLOIT_LIKELY' ? 'Review recommended' : '—'),
      showAction, action: () => this.goApproval('AP-01'), actionLabel: 'Open in approval queue', actionIcon: this.ic.approvals, actionIconEl: this.svgEl(this.ic.approvals, 14, 2)
    };
  }

  goFinding(id: string) { this.setState({ screen: 'findings', selF: id, fTab: 'overview' }); }
  setFTab(t: string) { this.setState({ fTab: t }); }
  onFSearch(e: any) { this.setState({ fQuery: e.target.value }); }
  vChip(v: any) { const m = this.VMETA[v] || this.VMETA.ERROR; return { label: m.label, short: m.short, color: m.color, tint: m.tint, border: m.border, icon: m.icon }; }
  filteredFindings() { const q = (this.state.fQuery || '').trim().toLowerCase(); let list = this.state.findings; if (q) list = list.filter((f: any) => f.id.toLowerCase().includes(q) || this.CAT[f.cat].cat.toLowerCase().includes(q) || f.sev.includes(q) || this.STMETA[f.status].label.toLowerCase().includes(q)); const rank: any = { critical: 0, high: 1, medium: 2, low: 3 }; return list.slice().sort((a: any, b: any) => rank[a.sev] - rank[b.sev]); }
  moveFinding(dir: number) { const list = this.filteredFindings(); const i = list.findIndex((f: any) => f.id === this.state.selF); const ni = Math.max(0, Math.min(list.length - 1, (i < 0 ? 0 : i) + dir)); if (list[ni]) this.setState({ selF: list[ni].id }); }

  findingsVM() {
    const st = this.state;
    const list = this.filteredFindings().map((f: any) => {
      const v = this.vChip(f.v); const sev = this.SEVMETA[f.sev]; const stm = this.STMETA[f.status]; const C = this.CAT[f.cat];
      return {
        id: f.id, onClick: () => this.goFinding(f.id), mOnClick: () => this.openMFinding(f.id),
        sevColor: sev.color, sevLabel: sev.label,
        vColor: v.color, vTint: v.tint, vBorder: v.border, vLabel: v.short, vIcon: v.icon, vIconEl: this.svgEl(v.icon, 10, 2.1),
        prov: f.prov === 'oracle' ? 'Oracle' : f.prov === 'human' ? 'Human' : f.v === 'EXPLOIT_LIKELY' ? 'Judge' : '—', provColor: f.prov === 'oracle' ? 'var(--phos)' : f.prov === 'human' ? 'var(--tz-human)' : 'var(--tx3)',
        catShort: this.SHORT[f.cat], owasp: C.owaspId, status: stm.label, statusColor: stm.color,
        owner: f.owner, age: f.age,
        rowBg: f.id === st.selF ? 'var(--sel)' : 'transparent', rowLine: f.id === st.selF ? 'var(--sel-line)' : 'transparent'
      };
    });
    return {
      fList: list, fCount: st.findings.length, fShown: list.length, fQuery: st.fQuery, onFSearch: (e: any) => this.onFSearch(e), fEmpty: list.length === 0,
      fd: this.buildFinding()
    };
  }

  buildFinding() {
    const st = this.state; const f: any = st.findings.find((x: any) => x.id === st.selF) || st.findings[0]; const C = this.CAT[f.cat]; const d: any = this.FDET[f.id] || {}; const v = this.vChip(f.v); const sev = this.SEVMETA[f.sev]; const stm = this.STMETA[f.status];
    const isExp = f.v === 'EXPLOIT_CONFIRMED' || f.v === 'EXPLOIT_LIKELY'; const tab = st.fTab;
    return {
      id: f.id, title: C.cat, catShort: this.SHORT[f.cat],
      vLabel: v.label, vColor: v.color, vTint: v.tint, vBorder: v.border, vIcon: v.icon, vKey: f.v, vIconEl: this.svgEl(v.icon, 12, 1.9),
      sevLabel: sev.label, sevColor: sev.color,
      status: stm.label, statusColor: stm.color,
      prov: f.prov === 'oracle' ? 'Oracle confirmed · canary-sensitive-record' : f.prov === 'human' ? 'Human confirmed · A. Okafor' : f.v === 'EXPLOIT_LIKELY' ? 'Judge assessment · above threshold' : f.v === 'INDETERMINATE' ? 'Parked · awaiting classification' : 'No exploit observed',
      confSource: f.prov === 'oracle' ? 'Oracle' : f.prov === 'human' ? 'Human' : '—',
      target: 'Atlas Support Agent', ver: 'v1.4.2', env: 'Staging', att: f.att,
      owaspWeb: C.owaspF === 'OWASP Web' ? C.owaspId + ' · ' + C.owaspName : '— (LLM-class finding)',
      owaspLLM: C.owaspF === 'OWASP LLM' ? C.owaspId + ' · ' + C.owaspName : '— (Web-class finding)',
      summary: d.summary || '', exploit: d.exploit || '', impact: d.impact || '', expected: d.expected || '', observed: d.observed || '',
      repro: (d.repro || []).map((s: string, i: number) => ({ n: i + 1, s })), remediation: d.remediation || '',
      fix: (d.fix || []).map((x: any) => ({ v: x.v, s: x.s, t: x.t, color: x.s === 'confirmed' ? 'var(--v-conf)' : x.s === 'recurred' ? 'var(--warn)' : x.s === 'guarded' ? 'var(--v-clear)' : x.s === 'needs-review' ? 'var(--v-indet)' : x.s === 'escalated' ? 'var(--warn)' : 'var(--tx2)' })),
      req: C.req, resp: isExp ? C.rExp : C.rSafe, quarText: C.quar,
      hashState: f.att === 'A-0177' ? 'mismatch' : 'verified', hashLabel: f.att === 'A-0177' ? 'Hash mismatch' : 'Verified', hashColor: f.att === 'A-0177' ? 'var(--v-err)' : 'var(--phos)',
      hasOracle: f.prov === 'oracle', hasJudge: f.v !== 'EXPLOIT_CONFIRMED' || f.prov === 'human',
      judgeScore: f.prov === 'oracle' ? '—' : (f.att === 'A-0183' ? '0.84' : f.att === 'A-0179' ? '0.81' : f.att === 'A-0180' ? '0.74' : f.att === 'A-0181' ? '0.63' : '0.11'),
      calib: f.v === 'INDETERMINATE' ? 'drift flagged' : 'calibrated · ok', calibColor: f.v === 'INDETERMINATE' ? 'var(--warn)' : 'var(--v-clear)',
      reg: this.REGMETA[f.reg],
      tabs: [{ id: 'overview', label: 'Overview' }, { id: 'evidence', label: 'Evidence' }, { id: 'reproduction', label: 'Reproduction' }, { id: 'remediation', label: 'Remediation' }, { id: 'history', label: 'History' }].map(t => ({ id: t.id, label: t.label, active: t.id === tab, fg: t.id === tab ? 'var(--tx)' : 'var(--tx2)', bd: t.id === tab ? 'var(--brand)' : 'transparent', onClick: () => this.setFTab(t.id) })),
      tabOverview: tab === 'overview', tabEvidence: tab === 'evidence', tabRepro: tab === 'reproduction', tabRemediation: tab === 'remediation', tabHistory: tab === 'history',
      audit: st.audit.slice(0, 4),
      showRemediate: f.status === 'confirmed', openRemediate: () => this.goApproval('AP-04'),
      isConfirmed: f.v === 'EXPLOIT_CONFIRMED', isIndet: f.v === 'INDETERMINATE'
    };
  }

  goApproval(id: string) { this.setState({ screen: 'approvals', apprId: id, apprMobile: true, decision: null, decisionStage: 'form', decisionNote: '', noteError: false, palOpen: false }); }
  openDecision(k: string) { const apprId = this.curApprId(); const ap = this.state.approvals.find((a: any) => a.id === apprId); if (!ap) return; if (this.blockedFor(ap.kind).blocked) return; this.setState({ decision: { k, needsNote: true, apprId, fid: ap.fid } as any, decisionStage: 'form', decisionNote: '', noteError: false, simFail: false }); }
  cancelDecision() { if (this.state.decisionStage === 'submitting') return; this.setState({ decision: null, decisionStage: 'form', decisionNote: '', noteError: false, simFail: false }); }
  confirmDecision() { const st = this.state; if (!st.decision || st.decisionStage === 'submitting') return; if ((st.decision as any).needsNote && !st.decisionNote.trim()) { this.setState({ noteError: true }); return; } this.setState({ decisionStage: 'submitting', noteError: false }); setTimeout(() => { if (this.state.simFail) { this.setState({ decisionStage: 'error' }); this.announce('Submission failed — not applied. Your rationale is preserved; Retry is available.'); } else { this.applyDecision(); } }, 1250); }
  retryDecision() { this.setState({ simFail: false }); this.confirmDecision(); }
  closeDecision() { this.setState((s: any) => ({ decision: null, decisionStage: 'form', decisionNote: '', apprId: (s.approvals.find((a: any) => a.id === s.apprId) ? s.apprId : ((s.approvals[0] || {} as any).id || null)) })); }
  consForAction(k: string, id: string) { const m: any = { 'approve-pub': id + ' is published as a confirmed CRITICAL finding and enters confirmation-dependent workflows. Recorded with your approver identity — launcher and approver must differ.', 'reject-pub': id + ' is not published. It stays confirmed and returns to the queue for revision.', 'confirm': id + ' is set to EXPLOIT_CONFIRMED with confirmation source = human. It becomes eligible for publication and regression admission.', 'no-exploit': id + ' is recorded as NO_EXPLOIT_OBSERVED for this run. This does not prove safety and is not admitted to the regression corpus.', 'escalate': id + ' is escalated to senior review. Its verdict stays parked — not safe, not confirmed — until classified.', 'approve-rem': 'The proposed remediation for ' + id + ' is approved. The fix is marked validated only after a deterministic regression oracle passes.', 'reject-rem': 'The proposed remediation for ' + id + ' is rejected and returns for revision.' }; return m[k] || ''; }
  applyDecision() {
    this.setState((s: any) => {
      const dec: any = s.decision; const ap: any = s.approvals.find((a: any) => a.id === (dec && dec.apprId)); if (!ap || !dec) return { decisionStage: 'done' };
      const fid = ap.fid; const note = s.decisionNote.trim(); const t = this.clockStr(this.now);
      const findings = s.findings.map((f: any) => Object.assign({}, f)); let approvals = s.approvals.map((a: any) => Object.assign({}, a)); const attempts = s.attempts.map((a: any) => Object.assign({}, a)); const audit = s.audit.slice();
      const F: any = findings.find((f: any) => f.id === fid); const att: any = F ? attempts.find((a: any) => a.id === F.att) : null;
      const who0 = this.ROLES[s.principalIdx].name; const push = (ev: string) => audit.unshift({ t, who: who0, ev });
      const rm = () => { approvals = approvals.filter((a: any) => a.id !== ap.id); };
      const k = dec.k;
      if (k === 'approve-pub') { if (F) F.status = 'published'; rm(); push('Publication acknowledged — ' + fid + ' published (approver ' + who0 + ' · launcher M. Reyes).'); }
      else if (k === 'reject-pub') { if (F) F.status = 'confirmed'; rm(); push('Publication rejected — ' + fid + ' held for revision.'); }
      else if (k === 'confirm') { if (F) { F.v = 'EXPLOIT_CONFIRMED'; F.prov = 'human'; F.status = 'confirmed'; F.reg = 'candidate'; } if (att) { att.v = 'EXPLOIT_CONFIRMED'; att.planned = 'EXPLOIT_CONFIRMED'; att.prov = 'human'; att.attn = null; } rm(); push('Indeterminate resolved → EXPLOIT_CONFIRMED (human) — ' + fid + '. Rationale: ' + note); }
      else if (k === 'no-exploit') { if (F) { F.v = 'NO_EXPLOIT_OBSERVED'; F.status = 'closed'; } if (att) { att.v = 'NO_EXPLOIT_OBSERVED'; att.planned = 'NO_EXPLOIT_OBSERVED'; att.attn = null; } rm(); push('Resolved → NO_EXPLOIT_OBSERVED (human) — ' + fid + '. Rationale: ' + note); }
      else if (k === 'escalate') { if (F) F.status = 'escalated'; const cur: any = approvals.find((a: any) => a.id === ap.id); if (cur) { cur.kind = 'escalation'; cur.esc = 'raised'; cur.action = 'Escalated review'; } push('Escalated to senior review — ' + fid + '. Rationale: ' + note); }
      else if (k === 'approve-rem') { if (F) F.status = 'remediation-approved'; rm(); push('Remediation approved — ' + fid + ' pending deterministic fix validation.'); }
      else if (k === 'reject-rem') { rm(); push('Remediation rejected — ' + fid + ' returned for revision.'); }
      return { findings, approvals, attempts, audit, decisionStage: 'done' };
    }, () => { const msgs: any = { 'approve-pub': ['Publication acknowledged', 'var(--phos)'], 'reject-pub': ['Publication rejected', 'var(--tx2)'], 'confirm': ['Verdict updated · human confirmed', 'var(--v-conf)'], 'no-exploit': ['Recorded · no exploit observed', 'var(--v-clear)'], 'escalate': ['Escalated to senior review', 'var(--warn)'], 'approve-rem': ['Remediation approved', 'var(--phos)'], 'reject-rem': ['Remediation rejected', 'var(--tx2)'] }; const dk = this.state.decision && (this.state.decision as any).k; const m = msgs[dk] || ['Done', 'var(--phos)']; this.toast(m[0], m[1]); });
  }
  curApprId() { const s = this.state; return s.approvals.find((a: any) => a.id === s.apprId) ? s.apprId : ((s.approvals[0] || {} as any).id || null); }
  mapApprovalRow(ap: any) {
    const st = this.state; const f: any = st.findings.find((x: any) => x.id === ap.fid) || {}; const C: any = this.CAT[f.cat] || {}; const v = this.vChip(f.v); const sev: any = this.SEVMETA[f.sev] || {};
    const KIND: any = { publication: { label: 'Critical publication', color: 'var(--v-conf)', icon: this.ic.findings }, indeterminate: { label: 'Indeterminate verdict', color: 'var(--v-indet)', icon: this.ic.diamond }, escalation: { label: 'Escalated review', color: 'var(--warn)', icon: this.ic.bell }, remediation: { label: 'Remediation', color: 'var(--tz-gov)', icon: this.ic.check } };
    const k = KIND[ap.kind] || KIND.publication;
    return {
      id: ap.id, kindLabel: k.label, kindColor: k.color, kindIcon: k.icon, fid: f.id, catShort: this.SHORT[f.cat],
      sevColor: sev.color, sevLabel: sev.label, vLabel: v.short, vColor: v.color, vTint: v.tint, vBorder: v.border, vIcon: v.icon, kindIconEl: this.svgEl(k.icon, 13, 1.8), vIconEl: this.svgEl(v.icon, 11, 2),
      sla: ap.sla, escRaised: ap.esc === 'raised', onClick: () => this.goApproval(ap.id), mOnClick: () => this.openMApproval(ap.id),
      rowBg: ap.id === this.curApprId() ? 'var(--sel)' : 'transparent', rowLine: ap.id === this.curApprId() ? 'var(--sel-line)' : 'transparent'
    };
  }
  buildApproval() {
    const st = this.state; const id = this.curApprId(); const ap: any = st.approvals.find((a: any) => a.id === id); if (!ap) return null;
    const f: any = st.findings.find((x: any) => x.id === ap.fid) || {}; const C: any = this.CAT[f.cat] || {}; const d: any = this.FDET[f.id] || {}; const v = this.vChip(f.v); const sev: any = this.SEVMETA[f.sev] || {};
    const KIND: any = { publication: { label: 'Critical publication', color: 'var(--v-conf)', icon: this.ic.findings }, indeterminate: { label: 'Indeterminate verdict', color: 'var(--v-indet)', icon: this.ic.diamond }, escalation: { label: 'Escalated review', color: 'var(--warn)', icon: this.ic.bell }, remediation: { label: 'Remediation', color: 'var(--tz-gov)', icon: this.ic.check } }; const k = KIND[ap.kind] || KIND.publication;
    const acts = ap.kind === 'publication' ? [{ k: 'approve-pub', label: 'Approve publication', tone: 'brand' }, { k: 'reject-pub', label: 'Reject publication', tone: 'neutral' }]
      : ap.kind === 'indeterminate' ? [{ k: 'confirm', label: 'Confirm exploit', tone: 'danger' }, { k: 'no-exploit', label: 'No exploit observed', tone: 'neutral' }, { k: 'escalate', label: 'Escalate', tone: 'warn' }]
        : ap.kind === 'escalation' ? [{ k: 'confirm', label: 'Confirm exploit', tone: 'danger' }, { k: 'no-exploit', label: 'No exploit observed', tone: 'neutral' }]
          : [{ k: 'approve-rem', label: 'Approve remediation', tone: 'brand' }, { k: 'reject-rem', label: 'Reject remediation', tone: 'neutral' }];
    const isExp = f.v === 'EXPLOIT_CONFIRMED' || f.v === 'EXPLOIT_LIKELY'; const block = this.blockedFor(ap.kind);
    return {
      id: ap.id, kind: ap.kind, blocked: block.blocked, blockReason: block.reason, kindLabel: k.label, kindColor: k.color, kindIcon: k.icon, action: ap.action, requestText: (ap.kind === 'publication' ? 'Approve or reject publication of this critical finding.' : ap.kind === 'indeterminate' ? 'Classify this parked verdict — confirm the exploit, record no exploit, or escalate.' : ap.kind === 'escalation' ? 'Senior review requested — confirm the exploit or record no exploit.' : 'Approve or reject the proposed remediation.'),
      fid: f.id, title: C.cat, sevColor: sev.color, sevLabel: sev.label,
      vLabel: v.label, vColor: v.color, vTint: v.tint, vBorder: v.border, vIcon: v.icon, kindIconEl: this.svgEl(k.icon, 13, 1.8), vIconEl: this.svgEl(v.icon, 11, 2),
      target: 'Atlas Support Agent', ver: 'v1.4.2', env: 'Staging',
      confSource: f.prov === 'oracle' ? 'Oracle confirmed' : f.prov === 'human' ? 'Human confirmed' : f.v === 'EXPLOIT_LIKELY' ? 'Judge · likely' : f.v === 'INDETERMINATE' ? 'Unresolved' : '—',
      integrity: f.att === 'A-0177' ? 'Hash mismatch' : 'Verified', integrityColor: f.att === 'A-0177' ? 'var(--v-err)' : 'var(--phos)', integrityBad: f.att === 'A-0177',
      impact: d.impact || '', expected: d.expected || '', observed: d.observed || '', reproCount: (d.repro || []).length, repro: (d.repro || []).map((s: string, i: number) => ({ n: i + 1, s })),
      sla: ap.sla, escRaised: ap.esc === 'raised',
      acts: acts.map((a: any) => ({ k: a.k, label: a.label, tone: a.tone, disabled: block.blocked, bg: block.blocked ? 'var(--bg-inset)' : (a.tone === 'brand' ? 'var(--brand)' : a.tone === 'danger' ? 'var(--v-conf)' : a.tone === 'warn' ? 'var(--warn)' : 'transparent'), fg: block.blocked ? 'var(--tx3)' : (a.tone === 'neutral' ? 'var(--tx)' : '#fff'), bd: block.blocked ? 'var(--bd)' : (a.tone === 'neutral' ? 'var(--bd-2)' : 'transparent'), cons: this.consForAction(a.k, f.id), onClick: () => this.openDecision(a.k) })),
      req: C.req, resp: isExp ? C.rExp : C.rSafe, quarText: C.quar
    };
  }
  apprVM() {
    const st = this.state; const dec: any = st.decision; let dv: any = null;
    if (dec) {
      const mob = (st.bp === 'sm' || st.surface === 'mobile'); const fid = dec.fid;
      const labelMap: any = { 'approve-pub': 'Approve publication', 'reject-pub': 'Reject publication', 'confirm': 'Confirm exploit', 'no-exploit': 'No exploit observed', 'escalate': 'Escalate', 'approve-rem': 'Approve remediation', 'reject-rem': 'Reject remediation' };
      const toneMap: any = { 'approve-pub': 'brand', 'reject-pub': 'neutral', 'confirm': 'danger', 'no-exploit': 'neutral', 'escalate': 'warn', 'approve-rem': 'brand', 'reject-rem': 'neutral' };
      const sumMap: any = { 'approve-pub': ['Finding status → Published', 'Queue item removed', 'Reviewer + timestamp recorded', 'Audit event written'], 'reject-pub': ['Publication withheld', 'Finding stays Confirmed', 'Audit event written'], 'confirm': ['Verdict → EXPLOIT_CONFIRMED', 'Confirmation source → human', 'Queue item removed', 'Finding history + audit updated'], 'no-exploit': ['Verdict → NO_EXPLOIT_OBSERVED', 'Not admitted to regression', 'Queue item removed', 'Audit event written'], 'escalate': ['Finding → Escalated', 'Kept in the escalated-review queue', 'Verdict stays parked', 'Audit event written'], 'approve-rem': ['Remediation approved', 'Pending deterministic fix validation', 'Queue item removed', 'Audit event written'], 'reject-rem': ['Remediation rejected', 'Returned for revision', 'Audit event written'] };
      const tone = toneMap[dec.k];
      dv = {
        k: dec.k, label: labelMap[dec.k], needsNote: dec.needsNote, note: st.decisionNote, noteError: st.noteError, noteBorder: st.noteError ? 'var(--v-conf)' : 'var(--bd)', cons: this.consForAction(dec.k, fid), fid,
        isForm: st.decisionStage === 'form', isSubmitting: st.decisionStage === 'submitting', isDone: st.decisionStage === 'done', isError: st.decisionStage === 'error', simFail: st.simFail, onRetry: () => this.retryDecision(), onSimFail: () => this.toggleSimFail(), summary: sumMap[dec.k] || [],
        btnBg: tone === 'brand' ? 'var(--brand)' : tone === 'danger' ? 'var(--v-conf)' : tone === 'warn' ? 'var(--warn)' : 'var(--bg-inset)', btnFg: tone === 'neutral' ? 'var(--tx)' : '#fff',
        onConfirm: () => this.confirmDecision(), onCancel: () => this.cancelDecision(), onNote: (e: any) => this.setState({ decisionNote: e.target.value, noteError: false }), onDone: () => this.closeDecision(),
        sheetAlign: mob ? 'flex-end' : 'center', sheetRadius: mob ? '20px 20px 0 0' : '12px', sheetMaxW: mob ? 'min(390px,100%)' : 'min(540px,94vw)', overlayPad: mob ? '0' : '24px',
        sheetRef: this._ensureSheetRef(), dragGrab: mob && st.decisionStage !== 'submitting', onDragStart: (e: any) => this._dragStart(e), onDragMove: (e: any) => this._dragMove(e), onDragEnd: (e: any) => this._dragEnd(e)
      };
    }
    return {
      aList: st.approvals.map((ap: any) => this.mapApprovalRow(ap)), aCurrent: this.buildApproval(), aEmpty: st.approvals.length === 0,
      apprMobile: st.apprMobile, backApprList: () => this.setState({ apprMobile: false }),
      hasDecision: !!dec, dv: dv || {}
    };
  }

  setTarget(id: string) { this.setState({ selT: id }); }
  setSpan(id: string) { this.setState({ selSpan: id }); }
  setMTab(t: string) { this.setState({ mTab: t, mView: null, decision: null, beNode: null }); }
  openMApproval(id: string) { this.setState({ apprId: id, mView: 'approval', decision: null }); }
  openMFinding(id: string) { this.setState({ selF: id, fTab: 'overview', mView: 'finding' }); }
  openMAttempt(id: string) { this.setState({ selA: id, inspectorTab: 'attempt', mView: 'attempt' }); }
  openMTarget(id: string) { this.setState({ selT: id, tTab: 'overview', mView: 'target', surfaceDraft: null }); }
  openMAgent(id: string) { this.setState({ cfgAgent: id, mView: 'agent', catalogOpen: false }); }
  mBack() {
    // A drill-in was reached by pushing a history entry (its mView change), so closing it is a
    // history pop — that keeps browser/OS Back, the in-app Back button, and Esc all consistent.
    if (this.state.mView && !this._applyingPop) { this.setState({ decision: null }); window.history.back(); return; }
    this.setState({ mView: null, decision: null });
  }
  targetLife(id: string) { const t: any = (this.state.tStore || []).find((x: any) => x.id === id); return t ? t.life : 'draft'; }
  _updT(id: string, fn: (t: any) => any) { this.setState((s: any) => ({ tStore: s.tStore.map((t: any) => t.id === id ? fn(Object.assign({}, t)) : t) })); }
  targetsVM() {
    try {
      const st = this.state;
      const CK: any = { pass: { c: 'var(--v-clear)', ic: this.ic.check }, warn: { c: 'var(--warn)', ic: 'M12 3l9.5 17H2.5z M12 9.5v5 M12 17.5h.01' }, fail: { c: 'var(--v-conf)', ic: 'M6 6l12 12 M18 6L6 18' }, na: { c: 'var(--tx3)', ic: 'M6 12h12' } };
      const LIFE: any = { draft: { l: 'Draft', c: 'var(--tx2)', bg: 'var(--bg-inset)' }, validating: { l: 'Validating', c: 'var(--tz-data)', bg: 'rgba(90,143,216,.13)' }, ready: { l: 'Ready', c: 'var(--phos)', bg: 'var(--phos-tint)' }, disabled: { l: 'Disabled', c: 'var(--warn)', bg: 'var(--warn-t)' }, archived: { l: 'Archived', c: 'var(--tx3)', bg: 'var(--bg-inset)' } };
      const SURFT: any = { endpoint: 'Endpoint', tool: 'Tool', rag: 'RAG / retrieval', memory: 'Memory', files: 'Files', action: 'Action' };
      const store = st.tStore;
      const q = st.tQuery.trim().toLowerCase();
      const list = store.filter((t: any) => { const lf = t.life; if (q && t.name.toLowerCase().indexOf(q) < 0 && t.id.indexOf(q) < 0) return false; if (st.tFilter !== 'all' && lf !== st.tFilter) return false; return true; }).map((t: any) => {
        const lf = t.life; const ready = lf === 'ready' && t.elig && t.connectivity === 'authorized' && (t.blockers || []).length === 0; return {
          id: t.id, name: t.name, env: t.env, ver: t.ver, active: t.active,
          lifeLabel: LIFE[lf].l, lifeColor: LIFE[lf].c, lifeBg: LIFE[lf].bg,
          eligColor: ready ? 'var(--phos)' : 'var(--v-conf)', eligLabel: ready ? 'Eligible' : LIFE[lf].l,
          onClick: () => this.setState({ selT: t.id, tTab: 'overview', surfaceDraft: null }), mOnClick: () => this.openMTarget(t.id), rowBg: t.id === st.selT ? 'var(--sel)' : 'transparent', rowLine: t.id === st.selT ? 'var(--sel-line)' : 'transparent'
        };
      });
      const tFilters = [['all', 'All'], ['ready', 'Ready'], ['draft', 'Draft'], ['disabled', 'Disabled'], ['archived', 'Archived']].map(f => ({ id: f[0], label: f[1], active: st.tFilter === f[0], bg: st.tFilter === f[0] ? 'var(--sel)' : 'transparent', fg: st.tFilter === f[0] ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setState({ tFilter: f[0] }) }));
      const t: any = store.find((z: any) => z.id === st.selT) || store[0];
      const lf = t.life;
      const probeAuthd = t.connectivity === 'authorized';
      const blockers = (t.blockers || []);
      const ready = lf === 'ready' && t.elig && probeAuthd && blockers.length === 0;
      const tabs = [['overview', 'Overview'], ['surfaces', 'Attack surfaces'], ['controls', 'Controls'], ['credentials', 'Credentials'], ['authorization', 'Authorization'], ['history', 'History']].map(tb => ({ id: tb[0], label: tb[1], active: st.tTab === tb[0], fg: st.tTab === tb[0] ? 'var(--tx)' : 'var(--tx2)', line: st.tTab === tb[0] ? 'var(--brand)' : 'transparent', pillBg: st.tTab === tb[0] ? 'var(--sel)' : 'transparent', pillFg: st.tTab === tb[0] ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setState({ tTab: tb[0] }) }));
      const acts: any[] = [];
      if (lf !== 'archived') acts.push({ label: 'Edit', kind: 'ghost', onClick: () => this.openEditTarget(t.id) });
      if (lf === 'ready') acts.push({ label: 'Disable', kind: 'ghost', onClick: () => this.setTargetLife(t.id, 'disabled', 'disabled') });
      if (lf === 'disabled') acts.push({ label: 'Restore', kind: 'primary', onClick: () => this.setTargetLife(t.id, 'ready', 'restored to Ready') });
      if (lf === 'draft' || lf === 'validating') acts.push({ label: 'Run structural validation', kind: 'primary', onClick: () => this.runStructural(t.id) });
      if (lf !== 'archived') acts.push({ label: 'Archive', kind: 'danger', onClick: () => this.setTargetLife(t.id, 'archived', 'archived') });
      const actions = acts.map((a: any) => ({ label: a.label, onClick: a.onClick, bg: a.kind === 'primary' ? 'var(--brand)' : a.kind === 'danger' ? 'var(--v-conf-t)' : 'transparent', fg: a.kind === 'primary' ? '#fff' : a.kind === 'danger' ? 'var(--v-conf)' : 'var(--tx)', bd: a.kind === 'primary' ? 'var(--brand)' : a.kind === 'danger' ? 'var(--v-conf)' : 'var(--bd-2)' }));
      const surfaces = (t.surfaces || []).map((s: any) => ({ id: s.id, name: s.name, typeLabel: SURFT[s.type] || s.type, ver: 'v' + s.ver, locator: s.locator, trust: s.trust, auth: s.auth, risk: s.risk, riskColor: s.risk === 'critical' ? 'var(--v-conf)' : s.risk === 'high' ? 'var(--warn)' : 'var(--tx2)', ow: s.ow, ol: s.ol, cats: s.cats, enabled: s.enabled, enabledLabel: s.enabled ? 'On' : 'Off', enabledColor: s.enabled ? 'var(--phos)' : 'var(--tx3)', validColor: s.valid === 'pass' ? 'var(--v-clear)' : s.valid === 'draft' ? 'var(--tx3)' : 'var(--warn)', validLabel: s.valid === 'pass' ? 'Valid' : s.valid === 'draft' ? 'Draft' : 'Warn', tested: s.tested, onEdit: () => this.openSurface(s.id), onToggle: () => this.toggleSurface(s.id, !s.enabled) }));
      const dr: any = st.surfaceDraft; const SFR = ['low', 'medium', 'high', 'critical']; const SFTR = ['external', 'governed', 'trusted', 'quarantined'];
      const sd = dr ? {
        mode: dr.mode, isCreate: dr.mode === 'create', title: dr.mode === 'create' ? 'New attack surface' : dr.name, id: dr.id || '(assigned on publish)', verLabel: dr.mode === 'create' ? 'v1 (new)' : ('v' + dr.ver + ' → v' + (dr.ver + 1)),
        name: dr.name, locator: dr.locator, auth: dr.auth, ow: dr.ow, ol: dr.ol, cats: dr.cats, enabled: dr.enabled, tested: dr.tested || 'never',
        types: ['endpoint', 'tool', 'rag', 'memory', 'files', 'action'].map(v => ({ v, label: SURFT[v], active: dr.type === v, bg: dr.type === v ? 'var(--sel)' : 'transparent', fg: dr.type === v ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setSurfaceField('type', v) })),
        risks: SFR.map(v => ({ v, active: dr.risk === v, bg: dr.risk === v ? 'var(--sel)' : 'transparent', fg: dr.risk === v ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setSurfaceField('risk', v) })),
        trusts: SFTR.map(v => ({ v, active: dr.trust === v, bg: dr.trust === v ? 'var(--sel)' : 'transparent', fg: dr.trust === v ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setSurfaceField('trust', v) })),
        setName: (e: any) => this.setSurfaceField('name', e.target.value), setLocator: (e: any) => this.setSurfaceField('locator', e.target.value), setAuth: (e: any) => this.setSurfaceField('auth', e.target.value), setOw: (e: any) => this.setSurfaceField('ow', e.target.value), setOl: (e: any) => this.setSurfaceField('ol', e.target.value), setCats: (e: any) => this.setSurfaceField('cats', e.target.value), toggleEnabled: () => this.setSurfaceField('enabled', !dr.enabled),
        publishLabel: dr.mode === 'create' ? 'Create surface' : 'Publish new version', publish: () => this.publishSurface(), cancel: () => this.setState({ surfaceDraft: null }), valid: !!(dr.name && dr.name.trim())
      } : null;
      const audit = (t.audit || []).map((a: any) => ({ t: a[0], who: a[1], ev: a[2] }));
      const det: any = {
        id: t.id, name: t.name, ver: t.ver, env: t.env, adapter: t.adapter, owner: t.owner,
        life: lf, lifeLabel: LIFE[lf].l, lifeColor: LIFE[lf].c, lifeBg: LIFE[lf].bg,
        ready, selectable: ready, eligColor: ready ? 'var(--phos)' : 'var(--v-conf)', eligLabel: ready ? 'Eligible for campaigns' : 'Not ready — ' + (lf === 'ready' ? 'blocked' : LIFE[lf].l),
        allowColor: t.allow === 'active' ? 'var(--v-clear)' : 'var(--warn)', allowLabel: t.allow === 'active' ? 'Active' : 'Pending', cred: t.cred,
        synthColor: t.synth === 'verified' ? 'var(--phos)' : 'var(--v-conf)', synthLabel: t.synth === 'verified' ? 'Verified' : 'Unverified',
        baseUrl: t.baseUrl || '—', hosts: (t.hosts || []), hostCount: (t.hosts || []).length, fixture: t.fixture || '—', canary: t.canary || '—',
        budget: t.budget || '—', rate: t.rate, attemptCap: t.attemptCap || '—', timeout: t.timeout || '—', verified: t.verified,
        structuralLabel: t.structural === 'pass' ? 'Passed' : t.structural === 'pending' ? 'Re-validation required' : 'Failed', structuralColor: t.structural === 'pass' ? 'var(--v-clear)' : 'var(--v-conf)',
        connLabel: probeAuthd ? 'Authorized' : (t.connectivity === 'stale' ? 'Stale — re-authorize' : 'Not authorized'), connColor: probeAuthd ? 'var(--phos)' : 'var(--warn)', probeAuthd,
        canAuthorize: (lf === 'ready' || lf === 'disabled' || lf === 'validating') && !probeAuthd, openAuthProbe: () => this.openAuthProbe(t.id), runStructural: () => this.runStructural(t.id), openEdit: () => this.openEditTarget(t.id),
        hasBlockers: blockers.length > 0, blockers,
        fields: [['Environment', t.env], ['Adapter type', t.adapter], ['Target version', t.ver], ['Base URL', t.baseUrl || '—'], ['Authorization owner', t.owner], ['Last verified', t.verified]].map(function (y: any) { return { k: y[0], v: y[1] }; }),
        allFail: !ready, checks: t.checks.map((c: any) => ({ label: c[0], state: c[1], detail: c[2], color: CK[c[1]].c, icon: CK[c[1]].ic, iconEl: this.svgEl(CK[c[1]].ic, 11, 2.2) })),
        tabOverview: st.tTab === 'overview', tabSurfaces: st.tTab === 'surfaces', tabControls: st.tTab === 'controls', tabCredentials: st.tTab === 'credentials', tabAuthorization: st.tTab === 'authorization', tabHistory: st.tTab === 'history',
        tabs, actions, surfaces, surfaceCount: surfaces.length, noSurfaces: surfaces.length === 0, enabledCount: surfaces.filter((s: any) => s.enabled).length, audit,
        newSurface: () => this.openSurfaceNew()
      };
      const nt: any = st.newT;
      return {
        tList: list, tDet: det, tFilters, tQuery: st.tQuery, onTQuery: (e: any) => this.setState({ tQuery: e.target.value }),
        surfaceEditOpen: !!sd, sDraft: sd || {}, closeSurface: () => this.setState({ surfaceDraft: null }),
        editOpen: !!st.editT, eDraft: st.editT ? {
          id: (st.editT as any).id, name: (st.editT as any).name, ver: (st.editT as any).ver, adapter: (st.editT as any).adapter, env: (st.editT as any).env, baseUrl: (st.editT as any).baseUrl, hosts: (st.editT as any).hosts, cred: (st.editT as any).cred, canary: (st.editT as any).canary, budget: (st.editT as any).budget, rate: (st.editT as any).rate, attemptCap: (st.editT as any).attemptCap, timeout: (st.editT as any).timeout, synthVerified: (st.editT as any).synth === 'verified',
          adapters: ['HTTP/JSON', 'gRPC', 'Browser'].map(a => ({ label: a, active: (st.editT as any).adapter === a, bg: (st.editT as any).adapter === a ? 'var(--sel)' : 'transparent', fg: (st.editT as any).adapter === a ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setEditField('adapter', a) })),
          envs: ['Sandbox', 'Test', 'Staging'].map(v => ({ label: v, active: (st.editT as any).env === v, bg: (st.editT as any).env === v ? 'var(--sel)' : 'transparent', fg: (st.editT as any).env === v ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setEditField('env', v) })),
          setName: (e: any) => this.setEditField('name', e.target.value), setVer: (e: any) => this.setEditField('ver', e.target.value), setBaseUrl: (e: any) => this.setEditField('baseUrl', e.target.value), setHosts: (e: any) => this.setEditField('hosts', e.target.value), setCred: (e: any) => this.setEditField('cred', e.target.value), setCanary: (e: any) => this.setEditField('canary', e.target.value), setBudget: (e: any) => this.setEditField('budget', e.target.value), setRate: (e: any) => this.setEditField('rate', e.target.value), setCap: (e: any) => this.setEditField('attemptCap', e.target.value), setTimeoutV: (e: any) => this.setEditField('timeout', e.target.value), toggleSynth: () => this.setEditField('synth', (st.editT as any).synth === 'verified' ? 'unverified' : 'verified'),
          save: () => this.saveEditTarget(), cancel: () => this.setState({ editT: null })
        } : {},
        authOpen: !!st.authProbe, authDraft: st.authProbe ? { rationale: (st.authProbe as any).rationale, err: (st.authProbe as any).err, launcher: (this.ROLES.find((r: any) => r.isLauncher) || {} as any).name || 'the launcher', principal: this.currentPrincipal().name, target: (store.find((z: any) => z.id === (st.authProbe as any).id) || {} as any).name || '', scope: (store.find((z: any) => z.id === (st.authProbe as any).id) || {} as any).env || '', setRationale: (e: any) => this.setAuthRationale(e), confirm: () => this.confirmAuthProbe(), cancel: () => this.setState({ authProbe: null }) } : {},
        newTargetStart: () => this.newTargetStart(), newTOpen: !!nt, newT: nt || {}, newTStep: nt ? nt.step : 1,
        newTStep1: !!nt && nt.step === 1, newTStep2: !!nt && nt.step === 2, newTStep3: !!nt && nt.step === 3,
        newTName: nt ? nt.name : '', newTVer: nt ? nt.ver : '', newTSynth: !!(nt && nt.synth), newTValid: !!(nt && nt.name && nt.name.trim()),
        newTSetName: (e: any) => this.newTargetSet('name', e.target.value), newTSetVer: (e: any) => this.newTargetSet('ver', e.target.value),
        newTToggleSynth: () => this.newTargetSet('synth', !(nt && nt.synth)),
        newTAdapters: ['HTTP/JSON', 'gRPC', 'Browser'].map(a => ({ label: a, active: !!nt && nt.adapter === a, bg: (!!nt && nt.adapter === a) ? 'var(--sel)' : 'transparent', fg: (!!nt && nt.adapter === a) ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.newTargetSet('adapter', a) })),
        newTEnvs: ['Sandbox', 'Test', 'Staging'].map(v => ({ label: v, active: !!nt && nt.env === v, bg: (!!nt && nt.env === v) ? 'var(--sel)' : 'transparent', fg: (!!nt && nt.env === v) ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.newTargetSet('env', v) })),
        newTNext: () => this.newTargetStep(Math.min(3, (nt ? nt.step : 1) + 1)), newTBack: () => this.newTargetStep(Math.max(1, (nt ? nt.step : 1) - 1)),
        newTNotStep1: !!nt && nt.step > 1, newTNotStep3: !!nt && nt.step < 3,
        newTCancel: () => this.newTargetCancel(), newTCreate: () => this.newTargetCreate(),
        newTBaseUrl: nt ? (nt.baseUrl || '') : '', newTHosts: nt ? (nt.hosts || '') : '', newTCred: nt ? (nt.cred || '') : '',
        newTSetBaseUrl: (e: any) => this.newTargetSet('baseUrl', e.target.value), newTSetHosts: (e: any) => this.newTargetSet('hosts', e.target.value), newTSetCred: (e: any) => this.newTargetSet('cred', e.target.value),
        newTAdapterVal: nt ? nt.adapter : '', newTEnvVal: nt ? nt.env : ''
      };
    } catch (_e: any) { console.log('TVMERR ' + (_e && _e.message) + ' @ ' + ((_e && _e.stack) || '').split('\n').slice(0, 3).join(' | ')); throw _e; }
  }

  setTargetLife(id: string, life: string, label: string) { this._updT(id, (t: any) => { t.life = life; t.audit = [[this.nowT(), this.currentPrincipal().name, 'Target ' + label + '.'], ...t.audit]; return t; }); this.toast('Target ' + label, 'var(--warn)'); }
  runStructural(id: string) { this._updT(id, (t: any) => { t.structural = 'pass'; if (t.life === 'draft') t.life = 'validating'; t.blockers = (t.blockers || []).filter((b: string) => !/structural|base url|allowlist|synthetic|attest/i.test(b)); t.audit = [[this.nowT(), this.currentPrincipal().name, 'Structural validation passed (ValidateTarget · local, no target contact).'], ...t.audit]; return t; }); this.toast('Structural validation passed · local only, target not contacted', 'var(--phos)'); }
  toggleSurface(sid: string, on: boolean) { const selT = this.state.selT; this._updT(selT, (t: any) => { t.surfaces = (t.surfaces || []).map((s: any) => s.id === sid ? Object.assign({}, s, { enabled: on }) : s); t.audit = [[this.nowT(), this.currentPrincipal().name, 'Attack surface ' + sid + ' ' + (on ? 'enabled' : 'disabled') + '.'], ...t.audit]; return t; }); this.toast('Attack surface ' + (on ? 'enabled' : 'disabled'), 'var(--brand)'); }
  openAuthProbe(id: string) { const p = this.currentPrincipal(); if (!p.canApprove) { this.toast('Blocked — authorization requires the Approver permission (' + p.role + ')', 'var(--v-conf)'); return; } if (p.isLauncher) { this.toast('Blocked — two-person rule: the run launcher cannot authorize its own probe', 'var(--v-conf)'); return; } this.setState({ authProbe: { id, rationale: '', err: false } as any }); }
  setAuthRationale(e: any) { const v = e.target.value; this.setState((s: any) => ({ authProbe: { ...(s.authProbe as any), rationale: v, err: false } })); }
  confirmAuthProbe() { const s = this.state; const ap: any = s.authProbe; if (!ap) return; const p = this.currentPrincipal(); const launcher: any = this.ROLES.find((r: any) => r.isLauncher) || {}; if (!p.canApprove || p.isLauncher) { this.setState({ authProbe: null }); this.toast('Blocked — two-person rule not satisfied', 'var(--v-conf)'); return; } if (!ap.rationale.trim()) { this.setState((ss: any) => ({ authProbe: { ...(ss.authProbe as any), err: true } })); return; } const rat = ap.rationale.trim(); this._updT(ap.id, (t: any) => { t.connectivity = 'authorized'; if (t.life === 'validating') t.life = 'ready'; t.verified = 'just now'; t.blockers = (t.blockers || []).filter((b: string) => !/authoriz/i.test(b)); t.audit = [[this.nowT(), p.name, 'Live-probe authorized (TargetProbeAuthorized) · approver ' + p.name + ' ≠ launcher ' + (launcher.name || '?') + ' · scope ' + t.env + ' · rationale: ' + rat], ...t.audit]; return t; }); this.setState({ authProbe: null }); this.toast('Live probe authorized · two-person satisfied · audited', 'var(--phos)'); }
  openEditTarget(id: string) { const t: any = this.state.tStore.find((x: any) => x.id === id); if (!t) return; this.setState({ editT: Object.assign({}, t, { hosts: (t.hosts || []).join(', ') }) }); }
  setEditField(k: string, v: any) { this.setState((s: any) => ({ editT: { ...(s.editT as any), [k]: v } })); }
  saveEditTarget() { const e: any = this.state.editT; if (!e) return; if (!e.name || !e.name.trim()) { this.toast('Display name is required', 'var(--v-conf)'); return; } this._updT(e.id, (t: any) => { const safety = (t.baseUrl !== e.baseUrl) || ((t.hosts || []).join(', ') !== e.hosts) || (t.cred !== e.cred) || (t.adapter !== e.adapter) || (t.env !== e.env); t.name = e.name.trim(); t.ver = e.ver; t.adapter = e.adapter; t.env = e.env; t.baseUrl = e.baseUrl; t.hosts = (e.hosts || '').split(',').map((h: string) => h.trim()).filter(Boolean); t.cred = e.cred; t.canary = e.canary; t.budget = e.budget; t.rate = e.rate; t.attemptCap = e.attemptCap; t.timeout = e.timeout; t.synth = e.synthVerified ? 'verified' : 'unverified'; const au: any[] = [[this.nowT(), this.currentPrincipal().name, 'Target configuration updated (UpdateTarget).']]; if (safety) { t.connectivity = 'unverified'; t.structural = 'pending'; if (t.life === 'ready') t.life = 'validating'; if ((t.blockers || []).join(' ').indexOf('re-authorization') < 0) t.blockers = [...(t.blockers || []), 'Live-probe re-authorization required after config change']; au.unshift([this.nowT(), this.currentPrincipal().name, 'Safety-relevant change — readiness & probe authorization invalidated; re-validation required.']); } t.audit = [...au, ...t.audit]; return t; }); this.setState({ editT: null }); this.toast('Target saved · audited', 'var(--phos)'); }
  openSurfaceNew() { this.setState({ surfaceDraft: { mode: 'create', name: '', type: 'endpoint', locator: '', trust: 'external', auth: 'bearer', risk: 'medium', ow: '—', ol: 'LLM01', cats: '', enabled: true } as any }); }
  openSurface(sid: string) { const t: any = this.state.tStore.find((x: any) => x.id === this.state.selT); const s: any = t && (t.surfaces || []).find((z: any) => z.id === sid); if (!s) return; this.setState({ surfaceDraft: Object.assign({ mode: 'edit' }, s) as any }); }
  setSurfaceField(k: string, v: any) { this.setState((s: any) => ({ surfaceDraft: { ...(s.surfaceDraft as any), [k]: v } })); }
  publishSurface() { const d: any = this.state.surfaceDraft; if (!d) return; if (!d.name || !d.name.trim()) { this.toast('Surface name is required', 'var(--v-conf)'); return; } const selT = this.state.selT; const who = this.currentPrincipal().name; const nm = d.name.trim(); this._updT(selT, (t: any) => { let surfaces = (t.surfaces || []).slice(); let ev; if (d.mode === 'create') { const id = 'sf-' + Math.random().toString(36).slice(2, 7); surfaces = [{ id, name: nm, type: d.type, ver: 1, locator: d.locator, trust: d.trust, auth: d.auth, risk: d.risk, ow: d.ow, ol: d.ol, cats: d.cats, enabled: !!d.enabled, valid: 'pass', tested: 'just now', history: [] }, ...surfaces]; ev = 'Attack surface created — ' + nm + ' v1 (AttackSurfaceVersionPublished).'; } else { const cur: any = surfaces.find((z: any) => z.id === d.id) || { ver: 1 }; const nv = cur.ver + 1; surfaces = surfaces.map((s: any) => { if (s.id !== d.id) return s; const hist = [{ ver: s.ver, name: s.name, type: s.type, risk: s.risk, at: this.nowT() }, ...(s.history || [])]; return { id: s.id, name: nm, type: d.type, ver: nv, locator: d.locator, trust: d.trust, auth: d.auth, risk: d.risk, ow: d.ow, ol: d.ol, cats: d.cats, enabled: !!d.enabled, valid: 'pass', tested: 'just now', history: hist }; }); ev = 'Attack surface ' + nm + ' new version published — v' + nv + ' (AttackSurfaceVersionPublished).'; } t.surfaces = surfaces; t.audit = [[this.nowT(), who, ev], ...t.audit]; return t; }); this.setState({ surfaceDraft: null }); this.toast(d.mode === 'create' ? 'Attack surface created' : 'New surface version published', 'var(--phos)'); }
  newTargetStart() { this.setState({ newT: { step: 1, name: '', ver: 'v0.1.0', adapter: 'HTTP/JSON', env: 'Sandbox', synth: false, baseUrl: '', hosts: '', cred: '' } as any }); }
  newTargetSet(k: string, v: any) { this.setState((s: any) => ({ newT: { ...(s.newT as any), [k]: v } })); }
  newTargetStep(n: number) { this.setState((s: any) => ({ newT: { ...(s.newT as any), step: n } })); }
  newTargetCancel() { this.setState({ newT: null }); }
  newTargetCreate() {
    const n: any = this.state.newT; const who = this.currentPrincipal().name; const id = 'tgt-' + Math.random().toString(36).slice(2, 7); const nm = (n.name || 'Untitled target').trim(); const hosts = (n.hosts || '').split(',').map((h: string) => h.trim()).filter(Boolean); const rec: any = {
      id, name: nm, env: n.env, adapter: n.adapter, ver: n.ver || 'v0.1.0', allow: 'pending', cred: (n.cred && n.cred.trim()) || '—', synth: n.synth ? 'verified' : 'unverified', owner: who, elig: false, active: false,
      checks: [['Allowlist entry', hosts.length ? 'warn' : 'fail', hosts.length ? (hosts.length + ' host(s) set — pending authorization') : 'Base URL / hosts not set'], ['Scoped credential', (n.cred && n.cred.trim()) ? 'warn' : 'fail', (n.cred && n.cred.trim()) ? (n.cred.trim() + ' (reference)') : 'No credential binding'], ['Synthetic-data policy', n.synth ? 'pass' : 'fail', n.synth ? 'Attested synthetic' : 'Not attested'], ['Connectivity', 'fail', 'No successful connection recorded'], ['Budget & rate', 'na', 'Blocked until authorized']],
      life: 'draft', baseUrl: n.baseUrl || '', hosts, budget: '—', rate: '—', attemptCap: 0, timeout: '—', verified: 'never', structural: 'fail', connectivity: 'unverified', fixture: n.synth ? 'attested · provenance pending' : 'not attested', canary: 'n/a',
      blockers: ['Structural validation not yet run', 'Live-probe authorization pending'].concat(n.synth ? [] : ['Synthetic-data policy not attested']),
      surfaces: [], audit: [[this.nowT(), who, 'Target created in DRAFT — ' + nm + ' ' + (n.ver || 'v0.1.0') + ' (CreateTarget).']]
    };
    this.setState((s: any) => ({ tStore: [rec, ...s.tStore], newT: null, selT: id, tTab: 'overview', screen: 'targets' })); this.toast('Target created in DRAFT · added to registry', 'var(--phos)');
  }
  nowT() { const d = new Date(); return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2); }
  selectAgent(id: string) { this.setState({ cfgAgent: id, catalogOpen: false }); }
  openCatalog(forId?: string) { this.setState({ catalogOpen: true, catalogFor: forId || this.state.cfgAgent, catalogQ: '', catalogProv: 'all', catalogSort: 'recency', catalogCompare: [], catalogState: 'ok' }); }
  closeCatalog() { this.setState({ catalogOpen: false }); }
  refreshCatalog() { this.setState({ catalogState: 'loading' }); clearTimeout(this._cat); this._cat = setTimeout(() => this.setState({ catalogState: 'ok' }), 900); }
  cycleCatalogState() { const o = ['ok', 'stale', 'rate-limit', 'provider-error', 'offline']; this.setState((s: any) => ({ catalogState: o[(o.indexOf(s.catalogState) + 1) % o.length] })); }
  toggleCompare(id: string) { this.setState((s: any) => { const c = s.catalogCompare.slice(); const i = c.indexOf(id); if (i >= 0) c.splice(i, 1); else if (c.length < 3) c.push(id); return { catalogCompare: c }; }); }
  pickModel(id: string) { const s = this.state; const a = s.catalogFor; if (!a) return; const patch: any = { agentModel: { ...s.agentModel, [a]: id }, cfgDirty: { ...s.cfgDirty, [a]: true }, catalogOpen: false, cfgPublish: { stage: 'idle', rationale: '', err: false } }; if (a === 'judge') patch.judgeCalib = 'invalidated'; this.setState(patch); this.toast(a === 'judge' ? 'Model staged · Judge calibration invalidated' : 'Model staged · publish to activate on next campaign', 'var(--brand)'); }
  judgeInvalidate() { this.setState((s: any) => ({ cfgDirty: { ...s.cfgDirty, judge: true }, judgeCalib: 'invalidated', cfgPublish: { stage: 'idle', rationale: '', err: false } })); this.toast('Calibration invalidated — non-oracle cases fail closed to INDETERMINATE', 'var(--warn)'); }
  setCfgScope(sc: string) { this.setState({ cfgScope: sc }); }
  setCfgRationale(e: any) { const v = e.target.value; this.setState((s: any) => ({ cfgPublish: { ...s.cfgPublish, rationale: v, err: false } })); }
  cfgValidate() { const s = this.state; if (!s.cfgDirty[s.cfgAgent]) { this.toast('No pending changes to publish', 'var(--tx2)'); return; } if (!s.cfgPublish.rationale.trim()) { this.setState((ss: any) => ({ cfgPublish: { ...ss.cfgPublish, err: true } })); return; } this.setState((ss: any) => ({ cfgPublish: { ...ss.cfgPublish, stage: 'validating', err: false } })); clearTimeout(this._pub); this._pub = setTimeout(() => this.setState((ss: any) => ({ cfgPublish: { ...ss.cfgPublish, stage: 'review' } })), 700); }
  cfgPublish() { const a = this.state.cfgAgent; this.setState((s: any) => ({ cfgPublish: { ...s.cfgPublish, stage: 'published' } })); clearTimeout(this._pub2); this._pub2 = setTimeout(() => { this.setState((s: any) => { const d: any = { ...s.cfgDirty }; delete d[a]; return { cfgDirty: d, cfgPublish: { stage: 'active', rationale: '', err: false }, audit: [{ t: this.nowT(), who: this.currentPrincipal().name, ev: 'Agent configuration published — ' + this.agentName(a) + ' → active on next campaign (AgentConfigurationPublished).' }, ...s.audit] }; }); this.toast((a === 'judge' && this.state.judgeCalib !== 'passing') ? 'Published · Judge still requires a calibration result' : 'Published · active on next campaign only', 'var(--phos)'); }, 500); }
  simulateCalibration(pass: boolean) { const who = this.currentPrincipal().name; if (pass) { this.setState((s: any) => ({ judgeCalib: 'passing', audit: [{ t: this.nowT(), who, ev: 'Judge calibration result acknowledged — PASSING (calibration evidence recorded). Non-oracle dispositions re-enabled.' }, ...s.audit] })); this.toast('Calibration result acknowledged · PASSING', 'var(--phos)'); } else { this.setState((s: any) => ({ judgeCalib: 'invalidated', audit: [{ t: this.nowT(), who, ev: 'Judge calibration result acknowledged — FAILED. Non-oracle cases remain INDETERMINATE.' }, ...s.audit] })); this.toast('Calibration failed · remains uncalibrated', 'var(--v-conf)'); } }
  agentName(id: string) { const a: any = this.AGENTS.find((x: any) => x.id === id); return a ? a.name : id; }
  agentsVM() {
    const st = this.state;
    const ZC: any = { trust: 'var(--tz-trust)', quar: 'var(--tz-quar)', gov: 'var(--tz-gov)', ext: 'var(--tz-ext)', human: 'var(--tz-human)', data: 'var(--tz-data)' };
    const modelById = (id: string) => this.MODEL_CATALOG.find((x: any) => x.id === id) || null;
    const mName = (id: string) => { const m: any = modelById(id); return m ? m.name : id; };
    const agentList = this.AGENTS.map((a: any) => ({ id: a.id, name: a.name, role: a.role, zoneColor: ZC[a.zone], model: mName(st.agentModel[a.id]), dirty: !!st.cfgDirty[a.id], uncal: a.id === 'judge' && st.judgeCalib !== 'passing', active: a.id === st.cfgAgent, bg: a.id === st.cfgAgent ? 'var(--sel)' : 'transparent', line: a.id === st.cfgAgent ? 'var(--brand)' : 'transparent', onClick: () => this.selectAgent(a.id), mOnClick: () => this.openMAgent(a.id), openCat: () => this.openCatalog(a.id) }));
    const detComps = this.DETERMINISTIC.map((d: any) => ({ name: d.name, why: d.why }));
    const a: any = this.AGENTS.find((x: any) => x.id === st.cfgAgent) || this.AGENTS[0];
    const cfg: any = this.AGENTCFG[a.id] || {};
    const curModel: any = modelById(st.agentModel[a.id]);
    const dirty = !!st.cfgDirty[a.id];
    let params: any[] = [];
    if (a.id === 'judge') { params = [['Confidence threshold', cfg.threshold], ['Human-review threshold', cfg.humanReview], ['Rubric version', cfg.rubric], ['Calibration', st.judgeCalib === 'passing' ? 'Passing' : st.judgeCalib === 'recalibrating' ? 'Recalibrating…' : 'Invalidated'], ['Last calibration', cfg.calibDate], ['Drift status', cfg.drift]]; }
    else if (a.id === 'rt') { params = [['Temperature', cfg.temp], ['Mutation strategy', cfg.mutation], ['Max attempts', cfg.maxAttempts], ['Per-attempt budget', '$' + cfg.perAttempt.toFixed(2)], ['Per-campaign budget', '$' + cfg.perCampaign.toFixed(2)], ['Allowed categories', cfg.cats]]; }
    else if (a.id === 'doc') { params = [['Output template', cfg.template], ['Citation/evidence', cfg.citation], ['Publication policy', cfg.publication], ['Redaction policy', cfg.redaction]]; }
    else { params = [['Planning policy', cfg.planning], ['Tool permissions', cfg.tools], ['Max delegation depth', cfg.delegation], ['Runtime budget', cfg.budget]]; }
    params = params.map((p: any) => ({ k: p[0], v: String(p[1]) }));
    const judgeInvalid = a.id === 'judge' && st.judgeCalib !== 'passing';
    const fallback = (a.id === 'rt') ? (cfg.fallback || []).map((f: string, i: number) => ({ ord: i + 1, name: mName(f) })) : [];
    const scopes = [['workspace', 'Workspace default'], ['target', 'Target override'], ['campaign', 'Campaign override']].map(s => ({ id: s[0], label: s[1], active: st.cfgScope === s[0], bg: st.cfgScope === s[0] ? 'var(--sel)' : 'transparent', fg: st.cfgScope === s[0] ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setCfgScope(s[0]) }));
    const effRows = (a.id === 'judge') ? [
      { k: 'Confidence threshold', ws: '0.72', tg: '0.72 (inherited)', cp: '0.72 (snapshot)', eff: '0.72', lock: 'Campaign snapshot is immutable' },
      { k: 'Human-review threshold', ws: '0.55', tg: '0.55 (inherited)', cp: '0.55', eff: '0.55', lock: '' },
      { k: 'Max attempts / campaign', ws: '400', tg: '400', cp: '400', eff: '400', lock: 'Server safety cap: 1000' }
    ] : [
      { k: 'Per-campaign budget', ws: '$12.00', tg: '$12.00 (inherited)', cp: '$12.00 (snapshot)', eff: '$12.00', lock: 'Server safety cap: $48' },
      { k: 'Max attempts / campaign', ws: '400', tg: '400', cp: '400', eff: '400', lock: 'Server safety cap: 1000' }
    ];
    const pub = st.cfgPublish;
    const aDet: any = {
      id: a.id, name: a.name, role: a.role, zoneColor: ZC[a.zone], dirty,
      modelId: st.agentModel[a.id], modelName: curModel ? curModel.name : st.agentModel[a.id], modelProvider: curModel ? curModel.provider : '—', modelCtx: curModel ? (curModel.ctx >= 1000000 ? (curModel.ctx / 1000000) + 'M' : (curModel.ctx / 1000) + 'K') : '—', modelIn: curModel ? ('$' + curModel.inP.toFixed(2)) : '—', modelOut: curModel ? ('$' + curModel.outP.toFixed(2)) : '—', modelParams: curModel ? curModel.params.join(' · ') : '—',
      openCatalog: () => this.openCatalog(a.id), params, isJudge: a.id === 'judge', isRt: a.id === 'rt', judgeInvalid, calibState: st.judgeCalib, calibLabel: (st.judgeCalib === 'passing' ? 'Passing' : st.judgeCalib === 'recalibrating' ? 'Recalibrating…' : 'Recalibration required'), calibPass: () => this.simulateCalibration(true), calibFail: () => this.simulateCalibration(false), calibColor: (st.judgeCalib === 'passing' ? 'var(--phos)' : st.judgeCalib === 'recalibrating' ? 'var(--tz-data)' : 'var(--warn)'), fallback, hasFallback: fallback.length > 0, judgeInvalidate: () => this.judgeInvalidate(),
      scopes, effRows,
      pubStage: pub.stage, pubIdle: pub.stage === 'idle', pubValidating: pub.stage === 'validating', pubReview: pub.stage === 'review', pubPublished: pub.stage === 'published', pubActive: pub.stage === 'active',
      pubRationale: pub.rationale, pubErr: pub.err, onRationale: (e: any) => this.setCfgRationale(e), validate: () => this.cfgValidate(), publish: () => this.cfgPublish(),
      canPublish: dirty, noPublish: !dirty
    };
    // model catalog
    const AV: any = { available: { l: 'Available', c: 'var(--phos)' }, cached: { l: 'Cached', c: 'var(--tz-data)' }, deprecated: { l: 'Deprecated', c: 'var(--warn)' }, unverified: { l: 'Unverified', c: 'var(--warn)' }, unavailable: { l: 'Unavailable', c: 'var(--v-conf)' } };
    const cq = st.catalogQ.trim().toLowerCase();
    let cat = this.MODEL_CATALOG.filter((m: any) => { if (cq && m.name.toLowerCase().indexOf(cq) < 0 && m.id.toLowerCase().indexOf(cq) < 0) return false; if (st.catalogProv !== 'all' && m.provider !== st.catalogProv) return false; return true; });
    const SORT: any = { recency: (x: any, y: any) => y.recency - x.recency, price: (x: any, y: any) => x.inP - y.inP, context: (x: any, y: any) => y.ctx - x.ctx, name: (x: any, y: any) => x.name.localeCompare(y.name) };
    cat = cat.slice().sort(SORT[st.catalogSort] || SORT.recency);
    const catRows = cat.map((m: any) => ({ id: m.id, name: m.name, provider: m.provider, ctx: (m.ctx >= 1000000 ? (m.ctx / 1000000) + 'M' : (m.ctx / 1000) + 'K'), mods: m.mods.join(' · '), params: m.params.length, inP: '$' + m.inP.toFixed(2), outP: '$' + m.outP.toFixed(2), availLabel: AV[m.avail].l, availColor: AV[m.avail].c, selectable: (m.avail !== 'unavailable' && m.avail !== 'deprecated'), current: st.agentModel[st.catalogFor as any] === m.id, inCompare: st.catalogCompare.indexOf(m.id) >= 0, onPick: () => { if (m.avail !== 'unavailable' && m.avail !== 'deprecated') this.pickModel(m.id); else this.toast('Cannot select an unavailable/deprecated model — no silent substitution', 'var(--v-conf)'); }, onCompare: () => this.toggleCompare(m.id) }));
    const providers = ['all'].concat(Array.from(new Set(this.MODEL_CATALOG.map((m: any) => m.provider)))).map(p => ({ id: p, label: p === 'all' ? 'All providers' : p, active: st.catalogProv === p, bg: st.catalogProv === p ? 'var(--sel)' : 'transparent', fg: st.catalogProv === p ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setState({ catalogProv: p }) }));
    const sorts = [['recency', 'Recency'], ['price', 'Price'], ['context', 'Context'], ['name', 'Name']].map(s => ({ id: s[0], label: s[1], active: st.catalogSort === s[0], bg: st.catalogSort === s[0] ? 'var(--sel)' : 'transparent', fg: st.catalogSort === s[0] ? 'var(--brand)' : 'var(--tx2)', onClick: () => this.setState({ catalogSort: s[0] }) }));
    const compareRows = st.catalogCompare.map((id: string) => modelById(id)).filter(Boolean).map((m: any) => ({ name: m.name, ctx: (m.ctx >= 1000000 ? (m.ctx / 1000000) + 'M' : (m.ctx / 1000) + 'K'), inP: '$' + m.inP.toFixed(2), outP: '$' + m.outP.toFixed(2), avail: AV[m.avail].l, availColor: AV[m.avail].c }));
    const cs = st.catalogState;
    const catInfo: any = {
      open: st.catalogOpen, forName: this.agentName((st.catalogFor as any) || a.id), count: catRows.length, rows: catRows, providers, sorts, q: st.catalogQ, onQ: (e: any) => this.setState({ catalogQ: e.target.value }),
      compare: compareRows, compareN: st.catalogCompare.length, hasCompare: st.catalogCompare.length > 0,
      state: cs, ok: cs === 'ok', loading: cs === 'loading', stale: cs === 'stale', rate: cs === 'rate-limit', err: cs === 'provider-error', offline: cs === 'offline', notOk: cs !== 'ok', showRows: (cs === 'ok' || cs === 'stale' || cs === 'offline'), banner: (cs !== 'ok' && cs !== 'loading'), bannerText: (cs === 'stale' ? 'Showing cached catalog — refresh to update' : cs === 'offline' ? 'Offline — showing last cached catalog' : cs === 'rate-limit' ? 'OpenRouter rate limit reached — retry shortly' : cs === 'provider-error' ? 'Provider error — cached results may be stale' : ''), bannerColor: (cs === 'rate-limit' || cs === 'provider-error') ? 'var(--v-conf)' : 'var(--warn)',
      freshLabel: cs === 'stale' ? 'Cached 14m ago · stale' : cs === 'offline' ? 'Offline — last cache' : 'Fresh · updated 20s ago',
      refresh: () => this.refreshCatalog(), cycleState: () => this.cycleCatalogState(), close: () => this.closeCatalog()
    };
    return { agentList, detComps, aDet, catInfo };
  }
  tracesVM() {
    const st = this.state; const T: any = this.TRACE; const total = T.totalMs;
    const ZC: any = { trust: 'var(--tz-trust)', quar: 'var(--tz-quar)', gov: 'var(--tz-gov)', ext: 'var(--tz-ext)', human: 'var(--tz-human)' };
    const ZL: any = { trust: 'Trusted control', quar: 'Quarantined', gov: 'Governed', ext: 'External target', human: 'Human gate' };
    const SS: any = { ok: { c: 'var(--v-clear)', l: 'OK' }, hit: { c: 'var(--phos)', l: 'Oracle hit' }, skip: { c: 'var(--tx3)', l: 'Skipped' }, wait: { c: 'var(--warn)', l: 'Waiting' }, error: { c: 'var(--v-err)', l: 'Error' } };
    const spans = T.spans.map((s: any) => ({
      id: s.id, label: s.label, agent: s.agent, corr: s.corr,
      left: (s.start / total * 100) + '%', width: Math.max(1.4, (s.dur / total * 100)) + '%', zoneColor: ZC[s.zone],
      dur: (s.dur >= 1000 ? (s.dur / 1000).toFixed(2) + 's' : s.dur + 'ms'), statusColor: SS[s.status].c,
      onClick: () => this.setSpan(s.id), rowBg: s.id === st.selSpan ? 'var(--sel)' : 'transparent', rowLine: s.id === st.selSpan ? 'var(--sel-line)' : 'transparent'
    }));
    const raw: any = T.spans.find((s: any) => s.id === st.selSpan) || T.spans[0];
    const sp = {
      label: raw.label, agent: raw.agent, model: raw.model, zoneColor: ZC[raw.zone], zoneLabel: ZL[raw.zone], desc: raw.desc,
      start: raw.start + ' ms', end: (raw.start + raw.dur) + ' ms', dur: (raw.dur >= 1000 ? (raw.dur / 1000).toFixed(2) + ' s' : raw.dur + ' ms'),
      tokens: raw.tokens, cost: '$' + raw.cost.toFixed(3), corr: raw.corr, statusColor: SS[raw.status].c, statusLabel: SS[raw.status].l
    };
    const ticks = [0, 1, 2, 3, 4].map(n => ({ label: n + 's', left: (n * 1000 / total * 100) + '%' }));
    return { trHeader: { run: T.run, attempt: T.attempt, trace: T.trace, total: (total / 1000).toFixed(2) + ' s' }, trSpans: spans, trTicks: ticks, trSel: sp };
  }
  coverageVM() {
    const CS: any = { tested: { label: 'Tested', color: 'var(--v-clear)', bg: 'var(--v-clear-t)' }, partial: { label: 'Partial', color: 'var(--tz-data)', bg: 'rgba(90,143,216,.13)' }, untested: { label: 'Untested', color: 'var(--warn)', bg: 'var(--warn-t)' }, na: { label: 'N/A', color: 'var(--tx3)', bg: 'transparent' } };
    const EV: any = { high: 3, med: 2, low: 1, none: 0 };
    const rows = this.COVERAGE.map((c: any) => ({
      tag: c.tag, fam: c.fam, name: c.name, stLabel: CS[c.state].label, stColor: CS[c.state].color, stBg: CS[c.state].bg,
      cases: c.cases, rate: (c.rate == null ? '—' : Math.round(c.rate * 100) + '%'), rateW: (c.rate == null ? 0 : Math.round(c.rate * 100)) + '%', hasRate: c.rate != null,
      ver: c.ver, ev1c: EV[c.ev] >= 1 ? 'var(--tx2)' : 'var(--bd)', ev2c: EV[c.ev] >= 2 ? 'var(--tx2)' : 'var(--bd)', ev3c: EV[c.ev] >= 3 ? 'var(--tx2)' : 'var(--bd)', isGap: c.state === 'untested', rowBg: c.state === 'untested' ? 'var(--warn-t)' : 'transparent'
    }));
    return { covRows: rows, covTested: this.COVERAGE.filter((c: any) => c.state === 'tested').length, covPartial: this.COVERAGE.filter((c: any) => c.state === 'partial').length, covUntested: this.COVERAGE.filter((c: any) => c.state === 'untested').length, covTotal: this.COVERAGE.length };
  }
  resilienceVM() {
    const R: any = this.RESILIENCE; const maxRate = 0.30;
    const NK: any = { incident: { c: 'var(--v-conf)', l: 'Incident' }, fix: { c: 'var(--v-clear)', l: 'Fix' }, deploy: { c: 'var(--tz-data)', l: 'Deploy' } };
    const versions = R.versions.map((v: any) => ({
      v: v.v, conf: Math.round(v.conf * 100) + '%', likely: Math.round(v.likely * 100) + '%',
      confH: (v.conf / maxRate * 100) + '%', likelyH: (v.likely / maxRate * 100) + '%', n: v.n, nColor: v.n < 120 ? 'var(--warn)' : 'var(--tx3)',
      note: v.note ? v.note.t : '', noteColor: v.note ? NK[v.note.k].c : 'transparent', noteLabel: v.note ? NK[v.note.k].l : '', hasNote: !!v.note
    }));
    const cats = R.cats.map((c: any) => {
      const imp = c.now < c.prev; return {
        name: c.name, prev: Math.round(c.prev * 100) + '%', now: Math.round(c.now * 100) + '%',
        delta: (imp ? '↓' : '↑') + ' ' + Math.abs(Math.round((c.now - c.prev) * 100)) + ' pts', deltaColor: imp ? 'var(--v-clear)' : 'var(--v-conf)',
        confLabel: c.conf === 'ok' ? 'n=' + c.n : c.conf === 'low' ? 'n=' + c.n + ' · low confidence' : 'n=' + c.n + ' · limited', confColor: c.conf === 'ok' ? 'var(--tx3)' : 'var(--warn)'
      };
    });
    return { resVersions: versions, resCats: cats };
  }
  costsVM() {
    const C: any = this.COSTS; const b = this.state.budget; const pct = Math.round((b.used / b.cap) * 1000) / 10;
    const maxA = Math.max.apply(null, C.byAgent.map((a: any) => a.v)); const maxM = Math.max.apply(null, C.byModel.map((m: any) => m.v));
    return {
      coState: pct >= 80 ? 'Approaching cap' : 'Nominal', coStateColor: pct >= 80 ? 'var(--warn)' : 'var(--v-clear)',
      coUsed: this.fmt2(b.used), coCap: this.fmt2(b.cap), coPct: pct + '%', coBurn: this.fmt2(b.burn), coProj: '2h 41m', coBudgetColor: pct >= 80 ? 'var(--warn)' : 'var(--brand)',
      coAgents: C.byAgent.map((a: any) => ({ k: a.k, v: this.fmt2(a.v), w: (a.v / maxA * 100) + '%', c: a.c })),
      coModels: C.byModel.map((m: any) => ({ k: m.k, v: this.fmt2(m.v), w: (m.v / maxM * 100) + '%' })),
      coCached: C.cachedPct + '%', coBatch: C.batchPct + '%', coHosted: C.hostedPct + '%', coRetry: this.fmt2(C.retry), coLow: this.fmt2(C.lowSignal)
    };
  }

  selectNode(id: string) { this.setState((s: any) => ({ beNode: s.beNode === id ? null : id })); }
  closeNode() { this.setState({ beNode: null }); }
  _ensureSheetRef() { if (!this._sheetRef) this._sheetRef = React.createRef(); return this._sheetRef; }
  _rubber(x: number) { return x / (1 + x / 60); }
  _dragStart(e: any) { const stg = this.state.decisionStage; if (stg !== 'form' && stg !== 'done' && stg !== 'error') return; const el = this._sheetRef && this._sheetRef.current; if (!el) return; try { e.currentTarget.setPointerCapture(e.pointerId); } catch (_) { } el.style.transition = 'none'; this._drag = { sy: e.clientY, dy: 0, ly: e.clientY, lt: Date.now(), v: 0 }; }
  _dragMove(e: any) { const d = this._drag; if (!d) return; let dy = e.clientY - d.sy; if (dy < 0) dy = -this._rubber(-dy); const now = Date.now(); if (now > d.lt) { d.v = (e.clientY - d.ly) / (now - d.lt); d.ly = e.clientY; d.lt = now; } d.dy = dy; const el = this._sheetRef.current; if (el) el.style.transform = 'translateY(' + dy + 'px)'; }
  _dragEnd(_e?: any) { const d = this._drag; this._drag = null; const el = this._sheetRef && this._sheetRef.current; if (!d || !el) return; el.style.transition = 'transform .32s var(--ease-drawer)'; if (d.dy > 90 || d.v > 0.5) { el.style.transform = 'translateY(110%)'; const stg = this.state.decisionStage; setTimeout(() => { if (stg === 'done') this.closeDecision(); else this.cancelDecision(); }, 210); } else { el.style.transform = 'translateY(0)'; } }
  svgEl(d: string, w?: number, sw?: number) { return React.createElement('svg', { viewBox: '0 0 24 24', width: w || 16, height: w || 16, fill: 'none', stroke: 'currentColor', strokeWidth: sw || 1.8, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': 'true' }, React.createElement('path', { d: d })); }
  focusActive() { const a: any = this.state.attempts.find((x: any) => x.st < 5) || this.state.attempts[0]; if (a) this.setState({ liveMode: 'stream', selA: a.id, inspectorTab: 'attempt' }); }
  openFindingAny(id: string) { this.setState({ screen: 'findings', selF: id, fTab: 'overview', mView: 'finding', beNode: null, palOpen: false }); }
  toggleMPhase(id: string) { this.setState((s: any) => ({ beMPhase: s.beMPhase === id ? null : id })); }
  birdseyeVM() {
    const st = this.state, running = st.campaignState === 'running', aborted = st.campaignState === 'aborted';
    const integ = st.scenario === 'integration';
    const AVAIL: any = {
      internal: { short: 'Internal', label: 'Implemented · internal', color: 'var(--info)', detail: 'Implemented in the platform; no console telemetry projection yet.' },
      partial: { short: 'Partial', label: 'Partial', color: 'var(--warn)', detail: 'Trusted boundary / preflight exists; live execution path incomplete.' },
      mvp: { short: 'Det. MVP', label: 'Deterministic MVP', color: 'var(--info)', detail: 'Deterministic fail-closed authority only; LLM evaluator / calibration path unavailable.' },
      prototype: { short: 'UI only', label: 'Prototype UI only', color: 'var(--v-indet)', detail: 'Prototype UI; backend service pending.' },
      unauthorized: { short: 'Not authorized', label: 'Live exec not authorized', color: 'var(--warn)', detail: 'External target; no authorized live campaign has produced results.' },
      unavailable: { short: 'Unavailable', label: 'Unavailable', color: 'var(--tx3)', detail: 'Not implemented / not registered — cannot presently operate.' },
    };
    const ZC: any = { trust: 'var(--tz-trust)', quar: 'var(--tz-quar)', gov: 'var(--tz-gov)', ext: 'var(--tz-ext)', human: 'var(--tz-human)', data: 'var(--tz-data)' };
    const ZL: any = { trust: 'Trusted', quar: 'Quarantined', gov: 'Governed', ext: 'External', human: 'Human gate', data: 'Data plane' };
    const SC: any = { working: { c: 'var(--phos)', l: 'Working' }, ready: { c: 'var(--v-clear)', l: 'Ready' }, idle: { c: 'var(--tx3)', l: 'Idle' }, waiting: { c: 'var(--warn)', l: 'Waiting' }, queued: { c: 'var(--brand)', l: 'Queued' }, draining: { c: 'var(--warn)', l: 'Draining' }, degraded: { c: 'var(--warn)', l: 'Degraded' }, error: { c: 'var(--v-err)', l: 'Error' }, stale: { c: 'var(--tx3)', l: 'Stale' }, disconnected: { c: 'var(--v-err)', l: 'Disconnected' }, terminated: { c: 'var(--tx3)', l: 'Terminated' } };
    const SIC: any = { working: this.ic.live, ready: this.ic.check, idle: 'M6 12h12', waiting: this.ic.clock, queued: 'M4 7h16 M4 12h16 M4 17h10', draining: 'M12 5v14 M6 13l6 6 6-6', degraded: 'M12 3l9 16H3z M12 10v4 M12 17h.01', error: 'M8.5 3h7l5 5v7l-5 5h-7l-5-5V8z M9.5 9.5l5 5 M14.5 9.5l-5 5', stale: this.ic.clock, disconnected: 'M4 4l16 16 M9 9a3 3 0 0 0-1 5 M15 15a3 3 0 0 0 1-5', terminated: 'M6 6h12v12H6z' };
    const TI: any = { agent: 'M13 3L4 14h7l-1 7 9-11h-7z', service: 'M4 7l8-4 8 4v10l-8 4-8-4z M4 7l8 4 8-4 M12 11v10', external: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M3 12h18 M12 3c2.4 2.6 2.4 15.4 0 18 M12 3c-2.4 2.6-2.4 15.4 0 18', human: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M5 20a7 7 0 0 1 14 0' };
    const PURP: any = { orch: 'Reads observability, prioritizes the next campaign, governs cost and abort.', rt: 'Generates and mutates adversarial inputs. Untrusted — no target credentials, no direct target path, no evidence write.', pol: 'The trusted enforcement boundary: allowlist, scoped credentials, synthetic-data, budget/rate caps, hard abort.', tgt: 'Trusted transport inside the Gateway/Recorder boundary. Holds the target-scoped credential (reference only) and invokes the pluggable adapter — never a decision-maker.', ext: 'The external target under test, reached only through the connector. Untrusted boundary; no credential, no evidence authority. Live execution is not yet authorized.', rec: 'Executes the authorized attempt and records the canonical, append-only, content-hashed AttemptResult.', judge: 'Independent evaluator — renders verdicts from recorder evidence only; cannot downgrade an oracle hit.', doc: 'Turns confirmed findings into reproducible reports; gated on human approval for critical publish.', reg: 'Deterministic replay of confirmed exploits; admits only passes-for-the-right-reason.', human: 'Mandatory human approval for critical publication and any remediation.', pg: 'Postgres source of record — exploit DB, checkpoints, and the SKIP LOCKED work queue.', queue: 'At-least-once work queue with lease/heartbeat/reaper and dead-letter.', obs: 'Observability layer — watches the system; never a verdict authority.' };
    const DET: any = {
      orch: { ep: ['orchestrator.internal:7100 · gRPC'], hb: '1s ago', succ: '99.6%', p50: '190ms', p95: '320ms', errs: [], att: ['A-0187', 'A-0186'], tr: ['T-4471'], find: [], cred: 'Control-plane role · holds no target credentials' },
      rt: { ep: ['rt-pool://gen-1', 'rt-pool://gen-2', 'rt-pool://gen-3'], hb: '0s ago', succ: '—', p50: '560ms', p95: '980ms', errs: ['gen-2 · 1 retry (rate limit)'], att: ['A-0187'], tr: ['T-4470'], find: [], cred: 'Untrusted zone · no credentials, no target path, no evidence write' },
      pol: { ep: ['policy-gateway.internal:7005'], hb: '0s ago', succ: '100%', p50: '12ms', p95: '21ms', errs: [], att: ['A-0187', 'A-0185'], tr: [], find: [], cred: 'Holds scoped target credential — reference only, value never shown' },
      tgt: { ep: ['policy-gateway.internal → adapter: http-json'], hb: '0s ago', succ: '100%', p50: '12ms', p95: '21ms', errs: [], att: ['A-0187', 'A-0185'], tr: ['T-4468'], find: [], cred: 'Holds scoped target credential — reference only, value never shown' },
      ext: { ep: ['https://atlas-support.staging.internal/v1'], hb: '0s ago', succ: '98.1%', p50: '1.6s', p95: '2.4s', errs: ['1× target-unreachable (A-0182)'], att: ['A-0187', 'A-0182'], tr: ['T-4468'], find: [], cred: 'External target · allowlisted · synthetic tenant only · live execution not authorized' },
      rec: { ep: ['recorder.internal:7200 (×2)'], hb: '0s ago', succ: '100%', p50: '34ms', p95: '60ms', errs: ['1× hash mismatch parked (A-0177)'], att: ['A-0185', 'A-0177'], tr: ['T-4467'], find: ['F-1042'], cred: 'Append-only writer · content-hashing' },
      judge: { ep: ['judge.internal:7300 (×2)'], hb: '2s ago', succ: '97.0%', p50: '2.1s', p95: '3.3s', errs: ['1× judge-timeout (A-0178)'], att: ['A-0185', 'A-0183'], tr: ['T-4466'], find: ['F-1042', 'F-1051'], cred: 'Reads recorder evidence only · cannot reach target' },
      doc: { ep: ['documentation.internal:7400'], hb: '8s ago', succ: '100%', p50: '—', p95: '—', errs: [], att: ['A-0185'], tr: [], find: ['F-1042'], cred: 'Publishes only on human approval' },
      reg: { ep: ['regression.internal:7450'], hb: '12m ago', succ: '100%', p50: '—', p95: '—', errs: [], att: [], tr: [], find: ['F-1039'], cred: 'Deterministic replay harness' },
      human: { ep: ['—'], hb: '14m ago', succ: '—', p50: '—', p95: '—', errs: [], att: ['A-0185'], tr: [], find: ['F-1042'], cred: 'Human approver · two-person rule enforced' },
      pg: { ep: ['pg-primary:5432', 'pg-replica:5432'], hb: '0s ago', succ: '100%', p50: '3ms', p95: '8ms', errs: [], att: [], tr: [], find: [], cred: 'Source of record' },
      queue: { ep: ['SKIP LOCKED lease queue'], hb: '0s ago', succ: '—', p50: '—', p95: '—', errs: [], att: [], tr: [], find: [], cred: 'Lease + heartbeat + reaper + dead-letter' },
      obs: { ep: ['langfuse.internal:3000'], hb: '22s ago', succ: '—', p50: '—', p95: '—', errs: ['Ingest delayed 22s (Postgres authoritative)'], att: [], tr: ['T-4466'], find: [], cred: 'Non-authoritative telemetry' },
    };
    const map = (c: any) => {
      const av = AVAIL[c.avail] || AVAIL.internal; let state = c.state; if (!running && (state === 'working' || state === 'waiting' || state === 'queued')) state = (aborted ? 'terminated' : 'idle'); if (integ) state = 'av'; const meta = integ ? { c: av.color, l: av.short } : (SC[state] || SC.idle); const n = c.inst.total; const d = DET[c.id] || {};
      const metric = integ ? { k: '', v: av.label } : ((c.q > 0) ? { k: 'Queue', v: String(c.q) } : (c.lat && c.lat !== '—') ? { k: 'p50', v: c.lat } : { k: 'Seen', v: c.fresh });
      return {
        id: c.id, name: c.name, type: c.type, typeIconEl: this.svgEl(TI[c.type], 14, 1.7),
        zone: c.zone, zoneColor: ZC[c.zone], zoneLabel: ZL[c.zone],
        state, stateColor: meta.c, stateLabel: meta.l, stateIconEl: this.svgEl(SIC[state] || SIC.idle, 11, (state === 'ready' || state === 'working') ? 2 : 1.9),
        task: integ ? av.detail : (running ? c.task : (aborted ? 'Stopped · campaign aborted' : 'Idle · standby')),
        cluster: !integ && n > 1, healthy: c.inst.healthy, total: n, working: c.inst.working || 0, idleN: c.inst.idle || 0, degradedN: c.inst.degraded || 0,
        fresh: c.fresh, lat: c.lat, q: c.q, metricK: metric.k, metricV: metric.v,
        onClick: () => this.selectNode(c.id), selected: st.beNode === c.id, availLabel: av.label, availColor: av.color, availShort: av.short,
        cardBg: st.beNode === c.id ? 'var(--sel)' : 'var(--bg-app)', cardBd: st.beNode === c.id ? 'var(--sel-line)' : 'var(--bd)',
        model: (this.state.agentModel && this.state.agentModel[c.id]) || c.model, hasModel: !!(((this.state.agentModel && this.state.agentModel[c.id]) || c.model) && (((this.state.agentModel && this.state.agentModel[c.id]) || c.model) !== '—' && ((this.state.agentModel && this.state.agentModel[c.id]) || c.model) !== 'deterministic')), uncal: (c.id === 'judge' && this.state.judgeCalib !== 'passing'), uncalLabel: (this.state.judgeCalib === 'recalibrating' ? 'Recalibrating… — non-oracle cases fail closed to INDETERMINATE' : 'Uncalibrated — non-oracle cases fail closed to INDETERMINATE'), purpose: PURP[c.id] || '',
        ep: integ ? [av.detail] : (d.ep || []), hasEp: integ ? true : !!(d.ep && d.ep.length), hb: integ ? '—' : (d.hb || c.fresh), succ: integ ? '—' : (d.succ || '—'), p50: integ ? 'no projection' : (d.p50 || c.lat || '—'), p95: integ ? '—' : (d.p95 || '—'),
        errs: (integ ? [] : (d.errs || [])), hasErrs: integ ? false : !!(d.errs && d.errs.length),
        relAtt: (d.att || []).map((id: string) => ({ id, onClick: () => this.setState({ screen: 'live', liveMode: 'stream', selA: id, inspectorTab: 'attempt', mView: 'attempt' }) })),
        relTr: (d.tr || []).map((id: string) => ({ id, onClick: () => this.go('traces') })),
        relFind: (d.find || []).map((id: string) => ({ id, onClick: () => this.openFindingAny(id) })),
        hasRel: ((d.att || []).length + (d.tr || []).length + (d.find || []).length) > 0, cred: d.cred || '—'
      };
    };
    const byId: any = {}; this.COMPONENTS.forEach((c: any) => byId[c.id] = c); const N = (id: string) => map(byId[id]);
    const zdef = [
      { ids: ['orch'], label: 'Trusted control', edge: 'CampaignDirective' },
      { ids: ['rt'], label: 'Untrusted generation', edge: 'AttackAttempt' },
      { ids: ['pol'], label: 'Enforcement boundary', edge: 'PolicyDecision · TargetRequest' },
      { ids: ['tgt', 'ext'], label: 'Trusted execution · connector → external target', edge: 'TargetResponse' },
      { ids: ['rec'], label: 'Trusted evidence', edge: 'AttemptResult · Evidence' },
      { ids: ['judge'], label: 'Independent evaluation', edge: 'Verdict' },
      { ids: ['doc', 'reg', 'human'], label: 'Outcomes · human governance', edge: '' },
    ];
    const inprog: any = st.attempts.find((a: any) => a.st < 5); const s2z: any = { 0: 1, 1: 2, 2: 3, 3: 4, 4: 5, 5: 6 };
    const activeZ = (running && inprog) ? (s2z[inprog.st] != null ? s2z[inprog.st] : 2) : -1;
    const followId = st.beFollow && st.attempts[0] ? st.attempts[0].id : '';
    const bePipeline = zdef.map((z, i) => {
      const active = running && activeZ === i; const pulse = active && st.beFollow; return {
        idx: (i + 1 < 10 ? '0' : '') + (i + 1), label: z.label, color: ZC[byId[z.ids[0]].zone], branch: z.ids.length > 1, nodesCols: z.ids.length > 1 ? 'repeat(' + z.ids.length + ',minmax(0,1fr))' : 'minmax(0,1fr)', nodes: z.ids.map(N),
        active, pulse, bandBd: pulse ? 'var(--phos)' : 'var(--bd)', bandShadow: pulse ? '0 0 0 1px var(--phos-tint)' : 'none',
        hasConn: i > 0, connLabel: i > 0 ? zdef[i - 1].edge : '', hasConnLabel: i > 0 && !!zdef[i - 1].edge, connActive: active, connColor: active ? 'var(--phos)' : 'var(--bd-2)', connAttempt: active ? followId : '', connHasAttempt: active && !!followId
      };
    });
    const services = this.COMPONENTS.filter((c: any) => c.stage < 0).map((c: any) => N(c.id));
    const SUP: any = { pg: 'Backs Recorder, Queue & Regression', queue: 'Feeds Policy Gateway → Target', obs: 'Watches all · non-authoritative' };
    services.forEach((s: any) => { s.supports = SUP[s.id] || ''; });
    const live = this.COMPONENTS.filter((c: any) => c.state !== 'terminated').reduce((a: number, c: any) => a + c.inst.total, 0);
    const degraded = this.COMPONENTS.some((c: any) => c.state === 'degraded');
    const totalInst = this.COMPONENTS.reduce((a: number, c: any) => a + c.inst.total, 0), healthyInst = this.COMPONENTS.reduce((a: number, c: any) => a + (c.inst.total - (c.inst.degraded || 0)), 0);
    const degName = (this.COMPONENTS.find((c: any) => c.state === 'degraded') || {} as any).name || '';
    const activeLabel = aborted ? 'Campaign aborted' : (running && inprog) ? ((this.STAGES[inprog.st] || 'Running') + ' · ' + inprog.id) : 'Idle · awaiting work';
    const activeColor = aborted ? 'var(--v-err)' : (running && inprog) ? 'var(--phos)' : 'var(--tx3)';
    const KIND: any = { publication: { t: 'Critical publication', i: this.ic.findings, c: 'var(--v-conf)' }, indeterminate: { t: 'Indeterminate verdict', i: this.ic.diamond, c: 'var(--v-indet)' }, escalation: { t: 'Escalated review', i: this.ic.bell, c: 'var(--warn)' }, remediation: { t: 'Remediation', i: this.ic.check, c: 'var(--tz-gov)' } };
    const att: any[] = [];
    att.push({ pri: 0, iconEl: this.svgEl(this.ic.abort, 14, 1.8), color: 'var(--v-err)', title: 'Evidence integrity failed · A-0177', why: 'Recomputed hash mismatch — Judge verdict blocked', cont: 'Parked · never counted safe', age: '2m', action: 'Inspect', onClick: () => this.setState({ screen: 'live', liveMode: 'stream', selA: 'A-0177', inspectorTab: 'evidence', mView: 'attempt', beNode: 'rec' }) });
    st.approvals.forEach((a: any) => { const k = KIND[a.kind] || KIND.publication; att.push({ pri: 1, iconEl: this.svgEl(k.i, 14, 1.8), color: k.c, title: k.t + ' · ' + a.fid, why: 'Human decision required — ' + (a.kind === 'publication' ? 'approver ≠ launcher' : 'rationale required'), cont: 'Campaign continues', age: a.sla, action: 'Review', onClick: () => this.goApproval(a.id) }); });
    att.push({ pri: 2, iconEl: this.svgEl(this.ic.bolt, 14, 1.8), color: 'var(--warn)', title: 'Observability degraded', why: 'Langfuse delayed 22s · Postgres authoritative', cont: 'Verdicts unaffected', age: '22s', action: 'Traces', onClick: () => this.setState({ screen: 'traces', beNode: 'obs', palOpen: false, mView: null }) });
    att.sort((a, b) => a.pri - b.pri);
    if (integ) { att.length = 0; att.push({ pri: 0, iconEl: this.svgEl(this.ic.bell, 14, 1.8), color: 'var(--tx3)', title: 'No live approval stream', why: 'Human-approval backend and finding/approval command APIs are pending (proposed).', cont: 'Prototype UI only', age: '', action: '', onClick: () => { } }); }
    const attShown = st.beAttnAll ? att : att.slice(0, 3);
    const tl = st.attempts.slice(0, 18).map((a: any) => { const resolved = a.st >= 5; const m = resolved ? (this.VMETA[a.v] || this.VMETA.ERROR) : null; const cat = this.SHORT[a.cat] || (this.CAT[a.cat] && this.CAT[a.cat].cat) || 'Attempt'; return { t: a.t, actor: a.strat, action: cat + (m ? (' · ' + m.short) : (' · ' + ((this.STAGES[a.st] || '').toLowerCase() || 'running'))), color: m ? m.color : 'var(--brand)', id: a.id, live: !resolved, onClick: () => this.setState({ screen: 'live', liveMode: 'stream', selA: a.id, inspectorTab: 'attempt' }) }; });
    let sheet: any = null; if (st.beNode) { const c = byId[st.beNode]; if (c) sheet = N(c.id); }
    // mobile semantic phases: group zones into fewer expandable phases
    const mzones = [
      { id: 'p1', label: 'Generate', short: 'Generate', zone: 'quar', ids: ['orch', 'rt'] },
      { id: 'p2', label: 'Govern & execute', short: 'Govern', zone: 'trust', ids: ['pol', 'tgt', 'ext'] },
      { id: 'p3', label: 'Record & judge', short: 'Record', zone: 'gov', ids: ['rec', 'judge'] },
      { id: 'p4', label: 'Outcomes', short: 'Outcomes', zone: 'human', ids: ['doc', 'reg', 'human'] },
    ];
    const mPhases = mzones.map((z: any) => {
      const nodes = z.ids.map(N); const anyActive = nodes.some((n: any) => n.state === 'working'); const bad = nodes.find((n: any) => n.state === 'degraded' || n.state === 'error' || n.state === 'waiting'); const head = bad || nodes.find((n: any) => n.state === 'working') || nodes[0];
      return {
        id: z.id, label: z.label, short: z.short, zoneColor: ZC[z.zone], nodes, count: nodes.length, open: st.beMPhase === z.id, onToggle: () => this.toggleMPhase(z.id), chevronRot: st.beMPhase === z.id ? '180deg' : '0deg',
        stateColor: head.stateColor, stateLabel: head.stateLabel, stateIconEl: head.stateIconEl, summary: nodes.map((n: any) => n.name).join(' · ')
      };
    });
    return {
      scenDemo: !integ, scenInteg: integ, setDemo: () => this.setState({ scenario: 'demo' }), setInteg: () => this.setState({ scenario: 'integration' }), scenDemoBg: !integ ? 'var(--sel)' : 'transparent', scenDemoFg: !integ ? 'var(--tx)' : 'var(--tx2)', scenIntegBg: integ ? 'var(--sel)' : 'transparent', scenIntegFg: integ ? 'var(--warn)' : 'var(--tx2)', scenarioTag: integ ? 'Integration state · no live data' : 'Demo scenario · synthetic', scenarioTagColor: integ ? 'var(--warn)' : 'var(--tx3)', tlLiveBadge: integ ? 'no stream' : 'live', tlLiveColor: integ ? 'var(--tx3)' : 'var(--phos)',
      liveBirdseye: st.liveMode === 'birdseye', liveStream: st.liveMode === 'stream', liveThumbX: st.liveMode === 'birdseye' ? '0%' : '100%', setBirdseye: () => this.setState({ liveMode: 'birdseye' }), setStream: () => this.setState({ liveMode: 'stream' }),
      beBg: st.liveMode === 'birdseye' ? 'var(--sel)' : 'transparent', beFg: st.liveMode === 'birdseye' ? 'var(--brand)' : 'var(--tx2)', streamBg: st.liveMode === 'stream' ? 'var(--sel)' : 'transparent', streamFg: st.liveMode === 'stream' ? 'var(--brand)' : 'var(--tx2)',
      beCollapsed: st.beCollapsed, beExpanded: !st.beCollapsed, toggleBeCollapse: () => this.setState((s: any) => ({ beCollapsed: !s.beCollapsed })),
      beFollow: st.beFollow, followBg: st.beFollow ? 'var(--sel)' : 'transparent', followFg: st.beFollow ? 'var(--brand)' : 'var(--tx2)', toggleFollow: () => this.setState((s: any) => ({ beFollow: !s.beFollow })),
      fitView: () => this.setState({ beNode: null, beFollow: true }), focusActive: () => this.focusActive(),
      beRailOpen: (st.beAttnRailOpen || !!st.beNode), beShowInspector: !!sheet, beShowAttn: (st.beAttnRailOpen && !sheet), beShowStrip: (!st.beAttnRailOpen && !sheet),
      beGridCols: (st.beAttnRailOpen || !!st.beNode) ? ('minmax(0,1fr) ' + ((st.bp === 'md') ? 300 : 360) + 'px') : 'minmax(0,1fr) 44px',
      bePipeline, beInfra: services, beLive: integ ? 'No live telemetry' : (live + ' live'),
      sysHealthLabel: integ ? 'Integration state' : (degraded ? 'System degraded' : 'All systems nominal'), sysHealthColor: integ ? 'var(--tx2)' : (degraded ? 'var(--warn)' : 'var(--phos)'), sysHealthSub: integ ? 'No live projection · see component availability' : ((degraded ? (degName + ' · ') : '') + healthyInst + '/' + totalInst + ' healthy'), sysDegraded: integ ? false : degraded,
      activeLabel: integ ? 'No live campaign · integration state' : activeLabel, activeColor: integ ? 'var(--tx3)' : activeColor,
      beAttention: attShown, beAttnCount: att.length, beHasAttn: att.length > 0, beAttnMore: Math.max(0, att.length - 3), beAttnAll: st.beAttnAll, beAttnHasMore: att.length > 3, toggleAttnAll: () => this.setState((s: any) => ({ beAttnAll: !s.beAttnAll })),
      beAttnRailOpen: st.beAttnRailOpen, toggleAttnRail: () => this.setState((s: any) => ({ beAttnRailOpen: !s.beAttnRailOpen })),
      beTimeline: integ ? [{ t: '—', actor: '', action: 'No live event stream — SSE/WebSocket transport not implemented (proposed).', color: 'var(--tx3)', id: '', live: false, onClick: () => { } }] : tl, beTLCollapsed: st.beTLCollapsed, beTLOpen: !st.beTLCollapsed, toggleTL: () => this.setState((s: any) => ({ beTLCollapsed: !s.beTLCollapsed })),
      beSheet: sheet || {}, beHasSheet: !!sheet, mNodeSheet: ((st.surface === 'mobile' || st.bp === 'sm') && st.screen === 'live' && st.liveMode === 'birdseye' && !!sheet), closeNode: () => this.closeNode(),
      mPhases, mPhaseChips: mPhases, beMActive: integ ? 'No live campaign' : activeLabel, beMActiveColor: integ ? 'var(--tx3)' : activeColor,
      beMAttn: st.beAttnAll ? att : att.slice(0, 1), beMAttnHasMore: att.length > 1, beMAttnMoreLabel: st.beAttnAll ? 'Show fewer' : ('View all (+' + Math.max(0, att.length - 1) + ')'),
      icFit: this.svgEl('M4 9V5a1 1 0 0 1 1-1h4 M20 9V5a1 1 0 0 0-1-1h-4 M4 15v4a1 1 0 0 0 1 1h4 M20 15v4a1 1 0 0 1-1 1h-4', 13, 1.8),
      icFollow: this.svgEl('M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M3 12h3 M18 12h3 M12 16v3', 13, 1.8),
      icFocus: this.svgEl('M13 3L4 14h7l-1 7 9-11h-7z', 13, 1.8),
      icChevron: this.svgEl('M6 9l6 6 6-6', 13, 2),
      tlChevron: st.beTLCollapsed ? '-90deg' : '0deg', tlHint: st.beTLCollapsed ? 'Expand' : 'Newest first',
      attnMoreLabel: st.beAttnAll ? 'Show fewer' : ('View all (+' + Math.max(0, att.length - 3) + ')')
    };
  }

  core() {
    const st = this.state; const b = st.budget; const pct = Math.round((b.used / b.cap) * 1000) / 10;
    const near = pct >= 80; const navm = this.nav.map((n: any) => ({ id: n.id, label: n.label, icon: n.icon, iconEl: this.svgEl(n.icon, 17, 1.7), go: () => this.go(n.id), active: n.id === st.screen, aria: n.id === st.screen ? 'page' : 'false', fg: n.id === st.screen ? 'var(--tx)' : 'var(--tx2)', bg: n.id === st.screen ? 'var(--sel)' : 'transparent', rail: n.id === st.screen ? 'var(--brand)' : 'transparent', hasBadge: n.id === 'approvals' && st.approvals.length > 0, badge: st.approvals.length }));
    const palRaw = this.palItemsRaw();
    const palItems = palRaw.map((it: any, i: number) => ({ label: it.label, group: it.group, icon: it.icon, iconEl: this.svgEl(it.icon, 15, 1.8), hint: it.hint === 'danger' ? '' : it.hint, run: () => this.runPal(it), bg: i === st.palIdx ? 'var(--hover)' : 'transparent', iconBg: it.hint === 'danger' ? 'var(--v-conf-t)' : 'var(--bg-inset)', iconFg: it.hint === 'danger' ? 'var(--v-conf)' : it.type === 'finding' ? 'var(--brand)' : 'var(--tx2)' }));
    return {
      integ: st.scenario === 'integration', notInteg: st.scenario !== 'integration', showAttest: st.bp === 'xl',
      toggleScenario: () => this.setState((s: any) => ({ scenario: s.scenario === 'integration' ? 'demo' : 'integration' })),
      scenarioBtnLabel: st.scenario === 'integration' ? 'Integration state' : 'Live · demo',
      scenarioBtnColor: st.scenario === 'integration' ? 'var(--tx3)' : 'var(--phos)',
      theme: st.theme, density: st.density, isDark: st.theme === 'dark', isLight: st.theme === 'light',
      isDesktop: !(st.bp === 'sm' || st.surface === 'mobile'), isMobile: (st.bp === 'sm' || st.surface === 'mobile'), phoneFrame: st.surface === 'mobile' && st.bp !== 'sm', notPhoneFrame: !(st.surface === 'mobile' && st.bp !== 'sm'), mOuter: (st.surface === 'mobile' && st.bp !== 'sm') ? 'height:100dvh;width:100%;overflow:auto;background:radial-gradient(130% 80% at 50% 0%,var(--bg-panel),var(--bg-app));display:flex;align-items:flex-start;justify-content:center;padding:22px 16px' : 'height:100dvh;width:100%;overflow:hidden;background:var(--bg-app);display:flex', mFrame: (st.surface === 'mobile' && st.bp !== 'sm') ? 'width:390px;max-width:100%;height:min(844px,calc(100dvh - 44px));background:var(--bg-app);border-radius:42px;border:1px solid var(--bd-2);box-shadow:var(--shadow);overflow:hidden;position:relative;display:flex;flex-direction:column' : 'width:100%;height:100dvh;background:var(--bg-app);overflow:hidden;position:relative;display:flex;flex-direction:column;padding-top:env(safe-area-inset-top,0px)', bp: st.bp, bpXl: st.bp === 'xl', bpLg: st.bp === 'lg', bpMd: st.bp === 'md', bpSm: st.bp === 'sm', shellCols: st.bp === 'xl' ? '216px 1fr' : '64px 1fr', navExpanded: st.bp === 'xl', navJustify: st.bp === 'xl' ? 'flex-start' : 'center', screen: st.screen,
      isLive: st.screen === 'live', isFindings: st.screen === 'findings', isApprovals: st.screen === 'approvals', isCoverage: st.screen === 'coverage', isResilience: st.screen === 'resilience', isTraces: st.screen === 'traces', isCosts: st.screen === 'costs', isTargets: st.screen === 'targets', isConfig: st.screen === 'config',
      goLive: () => this.go('live'),
      mTabLive: st.screen === 'live', mTabFindings: st.screen === 'findings', mTabApprovals: st.screen === 'approvals', mTabTargets: st.screen === 'targets', mMore: st.screen === 'more', mTabCoverage: st.screen === 'coverage', mTabResilience: st.screen === 'resilience', mTabTraces: st.screen === 'traces', mTabCosts: st.screen === 'costs', mTabConfig: st.screen === 'config',
      mViewNone: !st.mView, mViewApproval: st.mView === 'approval', mViewFinding: st.mView === 'finding', mViewAttempt: st.mView === 'attempt', mViewTarget: st.mView === 'target', mViewAgent: st.mView === 'agent',
      mTargetsList: st.screen === 'targets' && !st.mView, mConfigList: st.screen === 'config' && !st.mView,
      mNav: [{ id: 'live', label: 'Live', icon: this.ic.live }, { id: 'findings', label: 'Findings', icon: this.ic.findings }, { id: 'approvals', label: 'Approvals', icon: this.ic.approvals }, { id: 'targets', label: 'Targets', icon: this.ic.targets }, { id: 'more', label: 'More', icon: 'M5 12h.01 M12 12h.01 M19 12h.01' }].map((n: any) => { var sec = ['coverage', 'resilience', 'traces', 'costs', 'config', 'more']; var act = n.id === 'more' ? sec.indexOf(st.screen) >= 0 : st.screen === n.id; return { id: n.id, label: n.label, icon: n.icon, iconEl: this.svgEl(n.icon, 20, 1.8), active: act, color: act ? 'var(--brand)' : 'var(--tx3)', hasBadge: n.id === 'approvals' && st.approvals.length > 0, badge: st.approvals.length, onClick: () => this.go(n.id) }; }),
      moreItems: [{ id: 'coverage', label: 'Coverage', icon: this.ic.coverage }, { id: 'resilience', label: 'Resilience', icon: this.ic.resilience }, { id: 'traces', label: 'Traces', icon: this.ic.traces }, { id: 'costs', label: 'Costs', icon: this.ic.costs }, { id: 'config', label: 'Configuration', icon: 'M6 4v5 M6 13v7 M12 4v3 M12 11v9 M18 4v9 M18 17v3 M3 11h6 M9 7h6 M15 13h6' }].map((n: any) => ({ label: n.label, icon: n.icon, iconEl: this.svgEl(n.icon, 16, 1.7), onClick: () => this.go(n.id) })),
      openMApproval: (id: string) => this.openMApproval(id), openMFinding: (id: string) => this.openMFinding(id), mBack: () => this.mBack(),
      nav: navm, openRole: () => this.toggleRoleMenu(),
      operator: this.currentPrincipal(),
      roleMenu: st.roleMenu, closeRoleMenu: () => this.setState({ roleMenu: false }), roles: this.ROLES.map((r: any, i: number) => ({ name: r.name, role: r.role, initials: r.initials, isLauncher: r.isLauncher, canApprove: r.canApprove, active: i === st.principalIdx, bg: i === st.principalIdx ? 'var(--sel)' : 'transparent', roleLine: r.role + (r.isLauncher ? ' · launched RUN 042' : '') + (r.canApprove ? '' : ' · cannot approve'), onClick: () => this.setPrincipal(i) })),
      camp: { run: 'RUN 042', target: 'Atlas Support Agent', env: 'Staging', ver: 'v1.4.2', state: (st.campaignState === 'running' ? 'Running' : st.campaignState === 'aborting' ? 'Aborting…' : 'Aborted'), scope: 'Indirect injection · cross-tenant' },
      campColor: (st.campaignState === 'running' ? 'var(--v-clear)' : st.campaignState === 'aborting' ? 'var(--warn)' : 'var(--v-err)'), campAborted: st.campaignState === 'aborted', campRunning: st.campaignState === 'running', campAborting: st.campaignState === 'aborting', live: st.live,
      fresh: '2s ago', apprCount: st.approvals.length, hasAppr: st.approvals.length > 0, goApprovals: () => this.setState((s: any) => ({ screen: 'approvals', palOpen: false, mView: null, apprMobile: false, apprId: (s.approvals.find((a: any) => a.id === s.apprId) ? s.apprId : ((s.approvals[0] || {} as any).id || null)) })),
      openPalette: () => this.setState({ palOpen: true, palQ: '', palIdx: 0 }), closePalette: () => this.setState({ palOpen: false }), stop: (e: any) => { e.stopPropagation(); },
      palOpen: st.palOpen, palQ: st.palQ, palItems, palEmpty: palItems.length === 0, onPalInput: (e: any) => this.onPalInput(e),
      toggleTheme: () => this.toggleTheme(), setDesktop: () => this.setSurface('desktop'), setMobile: () => this.setSurface('mobile'),
      deskBg: st.surface === 'desktop' ? 'var(--sel)' : 'transparent', deskFg: st.surface === 'desktop' ? 'var(--brand)' : 'var(--tx2)', mobBg: st.surface === 'mobile' ? 'var(--sel)' : 'transparent', mobFg: st.surface === 'mobile' ? 'var(--brand)' : 'var(--tx2)',
      openAbort: () => this.openAbort(), closeAbort: () => this.closeAbort(), abortOpen: st.abortOpen,
      abortMobileOpacity: st.campaignState === 'aborted' ? 0.45 : 1,
      abortConfirm: st.abortStage === 'confirm', abortWorking: st.abortStage === 'working', abortDone: st.abortStage === 'done', abortError: st.abortStage === 'error', retryAbort: () => this.retryAbort(), simFail: st.simFail, toggleSimFail: () => this.toggleSimFail(),
      abortAck: st.abortAck, toggleAbortAck: () => this.toggleAbortAck(), doAbort: () => this.doAbort(), abortDisabled: !st.abortAck,
      ackBorder: st.abortAck ? 'var(--v-conf)' : 'var(--bd-2)', ackBg: st.abortAck ? 'var(--v-conf)' : 'transparent',
      abortBtnBg: st.abortAck ? 'var(--v-conf)' : 'var(--bg-inset)', abortBtnFg: st.abortAck ? '#fff' : 'var(--tx3)', abortBtnOp: st.abortAck ? 1 : 0.6,
      abortInfo: [{ k: 'Campaign', v: 'RUN 042' }, { k: 'Target', v: 'Atlas Support Agent v1.4.2 (Staging)' }, { k: 'Queued attempts', v: '6 will be cancelled' }, { k: 'In-flight execution', v: '2 will be recorded, then stopped' }, { k: 'Partial evidence', v: 'Retained and hash-verified' }, { k: 'Resume', v: 'Not resumable — start a new run' }],
      paused: st.paused, notPaused: !st.paused, togglePause: () => this.togglePause(), pauseTitle: st.paused ? 'Resume visual stream' : 'Pause visual stream (campaign keeps running)',
      hasToast: !!st.toast, toast: st.toast || { msg: '', color: 'var(--phos)' },
    };
  }

  liveVM() {
    const st = this.state; const b = st.budget; const pct = Math.round((b.used / b.cap) * 1000) / 10; const integ = st.scenario === 'integration';
    return {
      instr: integ ? { used: '—', cap: this.fmt2(b.cap), budgetPct: '0%', budgetColor: 'var(--tx3)', burn: '—', proj: 'no projection', queue: '—', rate: '60 rpm', cf: '—', likely: '—', indet: '—' } : { used: this.fmt2(b.used), cap: this.fmt2(b.cap), budgetPct: pct + '%', budgetColor: pct >= 80 ? 'var(--warn)' : 'var(--brand)', burn: this.fmt2(b.burn), proj: '2h 41m', queue: st.pending.length + 6, rate: '60 rpm', cf: 2, likely: 2, indet: 1 },
      rows: st.attempts.map((a: any) => this.mapRow(a)),
      mRows: st.attempts.slice(0, 7).map((a: any) => this.mapRow(a)),
      liveCols: st.bp === 'xl' ? '1.5fr 1.12fr 1.05fr' : (st.bp === 'lg' ? '1.3fr 1.05fr' : '1fr'), liveTwoPane: st.bp === 'lg' || st.bp === 'md', liveMdOne: st.bp === 'md',
      streamVisible: st.bp === 'xl' || st.bp === 'lg' || st.inspectorTab === 'stream',
      selVisible: st.bp === 'xl' || ((st.bp === 'lg' || st.bp === 'md') && st.inspectorTab === 'attempt'), evVisible: st.bp === 'xl' || ((st.bp === 'lg' || st.bp === 'md') && st.inspectorTab === 'evidence'),
      inspStream: st.inspectorTab === 'stream', inspAttempt: st.inspectorTab === 'attempt', inspEvidence: st.inspectorTab === 'evidence',
      setInspStream: () => this.setState({ inspectorTab: 'stream' as any }), setInspAttempt: () => this.setState({ inspectorTab: 'attempt' }), setInspEvidence: () => this.setState({ inspectorTab: 'evidence' }),
      inspStreamBg: st.inspectorTab === 'stream' ? 'var(--sel)' : 'transparent', inspStreamFg: st.inspectorTab === 'stream' ? 'var(--brand)' : 'var(--tx2)', inspAttemptBg: st.inspectorTab === 'attempt' ? 'var(--sel)' : 'transparent', inspAttemptFg: st.inspectorTab === 'attempt' ? 'var(--brand)' : 'var(--tx2)', inspEvidenceBg: st.inspectorTab === 'evidence' ? 'var(--sel)' : 'transparent', inspEvidenceFg: st.inspectorTab === 'evidence' ? 'var(--brand)' : 'var(--tx2)',
      newCount: st.newCount, showNew: st.newCount > 0, flushNew: () => this.flushNew(),
      onStreamScroll: () => this.onStreamScroll(), streamRef: this.streamRef,
      sel: this.buildSel(), ev: this.buildEv(),
      revealQuar: () => this.revealQuar(), hideQuar: () => this.hideQuar(), copyQuar: () => this.copyQuar(),
    };
  }

  renderVals() { return Object.assign({}, this.core(), this.liveVM(), this.findingsVM(), this.apprVM(), this.targetsVM(), this.tracesVM(), this.coverageVM(), this.resilienceVM(), this.costsVM(), this.birdseyeVM(), this.agentsVM()); }

  render() {
    return (
      <div style={{ height: "100dvh", width: "100%", overflow: "hidden", background: "var(--bg-app)", color: "var(--tx)" }} data-theme={this.state.theme} data-density={this.state.density}>
        <Shell app={this} />
      </div>
    );
  }
}
