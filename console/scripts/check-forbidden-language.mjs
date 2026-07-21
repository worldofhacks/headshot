#!/usr/bin/env node
/*
 * Repeatable forbidden-language check for the Headshot Operator Console (React port).
 * Fails (exit 1) if clinical / OpenEMR / platform-specific coupling regresses into the
 * console UI. Run in CI or locally:  npm run check:forbidden
 *
 * Scope: only the console UI source (src/**, index.html). The platform repo
 * (Adversarial Machine, one directory up) legitimately targets a clinical co-pilot as
 * target #1 and is intentionally NOT scanned. Ported from the handoff bundle's
 * scripts/check-forbidden-language.mjs (which scanned the single prototype .dc.html).
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCAN_DIRS = ["src"];
const SCAN_FILES = ["index.html"];
const EXT = /\.(ts|tsx|js|jsx|css|html)$/;
const SKIP_DIRS = new Set(["node_modules", "dist", ".vite", "fonts"]); // fonts/: binary woff2

// Whole-word / phrase patterns. Case-insensitive. (Verbatim from the handoff checker.)
const PRODUCT_COUPLING = [
  /clinical/i, /clinician/i, /\bpatient(s)?\b/i, /\bPHI\b/, /\bEHR\b/, /\bMRN\b/,
  /medication/i, /\breferral\b/i, /\bclinic\b/i, /dosing/i, /OpenEMR/i,
  /copilot/i, /co-pilot/i, /AgentForge/i, /Clinical Assistant/i,
  /\bwarfarin\b/i, /\bmetformin\b/i, /\blisinopril\b/i, /physician/i,
  /westgate/i, /northside/i, /\bpeds\b/i, /place_order/i, /order[_-]entry/i,
];

const PRODUCTION_BOUNDARY = [
  /RUN 042/i, /Atlas Support Agent/i, /F-1042/i, /AP-01/i, /A-0185/i,
  /A-0177/i, /CN-7731/i, /Demo scenario/i, /prototype principal/i,
  /simulat(?:e|ed|ion)/i, /Math\.random\s*\(/, /setInterval\s*\(/,
  /dangerouslySetInnerHTML/, /localStorage/, /sessionStorage/, /IndexedDB/,
  /from\s+["']\.\/?data["']/,
];

const FORBIDDEN = [...PRODUCT_COUPLING, ...PRODUCTION_BOUNDARY];

function collect(dir, out) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) collect(full, out);
    else if (EXT.test(name)) out.push(full);
  }
}

// Allow explicit file args (CI can pass a subset); otherwise scan the console source tree.
const argv = process.argv.slice(2);
let files = [];
if (argv.length) {
  files = argv.map((f) => join(ROOT, f));
} else {
  for (const d of SCAN_DIRS) collect(join(ROOT, d), files);
  for (const f of SCAN_FILES) files.push(join(ROOT, f));
}

let failures = 0;
for (const file of files) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    console.error(`! cannot read ${file}`);
    process.exitCode = 2;
    continue;
  }
  const lines = text.split(/\n/);
  for (const re of FORBIDDEN) {
    lines.forEach((ln, i) => {
      if (re.test(ln)) {
        failures++;
        console.error(`FORBIDDEN ${re} — ${relative(ROOT, file)}:${i + 1}: ${ln.trim().slice(0, 110)}`);
      }
    });
  }
}

if (failures) {
  console.error(
    `\n✗ Forbidden-language check FAILED (${failures} hit(s)). ` +
      `Remove clinical/OpenEMR/platform coupling from the console UI and fixtures.`,
  );
  process.exit(1);
}
console.log(`✓ Source policy passed — no target coupling, fixture data, browser authority, or persistent credential storage across ${files.length} console UI files.`);
