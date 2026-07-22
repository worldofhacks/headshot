#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const dist = join(root, "dist");
if (!existsSync(dist)) {
  console.error("Production bundle is absent; run npm run build first.");
  process.exit(1);
}

const files = [];
const collect = (directory) => {
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) collect(path);
    else files.push(path);
  }
};
collect(dist);

const maps = files.filter((path) => path.endsWith(".map"));
const readable = files.filter((path) => /\.(?:js|css|html)$/.test(path));
const allText = readable.map((path) => readFileSync(path, "utf8")).join("\n");
const identifiers = [
  "RUN 042", "Atlas Support Agent", "F-1042", "AP-01", "A-0185", "A-0177",
  "CN-7731", "Demo scenario", "prototype principal",
];

const index = readFileSync(join(dist, "index.html"), "utf8");
const externalRuntimeAsset = /<(?:script|link)\b[^>]*(?:src|href)=["']https?:\/\//i.test(index);
const sourceMapReference = /sourceMappingURL=/i.test(allText);
const identifierHits = identifiers.filter((identifier) => allText.toLowerCase().includes(identifier.toLowerCase()));
const appChunkMatch = index.match(/<script[^>]+src=["']([^"']*\/index-[^"']+\.js)["']/i);
const appChunk = appChunkMatch ? join(dist, appChunkMatch[1].replace(/^\//, "")) : null;
const appText = appChunk && existsSync(appChunk) ? readFileSync(appChunk, "utf8") : "";
const appAuthorityHits = [
  /Math\.random\s*\(/,
  /setInterval\s*\(/,
  /localStorage/,
  /sessionStorage/,
  /IndexedDB/,
  /dangerouslySetInnerHTML/,
].filter((pattern) => pattern.test(appText)).map(String);

const failures = [];
if (maps.length) failures.push(`source maps: ${maps.map(basename).join(", ")}`);
if (sourceMapReference) failures.push("source map reference in emitted text");
if (externalRuntimeAsset) failures.push("external script or stylesheet in index.html");
if (identifierHits.length) failures.push(`fixture identifiers: ${identifierHits.join(", ")}`);
if (!appChunk) failures.push("application entry chunk was not found");
if (appAuthorityHits.length) failures.push(`application authority APIs: ${appAuthorityHits.join(", ")}`);

if (failures.length) {
  console.error(`Production bundle policy failed:\n- ${failures.join("\n- ")}`);
  process.exit(1);
}
console.log(`✓ Production bundle policy passed across ${files.length} emitted files.`);
