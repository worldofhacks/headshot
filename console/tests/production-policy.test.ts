import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "..");
const sourceRoot = join(root, "src");

function sourceFiles(directory: string): string[] {
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? sourceFiles(path) : [path];
  }).filter((path) => /\.(?:ts|tsx|js|jsx)$/.test(path));
}

const forbidden = [
  /RUN 042/i,
  /Atlas Support Agent/i,
  /F-1042/i,
  /AP-01/i,
  /A-0185/i,
  /A-0177/i,
  /CN-7731/i,
  /Demo scenario/i,
  /prototype principal/i,
  /simulat(?:e|ed|ion)/i,
  /Math\.random\s*\(/,
  /setInterval\s*\(/,
  /dangerouslySetInnerHTML/,
  /localStorage/,
  /sessionStorage/,
  /IndexedDB/,
];

describe("production source boundary", () => {
  it("contains no demo dataset, simulation engine, token persistence, or unsafe HTML sink", () => {
    const violations: string[] = [];
    for (const path of sourceFiles(sourceRoot)) {
      const text = readFileSync(path, "utf8");
      for (const pattern of forbidden) {
        if (pattern.test(text)) violations.push(`${relative(root, path)}: ${pattern}`);
      }
    }
    expect(violations).toEqual([]);
  });

  it("does not import the production fixture module", () => {
    const imports = sourceFiles(sourceRoot)
      .map((path) => [relative(root, path), readFileSync(path, "utf8")] as const)
      .filter(([, text]) => /from\s+["']\.\/?data["']/.test(text));
    expect(imports).toEqual([]);
  });
});
