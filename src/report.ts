/**
 * Output rendering: human tables and --json. Every output ends
 * with the scope footer, so a verdict is never quoted without
 * its limit.
 */
import { CHECKED_AT, CVE_ID, GHSA_ID, VERSION } from "./cli-version.js";
import type { ParsedApp } from "./appconfig.js";
import type { ProductCheck } from "./products.js";
import type { RubyInstall } from "./discover.js";
import type { Verdict, VerdictResult } from "./verdict.js";

export const SCOPE_LINE =
  "Exposure conditions only. This tool does not prove exploitability and never sends a crashing payload. " +
  "A SAFE verdict means these three conditions do not line up - not that the host is safe from every Ruby flaw.";

export interface InstallReport {
  dir: string;
  binary: string;
  rawVersion: string;
  version: string | null;
  line: string | null;
  patch: string | null;
  framework: string | null;
  reachability: string | null;
  appSource: string | null;
  verdict: Verdict;
  deciding: string;
  reasons: string[];
  product: ProductCheck | null;
  productName: string | null;
  error: string | null;
}

export function installToReport(
  install: RubyInstall,
  result: VerdictResult,
  app: ParsedApp | null,
  appSource: string | null,
  product: ProductCheck | null,
  productName: string | null,
): InstallReport {
  return {
    dir: install.dir,
    binary: install.binary,
    rawVersion: install.rawVersion,
    version: install.version ? install.version.raw : null,
    line: install.version ? install.version.line : null,
    patch: result.patch,
    framework: app ? app.framework : null,
    reachability: app ? app.summary : null,
    appSource,
    verdict: result.verdict,
    deciding: result.deciding,
    reasons: result.reasons,
    product,
    productName,
    error: install.error,
  };
}

function pad(s: string, n: number): string {
  return s.length >= n ? s.slice(0, n) : s + " ".repeat(n - s.length);
}

export function renderScanTable(reports: InstallReport[]): string {
  const lines: string[] = [];
  lines.push(
    `ruby2shell ${VERSION} - ${CVE_ID} (${GHSA_ID}), facts checked ${CHECKED_AT}`,
  );
  lines.push("");
  lines.push(
    `${pad("install", 28)} ${pad("ruby", 9)} ${pad("framework", 18)} ${pad("verdict", 8)}`,
  );
  lines.push("-".repeat(72));
  for (const r of reports) {
    // Short dirs print in full; long dirs print their basename so
    // the install column never truncates mid-word.
    const name = r.dir.length <= 28 ? r.dir : (r.dir.split("/").pop() ?? r.dir);
    lines.push(
      `${pad(name, 28)} ${pad(r.version ?? "?", 9)} ${pad(r.framework ?? "-", 18)} ${pad(r.verdict, 8)}`,
    );
    for (const reason of r.reasons) lines.push(`  - ${reason}`);
    if (r.error) lines.push(`  - probe error: ${r.error}`);
  }
  lines.push("");
  const counts = (v: Verdict): number =>
    reports.filter((r) => r.verdict === v).length;
  lines.push(
    `summary: EXPOSED ${counts("EXPOSED")} / AT-RISK ${counts("AT-RISK")} / SAFE ${counts("SAFE")} / UNKNOWN ${counts("UNKNOWN")} - ${reports.length} install(s) scanned`,
  );
  lines.push(SCOPE_LINE);
  return lines.join("\n");
}

export function renderCheckTable(report: InstallReport): string {
  const lines: string[] = [];
  lines.push(
    `ruby2shell ${VERSION} - ${CVE_ID} (${GHSA_ID}), facts checked ${CHECKED_AT}`,
  );
  lines.push("");
  if (report.productName && report.product) {
    lines.push(`product: ${report.productName}`);
    if (report.product.fixedVersions.length > 0) {
      lines.push(`fixed releases: ${report.product.fixedVersions.join(", ")}`);
    } else {
      lines.push("fixed releases: none published yet");
    }
  } else {
    lines.push(`ruby: ${report.rawVersion || "(no output)"}`);
    lines.push(`binary: ${report.binary}`);
    if (report.line) lines.push(`line: ${report.line}`);
    if (report.patch) lines.push(`patch verdict: ${report.patch}`);
    if (report.framework) lines.push(`framework: ${report.framework}`);
    if (report.reachability) lines.push(`reachability: ${report.reachability}`);
    if (report.appSource) lines.push(`app evidence: ${report.appSource}`);
  }
  lines.push(`verdict: ${report.verdict}`);
  lines.push(`deciding condition: ${report.deciding}`);
  for (const reason of report.reasons) lines.push(`  - ${reason}`);
  if (report.error) lines.push(`probe error: ${report.error}`);
  lines.push("");
  lines.push(SCOPE_LINE);
  return lines.join("\n");
}

export function renderConfigTable(app: ParsedApp, target: string): string {
  const lines: string[] = [];
  lines.push(
    `ruby2shell ${VERSION} - app config scan, facts checked ${CHECKED_AT}`,
  );
  lines.push("");
  lines.push(`app: ${target}`);
  lines.push(`framework: ${app.framework}`);
  lines.push(`summary: ${app.summary}`);
  if (app.railsVersion) lines.push(`rails: ${app.railsVersion}`);
  if (app.sinatraVersion) lines.push(`sinatra: ${app.sinatraVersion}`);
  if (app.rackVersion) lines.push(`rack: ${app.rackVersion}`);
  if (app.apiOnly) lines.push("rails api_only: true");
  lines.push(`rack methodoverride: ${app.methodOverride}`);
  if (app.dockerRuby) lines.push(`docker ruby: ${app.dockerRuby}`);
  if (app.rubyVersionFile) lines.push(`.ruby-version: ${app.rubyVersionFile}`);
  if (app.caseConversionSites.length > 0) {
    lines.push("case-conversion on request params (REVIEW, not proof):");
    for (const site of app.caseConversionSites) {
      lines.push(`  ${site.file}:${site.line}: ${site.text}`);
    }
  } else {
    lines.push("case-conversion on request params: none found");
  }
  lines.push(`evidence: ${app.evidencePaths.join(", ")}`);
  lines.push("");
  lines.push(SCOPE_LINE);
  return lines.join("\n");
}

export function scanJson(
  reports: InstallReport[],
  appSource: string | null,
): Record<string, unknown> {
  return {
    tool: "ruby2shell",
    version: VERSION,
    checkedAt: CHECKED_AT,
    cve: CVE_ID,
    ghsa: GHSA_ID,
    app: appSource,
    installs: reports,
    scope: SCOPE_LINE,
  };
}

/** Exit code for a single verdict: 0 SAFE, 1 EXPOSED/AT-RISK, 2 UNKNOWN. */
export function verdictExitCode(verdict: Verdict): number {
  if (verdict === "SAFE") return 0;
  if (verdict === "UNKNOWN") return 2;
  return 1;
}
