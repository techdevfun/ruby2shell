/**
 * Ruby version parsing and the fixed-build table for the
 * 18/11/2026 Ruby security release (CVE-2026-132825 /
 * GHSA-34m4-m9fh-gqp5, "Ruby2Shell").
 *
 * Fixed builds: 3.3.14, 3.4.13, 4.0.10. The flaw is present in
 * CRuby back to 2.4.0; Ruby 3.2 and earlier are end of life and
 * will not receive these fixes. A version before 2.4.0 predates
 * the flaw.
 *
 * A version string that cannot be parsed is UNKNOWN, never SAFE.
 * A distro-suffixed version (e.g. "3.3.0-1ubuntu") is UNKNOWN:
 * the distro may have backported the fix, and the version number
 * alone cannot say. JRuby / TruffleRuby are not CRuby, so the
 * CRuby case-conversion table does not apply to them: UNKNOWN.
 *
 * Sources (checked 2026-11-20): Ruby security advisory,
 * ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/;
 * Veria Labs, verialabs.com/ruby2shell/ (status table updated
 * 2026-11-20 11:58 UTC); NVD, CVE-2026-132825.
 */
import { CVE_ID, GHSA_ID } from "./cli-version.js";

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  /** Full `X.Y.Z` token as printed, e.g. "3.4.12". */
  raw: string;
  /** Patch level from `ruby -v` (the pN), or null when absent. */
  patchLevel: number | null;
  /** Ruby line, e.g. "3.4". */
  line: string;
  /** Distro suffix from a bare version string, e.g. "-1ubuntu", or null. */
  distroSuffix: string | null;
  /** Non-CRuby engine detected from the -v output, e.g. "jruby". */
  engine: string | null;
}

/** Compare two dotted versions: -1, 0 or 1. */
export function compareVersions(
  a: { major: number; minor: number; patch: number },
  b: { major: number; minor: number; patch: number },
): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

/** Fixed build per supported line. */
export const FIXED_BUILDS: Record<string, string> = {
  "3.3": "3.3.14",
  "3.4": "3.4.13",
  "4.0": "4.0.10",
};

function fixedForLine(line: string): {
  major: number;
  minor: number;
  patch: number;
} | null {
  const fixed = FIXED_BUILDS[line];
  if (!fixed) return null;
  const [major, minor, patch] = fixed.split(".").map(Number);
  return { major, minor, patch };
}

/**
 * Parse `ruby -v` output or a bare version string. The first line
 * of `ruby -v` looks like
 * `ruby 3.4.12p0 (2026-10-20 revision ...) [x86_64-linux]`.
 * Returns null when no `ruby X.Y.Z` token is found.
 */
export function parseRubyVersion(output: string): ParsedVersion | null {
  const lower = output.toLowerCase();
  let engine: string | null = null;
  if (lower.includes("jruby")) engine = "jruby";
  else if (lower.includes("truffleruby")) engine = "truffleruby";
  const m = output.match(/ruby (\d+)\.(\d+)\.(\d+)(?:p(\d+))?/);
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  const patchLevel = m[4] !== undefined ? Number(m[4]) : null;
  const after = output.slice((m.index ?? 0) + m[0].length);
  const suffixMatch = after.match(/^(-[0-9A-Za-z.+~]+)/);
  return {
    major,
    minor,
    patch,
    raw: `${major}.${minor}.${patch}`,
    patchLevel,
    line: `${major}.${minor}`,
    distroSuffix: suffixMatch ? suffixMatch[1] : null,
    engine,
  };
}

/** Patch verdict for the Ruby2Shell flaw on one Ruby version. */
export type PatchVerdict =
  "fixed" | "affected" | "eol-no-fix" | "predates" | "unknown-line";

export function patchVerdictFor(v: ParsedVersion): PatchVerdict {
  // Before 2.4.0 the buggy loop did not exist yet.
  if (compareVersions(v, { major: 2, minor: 4, patch: 0 }) < 0)
    return "predates";
  const fixed = fixedForLine(v.line);
  if (!fixed) {
    // Lines 2.4-3.2 are end of life with no fix; lines newer than
    // the table (e.g. a future 4.1) are not in the 18/11/2026
    // advisory at all.
    if (compareVersions(v, { major: 3, minor: 3, patch: 0 }) < 0)
      return "eol-no-fix";
    return "unknown-line";
  }
  return compareVersions(v, fixed) >= 0 ? "fixed" : "affected";
}

/** Fixed build string for display, per line ("" when unknown). */
export function fixedBuildFor(line: string): string {
  return FIXED_BUILDS[line] ?? "";
}

/** Human-readable one-liner for a patch verdict. */
export function patchVerdictText(v: ParsedVersion): string {
  const verdict = patchVerdictFor(v);
  switch (verdict) {
    case "fixed":
      return `${v.raw} is at or above the fixed build ${fixedBuildFor(v.line)} (18/11/2026 release)`;
    case "affected":
      return `${v.raw} is in the affected range for ${CVE_ID} (fixed build is ${fixedBuildFor(v.line)})`;
    case "eol-no-fix":
      return `${v.raw} is end of life (3.2 and earlier) - the flaw is present back to 2.4.0 and no fix exists for this line`;
    case "predates":
      return `${v.raw} predates the flaw (the buggy case-conversion loop dates to Ruby 2.4.0)`;
    case "unknown-line":
      return `${v.raw} is on a Ruby line not covered by the 18/11/2026 fixed-build table (${Object.values(FIXED_BUILDS).join(", ")})`;
  }
}

export interface SiblingFlaw {
  ghsa: string;
  title: string;
  note: string;
}

/**
 * The other six flaws from the same 18/11/2026 security release.
 * They are a checklist note, NOT separate verdicts: only
 * GHSA-34m4-m9fh-gqp5 has a CVE so far (CVE-2026-132825); the
 * other six carry GHSA IDs only. Titles and notes are Ruby's own
 * wording from the advisory (ruby-lang.org, read live 2026-11-20).
 * Ruby is aware of PoCs that prove RCE in some scenarios for 5
 * of the 7 flaws in total; the advisory does not assign a
 * severity label per flaw, so none is stated here.
 */
export const SIBLING_FLAWS: SiblingFlaw[] = [
  {
    ghsa: "GHSA-34m4-m9fh-gqp5",
    title: "Heap buffer overflow in case conversion of strings (Ruby2Shell)",
    note: `This is ${CVE_ID} - the flaw this tool checks. RCE PoC known to Ruby.`,
  },
  {
    ghsa: "GHSA-7x2q-68qv-6p8x",
    title: "Double free in regular expression compilation",
    note: "Compiling a crafted Regexp pattern may allow RCE in apps that compile attacker-controlled patterns. RCE PoC known to Ruby. Same release, GHSA only.",
  },
  {
    ghsa: "GHSA-87fm-7w84-j2px",
    title: "Integer overflow in case conversion of strings",
    note: "Integer overflow causes a heap-based buffer overflow when changing the case of a crafted string. RCE PoC known to Ruby. Same release, GHSA only.",
  },
  {
    ghsa: "GHSA-wpqw-5qxg-m68r",
    title: "Out-of-bounds read in case-insensitive regular expression matching",
    note: "Matching against a crafted pattern may allow RCE in apps that use attacker-controlled patterns. PoC proves memory corruption in an attacker-controlled way. Same release, GHSA only.",
  },
  {
    ghsa: "GHSA-3p8q-wmhx-vm2w",
    title: "Heap buffer overflow in regular expression compilation",
    note: "Integer overflow in the Regexp engine causes a heap-based buffer overflow. RCE PoC known to Ruby. Same release, GHSA only.",
  },
  {
    ghsa: "GHSA-7whj-cfh7-xgm4",
    title: "Heap buffer overflow in Regexp#to_s",
    note: "Converting a crafted Regexp to a string may allow information disclosure or RCE. RCE PoC known to Ruby. Same release, GHSA only.",
  },
  {
    ghsa: "GHSA-pvgc-g7gj-pv6h",
    title: "Out-of-bounds read in case-insensitive backreference matching",
    note: "Matching a crafted string may disclose memory contents or crash the process. Same release, GHSA only.",
  },
];

export { CVE_ID, GHSA_ID };
