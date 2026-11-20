/**
 * Playbook (first-hour stopgap) and explain topics. Every claim
 * cites its source and the check date (2026-11-20). Nothing here
 * is a guess: fixed builds, vendor releases, the PoC date and the
 * KEV status were all verified live during the build.
 */
import { CHECKED_AT, CVE_ID, GHSA_ID } from "./cli-version.js";
import { SIBLING_FLAWS } from "./versions.js";

export interface PlaybookStep {
  title: string;
  detail: string;
}

export const PLAYBOOK_STEPS: PlaybookStep[] = [
  {
    title: "1. Upgrade Ruby first - this is a runtime flaw, not a gem",
    detail:
      "Upgrade to the fixed build for your line: 3.3.14, 3.4.13 or 4.0.10 (released 18/11/2026). " +
      "Updating gems or Rails does not help: the bug is in the interpreter. Rebuild every image from the fixed tags " +
      "(ruby:4.0.10, ruby:3.4.13, ruby:3.3.14 - official Docker images rebuilt 19/11/2026) and restart every process " +
      "so the fixed Ruby is the one running.",
  },
  {
    title: "2. Ruby 3.2 and earlier: there is no patch - upgrade",
    detail:
      "Ruby 3.2 and earlier are end of life and will not receive these fixes, but they carry the same code back to " +
      "2.4.0. The only move is upgrading to a supported Ruby (3.3.14, 3.4.13 or 4.0.10). Do not wait for a patch " +
      "that is not coming.",
  },
  {
    title: "3. Self-hosted products: install the vendor fixed release",
    detail:
      "GitLab 19.6.1 / 19.5.8 / 19.4.10, Mastodon 4.7.6 (also 4.6.12, 4.5.22, 4.4.29), OpenProject 17.9.8 (also 17.8.3), " +
      "Discourse base image 2.0.20261119-0203. Chatwoot fixed in 4.20.1. GitHub Enterprise Server (3.22.5 and " +
      "earlier) still had no fixed release yet on 20/11/2026 - watch the vendor and treat those installs as exposed. " +
      "Check with: ruby2shell check --product gitlab --product-version 19.6.0",
  },
  {
    title: "4. Patch internet-facing Rails and classic Sinatra first",
    detail:
      "Default Rails and classic-style Sinatra are reachable without authentication (Rack::MethodOverride calls " +
      ".upcase on the _method parameter). Plain Rack and other frameworks are not exposed by default. Patch the " +
      "internet-facing apps first, then workers and build images.",
  },
  {
    title: "5. The patch window is days: the PoC lands 25/11/2026",
    detail:
      "Veria Labs will publish a proof of concept demonstrating RCE on stock Rails on 25 November 2026, or later if " +
      "major vendors have not shipped a fix by then. Ruby is already aware of non-public PoCs that reach RCE in some " +
      "scenarios. No exploitation in the wild was reported as of 20/11/2026, and the CVE is not in the CISA KEV " +
      "catalog as of the 2026-11-18 catalog version.",
  },
  {
    title: "6. Verify the fix",
    detail:
      "Re-run: ruby2shell scan --app <dir> (or ruby2shell check <ruby-dir> --app <dir>) and confirm SAFE on the fixed " +
      "build. Confirm the running process uses the fixed Ruby (ruby -v in the deployed image), not just the lockfile. " +
      "Then re-run the other six flaws as a checklist: the same release fixes 7 flaws (see explain siblings).",
  },
  {
    title: "7. What NOT to do",
    detail:
      "Do not send a crashing sharp-s payload at a live app to 'test' it - that is the exploit path, and this tool " +
      "never does it. Do not run exploit code from untrusted repositories (PoC repos for this CVE already exist). " +
      "Do not trust a clean bundle audit: bundler-audit checks gems, not the interpreter, so it cannot see this flaw.",
  },
];

export const EXPLAIN_TOPICS: Record<string, string> = {
  [CVE_ID]: [
    `${CVE_ID} (GHSA-34m4-m9fh-gqp5, "Ruby2Shell") - one-byte heap buffer overflow in Ruby string case conversion.`,
    "Most single-byte encodings have no capital sharp s. Upcasing it writes two bytes (SS) but the loop only",
    "bounds-checks one. The output buffer is the input length plus 20 bytes, so an input with 21 sharp-s",
    "characters overflows the buffer by one byte. Reached by upcase, swapcase, downcase(:fold) and casecmp?.",
    "UTF-8 strings take a different code path and are not affected. The buggy loop dates to Ruby 2.4.0.",
    "Fixed upstream in ruby/ruby@d582f8f; fixed releases 3.3.14, 3.4.13, 4.0.10 (18/11/2026).",
    "NVD (read 20/11/2026): CVE-2026-132825 published to the CVE List; CNA (MITRE) CVSS 3.1 vector",
    "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H, score 7.4 High; NIST assessment not yet provided.",
    "Ruby rates the advisory Critical and publishes no CVSS of its own. CWE-122 (heap-based buffer overflow).",
    `Sources: Veria Labs verialabs.com/ruby2shell/; Ruby advisory 18/11/2026; NVD CVE-2026-132825. Checked ${CHECKED_AT}.`,
  ].join("\n"),
  [GHSA_ID]: [
    `${GHSA_ID} - the GitHub Security Advisory for ${CVE_ID}. Ruby requested CVE identifiers for all seven`,
    "flaws in the 18/11/2026 release; at disclosure only GHSA IDs existed. MITRE assigned CVE-2026-132825",
    "on 19/11/2026 06:34 UTC, so this flaw now has both IDs. The other six flaws still carry GHSA IDs only.",
    `Source: Ruby advisory 18/11/2026. Checked ${CHECKED_AT}.`,
  ].join("\n"),
  EXPOSED: [
    "EXPOSED means the three conditions line up on this install: the Ruby version is in the affected range,",
    "and the app runs default Rails or classic-style Sinatra (or mounts Rack::MethodOverride), so attacker",
    "input reaches case conversion without authentication. It means exposure, not proof of exploitability:",
    "the tool never sends a payload and never proves an app is exploitable. Patch to the fixed build.",
    `Sources: Veria Labs verialabs.com/ruby2shell/; Ruby advisory 18/11/2026. Checked ${CHECKED_AT}.`,
  ].join("\n"),
  "AT-RISK": [
    "AT-RISK is the honest middle verdict. It means the version is in the affected range but exposure cannot",
    "be decided: no app evidence was read, the framework is Rails api_only (MethodOverride may be absent),",
    "the app is plain Rack but its own code case-converts request params, or the Ruby line is end of life",
    "(3.2 and earlier) with no fix. Never silently SAFE. Read the reasons, then pass --app <dir> to decide.",
    `Checked ${CHECKED_AT}.`,
  ].join("\n"),
  SAFE: [
    "SAFE means these three conditions do not line up: the Ruby is at or above a fixed build (3.3.14 / 3.4.13 /",
    "4.0.10), or it predates the flaw (before 2.4.0), or it is an affected Ruby on plain Rack / another framework",
    "with no case-conversion evidence (not exposed by default). It does NOT mean the host is safe from every",
    "Ruby flaw: only CVE-2026-132825 drives this verdict. The other six 18/11/2026 flaws are a checklist note.",
    `Checked ${CHECKED_AT}.`,
  ].join("\n"),
  UNKNOWN: [
    "UNKNOWN means the tool cannot decide: the version string could not be parsed, the build is a distro package",
    "(the distro may have backported the fix - confirm in the distro advisory), the engine is not CRuby",
    "(JRuby / TruffleRuby), the Ruby line is not in the 18/11/2026 fixed-build table, or a product version is",
    "not covered by the vendor table. Do not assume safe. Fix the input, then re-run.",
    `Checked ${CHECKED_AT}.`,
  ].join("\n"),
  rails: [
    "Rails (default config) is affected on an affected Ruby. The path is Rack::MethodOverride: it calls .upcase",
    "on the attacker-controlled _method parameter with no authentication. The Semgrep detection-scripts team",
    "confirmed this path at runtime with benign instrumentation: a multipart part's declared charset survives",
    "into the case-conversion call, before authentication. Rails api_only may not mount MethodOverride, so",
    "api_only apps are AT-RISK until the middleware stack is checked, not EXPOSED by default.",
    `Sources: Veria Labs; semgrep/detection-scripts PR #16. Checked ${CHECKED_AT}.`,
  ].join("\n"),
  sinatra: [
    "Sinatra in classic style is affected on an affected Ruby; modular style (Sinatra::Base subclass) is not",
    "exposed by default. Classic Sinatra mounts Rack::MethodOverride by default, the same _method upcase path",
    "as Rails. This tool detects classic vs modular from config.ru and the app files, and reports the style.",
    `Source: Veria Labs verialabs.com/ruby2shell/. Checked ${CHECKED_AT}.`,
  ].join("\n"),
  rack: [
    "Plain Rack is not exposed by default (Veria Labs). No framework mounts the case-conversion path on its",
    "own, so an affected Ruby running plain Rack is SAFE by this tool's verdict - with the caveat that",
    "application code which upcases strings received in a legacy encoding may still be vulnerable. Run",
    "config-scan to list case-conversion calls on request params (REVIEW, never proof).",
    `Source: Veria Labs verialabs.com/ruby2shell/. Checked ${CHECKED_AT}.`,
  ].join("\n"),
  versions: [
    "Fixed builds (18/11/2026): Ruby 4.0.10, 3.4.13, 3.3.14. Affected: 4.0.0-4.0.9, 3.4.0-3.4.12, 3.3.13 and",
    "earlier (back to 2.4.0). Ruby 3.2 and earlier are end of life and will not receive these fixes. The branch",
    "trap: 3.4.13 is fixed but 3.3.13 is still vulnerable - never compare against a plain numeric threshold.",
    "Distro builds (e.g. 3.3.0-1ubuntu) are UNKNOWN: the distro may have backported the fix.",
    `Sources: Ruby advisory 18/11/2026; Veria Labs. Checked ${CHECKED_AT}.`,
  ].join("\n"),
  products: [
    "Self-hosted products bundle their own Ruby, so the fix must come from the vendor (Veria Labs status table,",
    "updated 20/11/2026 11:58 UTC). Patched: GitLab 19.6.1 / 19.5.8 / 19.4.10, Mastodon 4.7.6 / 4.6.12 / 4.5.22 /",
    "4.4.29, OpenProject 17.9.8 / 17.8.3, Discourse base image 2.0.20261119-0203, Chatwoot 4.20.1. No fix yet: GitHub Enterprise",
    "Server 3.22.5 and earlier. Check with: ruby2shell check --product gitlab",
    "--product-version 19.6.0",
    `Source: Veria Labs verialabs.com/ruby2shell/. Checked ${CHECKED_AT}.`,
  ].join("\n"),
  siblings: [
    "The 18/11/2026 security release fixes 7 flaws in total (2 in string case conversion, 5 in the Regexp engine,",
    "by the advisory's own titles). Only GHSA-34m4-m9fh-gqp5 has a CVE so far. Ruby is aware of PoCs that prove",
    "RCE in some scenarios for 5 of the 7. This tool verdicts only on GHSA-34m4-m9fh-gqp5; the rest are a checklist:",
    ...SIBLING_FLAWS.slice(1).map((f) => `- ${f.ghsa}: ${f.title}. ${f.note}`),
    `Source: Ruby advisory 18/11/2026. Checked ${CHECKED_AT}.`,
  ].join("\n"),
};
