/**
 * E2E tests: full CLI flows on fixture Ruby installs (fake `ruby`
 * shell scripts printing fixture -v outputs in tmp) and fixture
 * app dirs. Exit codes 0/1/2, --json shape, and the live check
 * against a real Ruby when RUBY2SHELL_REAL_RUBY points at one
 * (set by the builder; skipped in CI where no Ruby exists).
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
  chmodSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "dist", "cli.js");
const ex = (name) => readFileSync(join(ROOT, "examples", name), "utf8");

function run(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: cwd ?? ROOT,
  });
}

function makeFakeRuby(dir, versionFile) {
  mkdirSync(join(dir, "bin"), { recursive: true });
  const script = join(dir, "bin", "ruby");
  writeFileSync(
    script,
    `#!/bin/sh\nif [ "$1" = "-v" ]; then cat "${versionFile}"; exit 0; fi\nexit 0\n`,
  );
  chmodSync(script, 0o755);
  return dir;
}

function fleet() {
  const work = mkdtempSync(join(tmpdir(), "ruby2shell-fleet-"));
  const v3412 = join(work, "v3412.txt");
  const v3413 = join(work, "v3413.txt");
  const v320 = join(work, "v320.txt");
  writeFileSync(v3412, ex("ruby-v-3.4.12.txt"));
  writeFileSync(v3413, ex("ruby-v-3.4.13.txt"));
  writeFileSync(v320, ex("ruby-v-3.2.0.txt"));
  const a = makeFakeRuby(join(work, "ruby-3412"), v3412);
  const b = makeFakeRuby(join(work, "ruby-3413"), v3413);
  const c = makeFakeRuby(join(work, "ruby-320"), v320);
  return { work, a, b, c };
}

test("scan: fixture fleet verdicts + exit codes", () => {
  const { a, b, c } = fleet();
  const appDir = join(ROOT, "examples", "app-rails");
  const res = run(["scan", "--dirs", a, b, c, "--app", appDir, "--no-system"]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /EXPOSED 1/);
  assert.match(res.stdout, /AT-RISK 1/);
  assert.match(res.stdout, /SAFE 1/);
  assert.match(res.stdout, /3 install\(s\) scanned/);
  assert.match(res.stdout, /3\.4\.12/);
  assert.match(res.stdout, /Exposure conditions only/);
});

test("scan --json: shape + evidence", () => {
  const { a, b } = fleet();
  const res = run([
    "scan",
    "--dirs",
    a,
    b,
    "--app",
    join(ROOT, "examples", "app-rails"),
    "--no-system",
    "--json",
  ]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  const data = JSON.parse(res.stdout);
  assert.equal(data.tool, "ruby2shell");
  assert.equal(data.cve, "CVE-2026-132825");
  assert.equal(data.installs.length, 2);
  const exposed = data.installs.find((i) => i.version === "3.4.12");
  assert.equal(exposed.verdict, "EXPOSED");
  assert.equal(exposed.framework, "rails");
  assert.ok(exposed.reasons.length >= 2);
  const safe = data.installs.find((i) => i.version === "3.4.13");
  assert.equal(safe.verdict, "SAFE");
});

test("scan with no Ruby exits 2", () => {
  const empty = mkdtempSync(join(tmpdir(), "ruby2shell-empty-"));
  // --no-system keeps the test deterministic: CI runners ship a
  // system Ruby, which the default scan would (correctly) find.
  const res = run(["scan", "--dirs", empty, "--no-system"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr + res.stdout, /no Ruby install found/);
});

test("check a missing dir exits 2", () => {
  const res = run(["check", "/nonexistent/ruby-dir-xyz"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /no ruby binary found/);
});

test("check: per-verdict flows + exit codes", () => {
  const { a, b, c } = fleet();
  const appDir = join(ROOT, "examples", "app-rails");
  let res = run(["check", a, "--app", appDir]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /verdict: EXPOSED/);
  assert.match(
    res.stdout,
    /deciding condition: affected version \+ exposed framework/,
  );
  res = run(["check", b, "--app", appDir]);
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /verdict: SAFE/);
  res = run(["check", c, "--app", appDir]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /verdict: AT-RISK/);
  assert.match(res.stdout, /no fix exists/);
});

test("check: bare version strings", () => {
  let res = run([
    "check",
    "3.4.12",
    "--app",
    join(ROOT, "examples", "app-rails"),
  ]);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /verdict: EXPOSED/);
  res = run(["check", "3.4.13"]);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /verdict: SAFE/);
  res = run(["check", "3.3.0-1ubuntu"]);
  assert.equal(res.status, 2);
  assert.match(res.stdout, /verdict: UNKNOWN/);
  assert.match(res.stdout, /distro build/);
  res = run(["check", "2.3.9"]);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /predates the flaw/);
});

test("check --product: GitLab / GHES / Mastodon", () => {
  let res = run([
    "check",
    "--product",
    "gitlab",
    "--product-version",
    "19.6.0",
  ]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /verdict: EXPOSED/);
  res = run(["check", "--product", "gitlab", "--product-version", "19.6.1"]);
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /verdict: SAFE/);
  res = run(["check", "--product", "ghes", "--product-version", "3.22.5"]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /no fixed release has been published yet/);
  res = run(["check", "--product", "mastodon", "--product-version", "4.7.6"]);
  assert.equal(res.status, 0, res.stdout + res.stderr);
  res = run(["check", "--product", "nope", "--product-version", "1.0"]);
  assert.equal(res.status, 2);
  assert.match(res.stdout, /verdict: UNKNOWN/);
});

test("config-scan: Rails / Sinatra / Rack / api_only", () => {
  let res = run(["config-scan", join(ROOT, "examples", "app-rails")]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /framework: rails/);
  assert.match(res.stdout, /rack methodoverride: framework-default/);
  assert.match(res.stdout, /search_controller\.rb:3/);
  res = run(["config-scan", join(ROOT, "examples", "app-sinatra-classic")]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /framework: sinatra-classic/);
  res = run(["config-scan", join(ROOT, "examples", "app-rack")]);
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /framework: rack/);
  assert.match(res.stdout, /not exposed by default/);
  res = run(["config-scan", join(ROOT, "examples", "app-rails-api-only")]);
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /framework: rails-api-only/);
  res = run(["config-scan", join(ROOT, "examples", "app-rails"), "--json"]);
  assert.equal(res.status, 1);
  const data = JSON.parse(res.stdout);
  assert.equal(data.framework, "rails");
  assert.equal(data.caseConversionSites.length, 1);
});

test("config-scan: empty dir exits 2", () => {
  const empty = mkdtempSync(join(tmpdir(), "ruby2shell-empty-"));
  const res = run(["config-scan", empty]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /no app evidence found/);
});

test("playbook: upgrade paths + vendor fixes + PoC date", () => {
  const res = run(["playbook"]);
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /3\.3\.14, 3\.4\.13 or 4\.0\.10/);
  assert.match(res.stdout, /GitLab 19\.6\.1 \/ 19\.5\.8 \/ 19\.4\.10/);
  assert.match(res.stdout, /25 November 2026/);
  assert.match(res.stdout, /no fixed release yet/);
  assert.match(res.stdout, /never does it/);
  const json = run(["playbook", "--json"]);
  assert.equal(json.status, 0);
  const data = JSON.parse(json.stdout);
  assert.equal(data.steps.length, 7);
});

test("explain: topics cite sources + check date", () => {
  for (const topic of [
    "CVE-2026-132825",
    "GHSA-34m4-m9fh-gqp5",
    "EXPOSED",
    "AT-RISK",
    "SAFE",
    "UNKNOWN",
    "rails",
    "sinatra",
    "rack",
    "versions",
    "products",
    "siblings",
  ]) {
    const res = run(["explain", topic]);
    assert.equal(res.status, 0, `explain ${topic}: ${res.stderr}`);
    assert.ok(res.stdout.length > 100, topic);
  }
  const sib = run(["explain", "siblings"]);
  assert.match(sib.stdout, /GHSA-7x2q-68qv-6p8x/);
  assert.match(sib.stdout, /GHSA-pvgc-g7gj-pv6h/);
  const bad = run(["explain", "nope"]);
  assert.equal(bad.status, 2);
});

test("init: writes a valid config", () => {
  const dir = mkdtempSync(join(tmpdir(), "ruby2shell-init-"));
  const res = run(["init"], dir);
  assert.equal(res.status, 0, res.stdout + res.stderr);
  assert.match(res.stdout, /wrote ruby2shell\.config\.json/);
  const cfg = JSON.parse(
    readFileSync(join(dir, "ruby2shell.config.json"), "utf8"),
  );
  assert.ok(Array.isArray(cfg.scanDirs));
});

test("help and version", () => {
  assert.equal(run(["--help"]).status, 0);
  assert.match(run(["--help"]).stdout, /CVE-2026-132825/);
  assert.match(run(["--version"]).stdout, /ruby2shell 0\.1\.0/);
  assert.equal(run(["bogus-command"]).status, 2);
});

test("live check: real Ruby 3.4.12 is EXPOSED with the Rails app", () => {
  const realRuby = process.env.RUBY2SHELL_REAL_RUBY;
  if (!realRuby || !existsSync(realRuby)) {
    test.skip("no real Ruby on this host (RUBY2SHELL_REAL_RUBY unset)");
    return;
  }
  const res = run([
    "check",
    realRuby,
    "--app",
    join(ROOT, "examples", "app-rails"),
  ]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /ruby 3\.4\.12/);
  assert.match(res.stdout, /verdict: EXPOSED/);
});
