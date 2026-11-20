/**
 * Unit tests: version parsing, per-branch fixed-version compare
 * (the branch trap: 3.3.13 affected but 3.4.13 fixed), app
 * evidence parsing, product version checks, verdict matrix.
 * Fixture -v strings: the 3.4.12 text is RECORDED from the real
 * Ruby built from source on this build machine (20/11/2026);
 * the other texts are representative format with version numbers
 * from the Ruby 18/11/2026 security advisory (see
 * examples/README.md).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  detectSinatraStyle,
  dockerRubyVersion,
  gemVersionFromLock,
  parseAppDir,
} from "../dist/appconfig.js";
import { checkProduct, compareProductVersions } from "../dist/products.js";
import { decideVerdict } from "../dist/verdict.js";
import {
  SIBLING_FLAWS,
  fixedBuildFor,
  parseRubyVersion,
  patchVerdictFor,
} from "../dist/versions.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ex = (name) => readFileSync(join(ROOT, "examples", name), "utf8");

const V_3412 = ex("ruby-v-3.4.12.txt");
const V_3413 = ex("ruby-v-3.4.13.txt");
const V_3314 = ex("ruby-v-3.3.14.txt");
const V_3313 = ex("ruby-v-3.3.13.txt");
const V_409 = ex("ruby-v-4.0.9.txt");
const V_4010 = ex("ruby-v-4.0.10.txt");
const V_320 = ex("ruby-v-3.2.0.txt");
const V_239 = ex("ruby-v-2.3.9.txt");

function app(overrides = {}) {
  return {
    framework: "unknown",
    railsVersion: null,
    sinatraVersion: null,
    rackVersion: null,
    apiOnly: false,
    methodOverride: "unknown",
    dockerRuby: null,
    rubyVersionFile: null,
    caseConversionSites: [],
    evidencePaths: [],
    summary: "no framework evidence found",
    ...overrides,
  };
}

test("parseRubyVersion: recorded 3.4.12", () => {
  const v = parseRubyVersion(V_3412);
  assert.ok(v);
  assert.equal(v.raw, "3.4.12");
  assert.equal(v.line, "3.4");
  // The real 3.4.12 -v output carries no pN patch level.
  assert.equal(v.patchLevel, null);
  assert.equal(v.distroSuffix, null);
  assert.equal(v.engine, null);
});

test("parseRubyVersion: fixed builds parse", () => {
  assert.equal(parseRubyVersion(V_3413)?.raw, "3.4.13");
  assert.equal(parseRubyVersion(V_3314)?.raw, "3.3.14");
  assert.equal(parseRubyVersion(V_4010)?.raw, "4.0.10");
  assert.equal(parseRubyVersion(V_320)?.raw, "3.2.0");
  assert.equal(parseRubyVersion(V_239)?.raw, "2.3.9");
});

test("parseRubyVersion: distro suffix is detected", () => {
  const v = parseRubyVersion("ruby 3.3.0-1ubuntu");
  assert.ok(v);
  assert.equal(v.raw, "3.3.0");
  assert.equal(v.distroSuffix, "-1ubuntu");
});

test("parseRubyVersion: JRuby and TruffleRuby are engines, not CRuby", () => {
  const j = parseRubyVersion("jruby 9.4.8.0 (3.1.0) 2024-01-01 [x86_64-linux]");
  assert.ok(j);
  assert.equal(j.engine, "jruby");
  const t = parseRubyVersion(
    "truffleruby 24.1.0, like ruby 3.3.0, JVM [x86_64-linux]",
  );
  assert.ok(t);
  assert.equal(t.engine, "truffleruby");
});

test("parseRubyVersion: unparseable output is null", () => {
  assert.equal(parseRubyVersion("hello world"), null);
  assert.equal(parseRubyVersion(""), null);
  assert.equal(parseRubyVersion("ruby version unknown"), null);
});

test("fixed-build table: the branch trap", () => {
  // 3.3.13 is affected but 3.4.13 is fixed: never compare
  // against a plain numeric threshold.
  assert.equal(patchVerdictFor(parseRubyVersion(V_3313)), "affected");
  assert.equal(patchVerdictFor(parseRubyVersion(V_3413)), "fixed");
  assert.equal(patchVerdictFor(parseRubyVersion(V_3314)), "fixed");
  assert.equal(patchVerdictFor(parseRubyVersion(V_3412)), "affected");
  assert.equal(patchVerdictFor(parseRubyVersion(V_409)), "affected");
  assert.equal(patchVerdictFor(parseRubyVersion(V_4010)), "fixed");
  assert.equal(fixedBuildFor("3.3"), "3.3.14");
  assert.equal(fixedBuildFor("3.4"), "3.4.13");
  assert.equal(fixedBuildFor("4.0"), "4.0.10");
});

test("patch verdict: EOL lines have no fix, pre-2.4.0 predates", () => {
  assert.equal(patchVerdictFor(parseRubyVersion(V_320)), "eol-no-fix");
  assert.equal(
    patchVerdictFor(
      parseRubyVersion("ruby 3.2.9p0 (2025-01-01 revision x) [x86_64-linux]"),
    ),
    "eol-no-fix",
  );
  assert.equal(
    patchVerdictFor(
      parseRubyVersion("ruby 2.4.0p0 (2016-12-25 revision x) [x86_64-linux]"),
    ),
    "eol-no-fix",
  );
  assert.equal(patchVerdictFor(parseRubyVersion(V_239)), "predates");
});

test("patch verdict: a future line is unknown, never safe", () => {
  assert.equal(
    patchVerdictFor(
      parseRubyVersion("ruby 4.1.0p0 (2027-01-01 revision x) [x86_64-linux]"),
    ),
    "unknown-line",
  );
});

test("gemVersionFromLock: rails / sinatra / rack", () => {
  const lock = ex("app-rails/Gemfile.lock");
  assert.equal(gemVersionFromLock(lock, "rails"), "7.1.3");
  assert.equal(gemVersionFromLock(lock, "rack"), "3.0.8");
  assert.equal(gemVersionFromLock(lock, "sinatra"), null);
  assert.equal(
    gemVersionFromLock(ex("app-sinatra-classic/Gemfile.lock"), "sinatra"),
    "4.1.0",
  );
});

test("dockerRubyVersion: FROM ruby:X.Y", () => {
  assert.equal(dockerRubyVersion(ex("Dockerfile-vulnerable")), "3.4.12");
  assert.equal(dockerRubyVersion(ex("Dockerfile-fixed")), "3.4.13");
  assert.equal(dockerRubyVersion("FROM ubuntu:24.04\n"), null);
});

test("detectSinatraStyle: classic vs modular", () => {
  assert.equal(
    detectSinatraStyle(['require "sinatra"\nget "/" do end']),
    "classic",
  );
  assert.equal(
    detectSinatraStyle([
      'require "sinatra/base"\nclass App < Sinatra::Base\nend',
    ]),
    "modular",
  );
  assert.equal(detectSinatraStyle(['require "rack"']), "unknown");
});

test("parseAppDir: default Rails", () => {
  const parsed = parseAppDir(join(ROOT, "examples", "app-rails"));
  assert.equal(parsed.framework, "rails");
  assert.equal(parsed.railsVersion, "7.1.3");
  assert.equal(parsed.methodOverride, "framework-default");
  assert.equal(parsed.apiOnly, false);
  assert.equal(parsed.dockerRuby, null);
  assert.equal(parsed.rubyVersionFile, "3.4.12");
  assert.equal(parsed.caseConversionSites.length, 1);
  assert.match(parsed.caseConversionSites[0].file, /search_controller/);
});

test("parseAppDir: classic Sinatra", () => {
  const parsed = parseAppDir(join(ROOT, "examples", "app-sinatra-classic"));
  assert.equal(parsed.framework, "sinatra-classic");
  assert.equal(parsed.sinatraVersion, "4.1.0");
  assert.equal(parsed.methodOverride, "framework-default");
});

test("parseAppDir: plain Rack", () => {
  const parsed = parseAppDir(join(ROOT, "examples", "app-rack"));
  assert.equal(parsed.framework, "rack");
  assert.equal(parsed.rackVersion, "3.0.8");
  assert.equal(parsed.methodOverride, "absent");
  assert.equal(parsed.caseConversionSites.length, 0);
});

test("parseAppDir: Rails api_only", () => {
  const parsed = parseAppDir(join(ROOT, "examples", "app-rails-api-only"));
  assert.equal(parsed.framework, "rails-api-only");
  assert.equal(parsed.apiOnly, true);
  assert.equal(parsed.methodOverride, "unknown");
});

test("parseAppDir: Dockerfile ruby version is evidence", () => {
  const dir = mkdtempSync(join(tmpdir(), "ruby2shell-app-"));
  writeFileSync(join(dir, "Dockerfile"), "FROM ruby:3.4.12\nWORKDIR /app\n");
  const parsed = parseAppDir(dir);
  assert.equal(parsed.dockerRuby, "3.4.12");
  assert.equal(parsed.framework, "unknown");
});

test("parseAppDir: explicit MethodOverride in config.ru", () => {
  const dir = mkdtempSync(join(tmpdir(), "ruby2shell-app-"));
  mkdirSync(join(dir, "config"), { recursive: true });
  writeFileSync(join(dir, "Gemfile.lock"), "GEM\n  specs:\n    rack (3.0.8)\n");
  writeFileSync(
    join(dir, "config.ru"),
    'require "rack"\nuse Rack::MethodOverride\nrun ->(env) { [200, {}, ["ok"]] }\n',
  );
  const parsed = parseAppDir(dir);
  assert.equal(parsed.framework, "rack");
  assert.equal(parsed.methodOverride, "present");
});

test("product versions: GitLab fixed branches", () => {
  assert.equal(checkProduct("gitlab", "19.6.0").status, "vulnerable");
  assert.equal(checkProduct("gitlab", "19.6.1").status, "patched");
  assert.equal(checkProduct("gitlab", "19.5.7").status, "vulnerable");
  assert.equal(checkProduct("gitlab", "19.5.8").status, "patched");
  assert.equal(checkProduct("gitlab", "19.4.9").status, "vulnerable");
  assert.equal(checkProduct("gitlab", "19.4.10").status, "patched");
  assert.equal(checkProduct("gitlab", "19.7.0").status, "patched");
  assert.equal(checkProduct("gitlab", "19.3.0").status, "vulnerable");
});

test("product versions: GHES and Chatwoot have no fix yet", () => {
  const ghes = checkProduct("ghes", "3.22.5");
  assert.equal(ghes.status, "vulnerable");
  assert.equal(ghes.fixedVersions.length, 0);
  assert.match(ghes.reason, /no fixed release/);
  assert.equal(checkProduct("ghes", "3.22.6").status, "unknown");
  assert.equal(checkProduct("chatwoot", "4.20.0").status, "vulnerable");
  assert.equal(checkProduct("chatwoot", "4.21.0").status, "unknown");
});

test("product versions: Mastodon / OpenProject / Discourse", () => {
  assert.equal(checkProduct("mastodon", "4.7.5").status, "vulnerable");
  assert.equal(checkProduct("mastodon", "4.7.6").status, "patched");
  assert.equal(checkProduct("mastodon", "4.6.11").status, "vulnerable");
  assert.equal(checkProduct("mastodon", "4.6.12").status, "patched");
  assert.equal(checkProduct("mastodon", "4.4.28").status, "vulnerable");
  assert.equal(checkProduct("mastodon", "4.4.29").status, "patched");
  assert.equal(checkProduct("openproject", "17.9.7").status, "vulnerable");
  assert.equal(checkProduct("openproject", "17.9.8").status, "patched");
  assert.equal(checkProduct("openproject", "17.8.2").status, "vulnerable");
  assert.equal(checkProduct("openproject", "17.8.3").status, "patched");
  assert.equal(
    checkProduct("discourse", "2.0.20261119-0202").status,
    "vulnerable",
  );
  assert.equal(
    checkProduct("discourse", "2.0.20261119-0203").status,
    "patched",
  );
  assert.equal(checkProduct("unknown-product", "1.0").status, "unknown");
});

test("compareProductVersions: date-style versions", () => {
  assert.equal(
    compareProductVersions("2.0.20261119-0203", "2.0.20261119-0202"),
    1,
  );
  assert.equal(compareProductVersions("19.6.1", "19.6.0"), 1);
  assert.equal(compareProductVersions("4.7.6", "4.7.6"), 0);
});

test("verdict matrix: all four verdicts", () => {
  const railsApp = app({
    framework: "rails",
    railsVersion: "7.1.3",
    methodOverride: "framework-default",
    summary: "Rails 7.1.3 (default config)",
  });
  const rackApp = app({
    framework: "rack",
    rackVersion: "3.0.8",
    methodOverride: "absent",
    summary: "plain Rack - not exposed by default",
  });
  const base = {
    app: railsApp,
    appSource: "examples/app-rails",
    rawVersion: V_3412,
    product: null,
    productName: null,
  };
  // EXPOSED: affected version + default Rails.
  assert.equal(
    decideVerdict({ ...base, version: parseRubyVersion(V_3412) }).verdict,
    "EXPOSED",
  );
  // SAFE: fixed version, same app.
  assert.equal(
    decideVerdict({ ...base, version: parseRubyVersion(V_3413) }).verdict,
    "SAFE",
  );
  // SAFE: affected version, plain Rack.
  assert.equal(
    decideVerdict({
      ...base,
      version: parseRubyVersion(V_3412),
      app: rackApp,
    }).verdict,
    "SAFE",
  );
  // AT-RISK: affected version, no app evidence.
  assert.equal(
    decideVerdict({ ...base, version: parseRubyVersion(V_3412), app: null })
      .verdict,
    "AT-RISK",
  );
  // AT-RISK: EOL line, no fix exists.
  assert.equal(
    decideVerdict({ ...base, version: parseRubyVersion(V_320) }).verdict,
    "AT-RISK",
  );
  // UNKNOWN: version unparseable.
  assert.equal(decideVerdict({ ...base, version: null }).verdict, "UNKNOWN");
  // UNKNOWN: distro build.
  assert.equal(
    decideVerdict({
      ...base,
      version: parseRubyVersion("ruby 3.3.0-1ubuntu"),
    }).verdict,
    "UNKNOWN",
  );
  // AT-RISK: Rails api_only.
  assert.equal(
    decideVerdict({
      ...base,
      version: parseRubyVersion(V_3412),
      app: app({
        framework: "rails-api-only",
        railsVersion: "7.1.3",
        apiOnly: true,
        methodOverride: "unknown",
        summary: "Rails 7.1.3 (api_only)",
      }),
    }).verdict,
    "AT-RISK",
  );
  // SAFE: predates the flaw.
  assert.equal(
    decideVerdict({ ...base, version: parseRubyVersion(V_239) }).verdict,
    "SAFE",
  );
});

test("verdict: product check drives its own verdict", () => {
  const base = {
    version: null,
    app: null,
    appSource: "",
    rawVersion: "",
    productName: "gitlab",
  };
  assert.equal(
    decideVerdict({
      ...base,
      product: checkProduct("gitlab", "19.6.0"),
    }).verdict,
    "EXPOSED",
  );
  assert.equal(
    decideVerdict({
      ...base,
      product: checkProduct("gitlab", "19.6.1"),
    }).verdict,
    "SAFE",
  );
  assert.equal(
    decideVerdict({
      ...base,
      product: checkProduct("ghes", "3.22.6"),
    }).verdict,
    "UNKNOWN",
  );
});

test("verdict: explicit MethodOverride on plain Rack is EXPOSED", () => {
  const result = decideVerdict({
    version: parseRubyVersion(V_3412),
    app: app({
      framework: "rack",
      rackVersion: "3.0.8",
      methodOverride: "present",
      summary: "plain Rack - not exposed by default",
    }),
    appSource: "tmp",
    rawVersion: V_3412,
    product: null,
    productName: null,
  });
  assert.equal(result.verdict, "EXPOSED");
});

test("verdict: Rack app whose own code case-converts params is AT-RISK", () => {
  const result = decideVerdict({
    version: parseRubyVersion(V_3412),
    app: app({
      framework: "rack",
      rackVersion: "3.0.8",
      methodOverride: "absent",
      summary: "plain Rack - not exposed by default",
      caseConversionSites: [
        { file: "app.rb", line: 3, text: "name = params[:name].upcase" },
      ],
    }),
    appSource: "tmp",
    rawVersion: V_3412,
    product: null,
    productName: null,
  });
  assert.equal(result.verdict, "AT-RISK");
});

test("siblings: seven flaws, real GHSA IDs, first is Ruby2Shell", () => {
  assert.equal(SIBLING_FLAWS.length, 7);
  assert.equal(SIBLING_FLAWS[0].ghsa, "GHSA-34m4-m9fh-gqp5");
  const ids = SIBLING_FLAWS.map((f) => f.ghsa);
  assert.ok(ids.includes("GHSA-7x2q-68qv-6p8x"));
  assert.ok(ids.includes("GHSA-87fm-7w84-j2px"));
  assert.ok(ids.includes("GHSA-wpqw-5qxg-m68r"));
  assert.ok(ids.includes("GHSA-3p8q-wmhx-vm2w"));
  assert.ok(ids.includes("GHSA-7whj-cfh7-xgm4"));
  assert.ok(ids.includes("GHSA-pvgc-g7gj-pv6h"));
  for (const f of SIBLING_FLAWS) {
    assert.match(f.ghsa, /^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$/);
  }
});

test("discoverRuby --no-system only searches given dirs", async () => {
  const { discoverRuby } = await import("../dist/discover.js");
  const { a } = (() => {
    const work = mkdtempSync(join(tmpdir(), "ruby2shell-disc-"));
    const v = join(work, "v.txt");
    writeFileSync(v, ex("ruby-v-3.4.12.txt"));
    mkdirSync(join(work, "ruby-3412", "bin"), { recursive: true });
    const script = join(work, "ruby-3412", "bin", "ruby");
    writeFileSync(script, `#!/bin/sh\ncat "${v}"\n`);
    return { a: join(work, "ruby-3412") };
  })();
  const found = discoverRuby([a], { system: false });
  assert.deepEqual(found, [join(a, "bin", "ruby")]);
});

test("trigger shape: 21 sharp-s characters is the overflow count", () => {
  // The flaw: each sharp-s adds one byte to the output, and the
  // buffer is the input length plus 20 bytes. 21 sharp-s chars
  // overflow it by one byte. The character is written here as an
  // ASCII escape so the source stays pure ASCII.
  const sharpS = "\u00DF";
  assert.equal(sharpS.length, 1);
  assert.equal(sharpS.repeat(21).length, 21);
});
