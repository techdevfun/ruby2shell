#!/usr/bin/env node
/**
 * ruby2shell - is this Ruby install, or this app, exposed to
 * Ruby2Shell (CVE-2026-132825 / GHSA-34m4-m9fh-gqp5)?
 * Condition-based: Ruby patch level vs the 18/11/2026 fixed
 * builds + framework exposure (default Rails / classic Sinatra
 * reachable, plain Rack not exposed by default) + sharp-s input
 * reachability from config evidence, checked together on the
 * live host.
 * Zero runtime dependencies. No network calls in scan/check.
 * Never sends a payload, never runs exploit input: probing runs
 * only `ruby -v` and reads files.
 */
import { existsSync, writeFileSync } from "node:fs";
import { parseAppDir, parseConfigTarget } from "./appconfig.js";
import { CHECKED_AT, CVE_ID, GHSA_ID, VERSION } from "./cli-version.js";
import { discoverRuby, probeRuby, resolveBinary } from "./discover.js";
import { EXPLAIN_TOPICS, PLAYBOOK_STEPS } from "./playbook.js";
import { checkProduct, type ProductCheck } from "./products.js";
import {
  SCOPE_LINE,
  installToReport,
  renderCheckTable,
  renderConfigTable,
  renderScanTable,
  scanJson,
  verdictExitCode,
  type InstallReport,
} from "./report.js";
import { decideVerdict } from "./verdict.js";
import { parseRubyVersion, type ParsedVersion } from "./versions.js";

function printHelp(): void {
  console.log(`ruby2shell ${VERSION} - is this Ruby exposed to Ruby2Shell (${CVE_ID}, ${GHSA_ID})?
${SCOPE_LINE}

Usage:
  ruby2shell scan [--dirs <dir>...] [--app <dir>] [--no-system] [--json]
  ruby2shell check <ruby-dir-or-version> [--app <dir>] [--json]
  ruby2shell check --product <name> --product-version <ver> [--json]
  ruby2shell config-scan <app-dir> [--json]
  ruby2shell playbook [--json]
  ruby2shell explain <topic>
  ruby2shell init
  ruby2shell --help | --version

Commands:
  scan         Discover Ruby installs (PATH, rbenv, rvm, system
               dirs, --dirs) and verdict each one: EXPOSED /
               AT-RISK / SAFE / UNKNOWN. With --app, framework
               exposure is read from that app.
  check        Verdict a single Ruby install directory, a binary,
               or a bare version string (e.g. 3.4.12). With
               --product, verdict a self-hosted product version
               instead (gitlab, ghes, chatwoot, mastodon,
               openproject, discourse).
  config-scan  Parse an app dir: Gemfile.lock, config.ru,
               Dockerfile, .ruby-version, case-conversion calls
               on request params. No Ruby version needed.
  playbook     First-hour stopgap: upgrade path per branch, EOL
               warning, vendor-product fixed versions, verification.
  explain      Background on a topic: ${CVE_ID}, ${GHSA_ID},
               EXPOSED, AT-RISK, SAFE, UNKNOWN, rails, sinatra,
               rack, versions, products, siblings.
  init         Write ruby2shell.config.json for this directory.

Exit codes (scan/check/config-scan):
  0  no EXPOSED install (scan) / SAFE (check) / not exposed by
     default (config-scan)
  1  >=1 EXPOSED install (scan) / EXPOSED or AT-RISK (check) /
     exposed framework found (config-scan)
  2  usage error, no Ruby found, or UNKNOWN verdict (check)

Flags:
  --dirs <dir>...        Extra dirs to search for Ruby installs.
  --no-system            Scan only --dirs (skip PATH, rbenv, rvm,
                         system dirs). Keeps a fleet scan deterministic.
  --app <dir>            App dir to read framework evidence from.
  --product <name>       Self-hosted product to check (check only).
  --product-version <v>  Product version to check (check only).
  --json                 Machine-readable output.

Facts checked ${CHECKED_AT}: fixed Ruby 3.3.14 / 3.4.13 / 4.0.10.
Ruby rates the flaw Critical; MITRE CNA CVSS 3.1 is 7.4 High
(AV:L/AC:H). No exploitation in the wild reported as of
${CHECKED_AT}; Veria Labs publishes a PoC on 25/11/2026.`);
}

interface GlobalOpts {
  json: boolean;
  dirs: string[];
  app: string | null;
  product: string | null;
  productVersion: string | null;
  noSystem: boolean;
}

function parseOpts(args: string[]): { opts: GlobalOpts; rest: string[] } {
  const opts: GlobalOpts = {
    json: false,
    dirs: [],
    app: null,
    product: null,
    productVersion: null,
    noSystem: false,
  };
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--json") opts.json = true;
    else if (arg === "--no-system") opts.noSystem = true;
    else if (arg === "--dirs") {
      i++;
      while (i < args.length && !args[i].startsWith("--")) {
        opts.dirs.push(args[i]);
        i++;
      }
      i--;
    } else if (arg === "--app") {
      i++;
      opts.app = args[i] ?? null;
    } else if (arg === "--product") {
      i++;
      opts.product = args[i] ?? null;
    } else if (arg === "--product-version") {
      i++;
      opts.productVersion = args[i] ?? null;
    } else if (arg.startsWith("--")) {
      console.error(`unknown flag: ${arg}`);
      process.exit(2);
    } else {
      rest.push(arg);
    }
  }
  return { opts, rest };
}

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(2);
}

function cmdScan(opts: GlobalOpts): number {
  const binaries = discoverRuby(opts.dirs, { system: !opts.noSystem });
  if (binaries.length === 0) {
    if (opts.json) {
      console.log(JSON.stringify({ error: "no Ruby install found" }, null, 2));
    } else {
      console.error(
        "no Ruby install found (PATH, rbenv, rvm, system dirs, --dirs). Pass --dirs <dir> with the install.",
      );
    }
    return 2;
  }
  let app = null as ReturnType<typeof parseAppDir> | null;
  let appSource: string | null = null;
  if (opts.app) {
    if (!existsSync(opts.app)) fail(`app dir not found: ${opts.app}`);
    app = parseAppDir(opts.app);
    appSource = opts.app;
  }
  const reports: InstallReport[] = binaries.map((binary) => {
    const install = probeRuby(binary);
    const result = decideVerdict({
      version: install.version,
      app,
      appSource: appSource ?? "",
      rawVersion: install.rawVersion,
      product: null,
      productName: null,
    });
    return installToReport(install, result, app, appSource, null, null);
  });
  if (opts.json) {
    console.log(JSON.stringify(scanJson(reports, appSource), null, 2));
  } else {
    console.log(renderScanTable(reports));
  }
  const worst = reports.some((r) => r.verdict === "EXPOSED")
    ? 1
    : reports.some((r) => r.verdict === "AT-RISK")
      ? 1
      : reports.some((r) => r.verdict === "UNKNOWN")
        ? 2
        : 0;
  return worst;
}

interface CheckSubject {
  version: ParsedVersion | null;
  rawVersion: string;
  binary: string;
  dir: string;
  product: ProductCheck | null;
  productName: string | null;
}

/** Resolve what `check` verdicts: a product, a version string, or a Ruby install. */
function resolveCheckSubject(
  target: string | null,
  opts: GlobalOpts,
): CheckSubject {
  if (opts.product) {
    if (!opts.productVersion) {
      fail("--product needs --product-version <ver>");
    }
    return {
      version: null,
      rawVersion: "",
      binary: "(product check, no Ruby binary)",
      dir: opts.product,
      product: checkProduct(opts.product, opts.productVersion),
      productName: opts.product,
    };
  }
  if (!target) fail("check needs <ruby-dir-or-version> or --product");
  if (/^\d/.test(target)) {
    // Bare version string, e.g. 3.4.12 or 3.3.0-1ubuntu.
    const version = parseRubyVersion(`ruby ${target}`);
    if (!version) fail(`could not parse version: ${target}`);
    return {
      version,
      rawVersion: `ruby ${target}`,
      binary: "(version string, no binary)",
      dir: target,
      product: null,
      productName: null,
    };
  }
  const resolved = resolveBinary(target);
  if (!resolved) fail(`no ruby binary found under: ${target}`);
  const install = probeRuby(resolved);
  if (install.error) {
    console.error(`probe error: ${install.error}`);
  }
  return {
    version: install.version,
    rawVersion: install.rawVersion,
    binary: resolved,
    dir: install.dir,
    product: null,
    productName: null,
  };
}

function cmdCheck(target: string | null, opts: GlobalOpts): number {
  const { version, rawVersion, binary, dir, product, productName } =
    resolveCheckSubject(target, opts);
  let app = null as ReturnType<typeof parseAppDir> | null;
  let appSource: string | null = null;
  if (opts.app) {
    if (!existsSync(opts.app)) fail(`app dir not found: ${opts.app}`);
    app = parseAppDir(opts.app);
    appSource = opts.app;
  }
  const result = decideVerdict({
    version,
    app,
    appSource: appSource ?? "",
    rawVersion,
    product,
    productName,
  });
  const report = installToReport(
    {
      dir,
      binary,
      rawVersion,
      version,
      error: null,
    },
    result,
    app,
    appSource,
    product,
    productName,
  );
  if (opts.json) {
    console.log(JSON.stringify(scanJson([report], appSource), null, 2));
  } else {
    console.log(renderCheckTable(report));
  }
  return verdictExitCode(result.verdict);
}

function cmdConfigScan(target: string, opts: GlobalOpts): number {
  const res = parseConfigTarget(target);
  if ("error" in res) fail(res.error);
  const parsed = res.parsed;
  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          tool: "ruby2shell",
          version: VERSION,
          checkedAt: CHECKED_AT,
          app: target,
          framework: parsed.framework,
          summary: parsed.summary,
          railsVersion: parsed.railsVersion,
          sinatraVersion: parsed.sinatraVersion,
          rackVersion: parsed.rackVersion,
          apiOnly: parsed.apiOnly,
          methodOverride: parsed.methodOverride,
          dockerRuby: parsed.dockerRuby,
          rubyVersionFile: parsed.rubyVersionFile,
          caseConversionSites: parsed.caseConversionSites,
          evidencePaths: parsed.evidencePaths,
          scope: SCOPE_LINE,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(renderConfigTable(parsed, target));
  }
  if (parsed.framework === "unknown") return 2;
  return parsed.framework === "rails" || parsed.framework === "sinatra-classic"
    ? 1
    : 0;
}

function cmdPlaybook(opts: GlobalOpts): void {
  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          tool: "ruby2shell",
          version: VERSION,
          checkedAt: CHECKED_AT,
          steps: PLAYBOOK_STEPS,
          scope: SCOPE_LINE,
        },
        null,
        2,
      ),
    );
    return;
  }
  console.log(
    "ruby2shell playbook - first hour after the 18/11/2026 Ruby2Shell disclosure",
  );
  for (const step of PLAYBOOK_STEPS) {
    console.log(`\n${step.title}\n  ${step.detail}`);
  }
  console.log(`\n${SCOPE_LINE}`);
}

function cmdExplain(topic: string): number {
  const text = EXPLAIN_TOPICS[topic];
  if (!text) {
    console.error(
      `unknown topic: ${topic}. Topics: ${Object.keys(EXPLAIN_TOPICS).join(", ")}`,
    );
    return 2;
  }
  console.log(text);
  return 0;
}

function cmdInit(): void {
  const config = {
    scanDirs: [] as string[],
    appDir: "",
    notes:
      "Run `ruby2shell scan --app <dir>` on each host. Set appDir to the app that serves traffic.",
  };
  writeFileSync(
    "ruby2shell.config.json",
    JSON.stringify(config, null, 2) + "\n",
  );
  console.log("wrote ruby2shell.config.json");
  console.log("run on each host: ruby2shell scan --app ./my-rails-app");
}

function main(): void {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printHelp();
    return;
  }
  if (argv[0] === "--version" || argv[0] === "-V") {
    console.log(`ruby2shell ${VERSION}`);
    return;
  }
  const [command, ...rest] = argv;
  const { opts, rest: positional } = parseOpts(rest);
  let code = 0;
  switch (command) {
    case "scan":
      code = cmdScan(opts);
      break;
    case "check":
      if (opts.product) {
        if (positional.length > 0)
          fail("check --product takes no positional argument");
        code = cmdCheck(null, opts);
      } else {
        if (positional.length !== 1)
          fail("check needs exactly one <ruby-dir-or-version>");
        code = cmdCheck(positional[0], opts);
      }
      break;
    case "config-scan":
      if (positional.length !== 1)
        fail("config-scan needs exactly one <app-dir>");
      code = cmdConfigScan(positional[0], opts);
      break;
    case "playbook":
      cmdPlaybook(opts);
      break;
    case "explain":
      if (positional.length !== 1) fail("explain needs exactly one <topic>");
      code = cmdExplain(positional[0]);
      break;
    case "init":
      cmdInit();
      break;
    default:
      console.error(`unknown command: ${command}`);
      printHelp();
      code = 2;
  }
  process.exit(code);
}

main();
