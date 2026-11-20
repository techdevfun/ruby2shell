/**
 * App evidence: framework exposure and input reachability, read
 * from the app's own files. Nothing here is probed over the
 * network and no payload is ever sent: the evidence is Gemfile /
 * Gemfile.lock, config.ru, config/application.rb, Dockerfile,
 * .ruby-version, and a read-only scan of Ruby sources for
 * case-conversion calls on request parameters.
 *
 * Framework exposure (Veria Labs, 20/11/2026): Rails is affected
 * in its default configuration, classic-style Sinatra is
 * affected, other frameworks and plain Rack are not exposed by
 * default. The Rails path is Rack::MethodOverride, which calls
 * .upcase on the attacker-controlled `_method` parameter with no
 * authentication (confirmed at runtime with benign
 * instrumentation by the Semgrep detection-scripts team).
 *
 * A route that calls upcase / downcase / swapcase / casecmp? on
 * request params is a REVIEW hit: it shows input reaches case
 * conversion, it never proves exploitability.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

export type Framework =
  | "rails"
  | "rails-api-only"
  | "sinatra-classic"
  | "sinatra-modular"
  | "rack"
  | "other"
  | "unknown";

export interface CaseConversionSite {
  file: string;
  line: number;
  text: string;
}

export interface ParsedApp {
  framework: Framework;
  railsVersion: string | null;
  sinatraVersion: string | null;
  rackVersion: string | null;
  /** Rails api_only flag seen in config/application.rb. */
  apiOnly: boolean;
  /** Rack::MethodOverride evidence: framework-default | present | absent | unknown. */
  methodOverride: "framework-default" | "present" | "absent" | "unknown";
  /** Ruby version from Dockerfile FROM ruby:X.Y, or null. */
  dockerRuby: string | null;
  /** Ruby version from .ruby-version, or null. */
  rubyVersionFile: string | null;
  /** Case-conversion calls on request params (REVIEW, never proof). */
  caseConversionSites: CaseConversionSite[];
  /** Files actually read, for evidence. */
  evidencePaths: string[];
  /** One-line framework summary for tables. */
  summary: string;
}

function readIfExists(path: string): string | null {
  try {
    if (!existsSync(path)) return null;
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

/** Gem version from a Gemfile.lock `    rails (7.1.3)` line. */
export function gemVersionFromLock(
  lockText: string,
  gem: string,
): string | null {
  const re = new RegExp(`^\\s{4}${gem} \\(([^)]+)\\)`, "m");
  const m = lockText.match(re);
  return m ? m[1] : null;
}

/** Ruby version from a Dockerfile `FROM ruby:3.4.12` line. */
export function dockerRubyVersion(dockerText: string): string | null {
  const m = dockerText.match(/^FROM\s+ruby:([0-9][^\s]*)/im);
  return m ? m[1] : null;
}

/**
 * Detect Sinatra style from config.ru / app files: classic style
 * is `require 'sinatra'` at top level; modular style is
 * `require 'sinatra/base'` plus a `Sinatra::Base` subclass.
 */
export function detectSinatraStyle(
  texts: string[],
): "classic" | "modular" | "unknown" {
  const joined = texts.join("\n");
  if (/require\s+['"]sinatra\/base['"]/.test(joined)) return "modular";
  if (/<\s*Sinatra::Base/.test(joined)) return "modular";
  if (/require\s+['"]sinatra['"]/.test(joined)) return "classic";
  return "unknown";
}

const CASE_CALL_RE =
  /\bparams\b[^;\n]{0,80}\b(upcase|downcase|swapcase|casecmp\?)\b|\b(upcase|downcase|swapcase|casecmp\?)\b[^;\n]{0,40}\bparams\b/;

/** Walk .rb files under dir (max 200 files, depth-limited). */
function collectRubyFiles(dir: string, out: string[], depth: number): void {
  if (depth > 4 || out.length >= 200) return;
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const entry of entries) {
    if (entry.startsWith(".")) continue;
    const full = join(dir, entry);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (entry === "node_modules" || entry === "vendor") continue;
      collectRubyFiles(full, out, depth + 1);
    } else if (entry.endsWith(".rb")) {
      out.push(full);
    }
  }
}

function scanCaseConversionSites(appDir: string): CaseConversionSite[] {
  const files: string[] = [];
  for (const sub of ["app", "config", "lib"]) {
    collectRubyFiles(join(appDir, sub), files, 0);
  }
  const sites: CaseConversionSite[] = [];
  for (const file of files) {
    const text = readIfExists(file);
    if (!text) continue;
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (CASE_CALL_RE.test(lines[i])) {
        sites.push({
          file: file.replace(appDir + "/", ""),
          line: i + 1,
          text: lines[i].trim().slice(0, 120),
        });
        if (sites.length >= 5) return sites;
      }
    }
  }
  return sites;
}

export function parseAppDir(appDir: string): ParsedApp {
  const evidencePaths: string[] = [];
  const lockText = readIfExists(join(appDir, "Gemfile.lock"));
  if (lockText !== null) evidencePaths.push(join(appDir, "Gemfile.lock"));
  const gemfileText = readIfExists(join(appDir, "Gemfile"));
  if (gemfileText !== null) evidencePaths.push(join(appDir, "Gemfile"));
  const configRu = readIfExists(join(appDir, "config.ru"));
  if (configRu !== null) evidencePaths.push(join(appDir, "config.ru"));
  const appRb = readIfExists(join(appDir, "config", "application.rb"));
  if (appRb !== null)
    evidencePaths.push(join(appDir, "config", "application.rb"));
  const dockerText = readIfExists(join(appDir, "Dockerfile"));
  if (dockerText !== null) evidencePaths.push(join(appDir, "Dockerfile"));
  const rubyVersionText = readIfExists(join(appDir, ".ruby-version"));
  if (rubyVersionText !== null)
    evidencePaths.push(join(appDir, ".ruby-version"));

  const railsVersion = lockText ? gemVersionFromLock(lockText, "rails") : null;
  const sinatraVersion = lockText
    ? gemVersionFromLock(lockText, "sinatra")
    : null;
  const rackVersion = lockText ? gemVersionFromLock(lockText, "rack") : null;
  const dockerRuby = dockerText ? dockerRubyVersion(dockerText) : null;
  const rubyVersionFile = rubyVersionText
    ? rubyVersionText.trim().split(/\s+/)[0]
    : null;
  const apiOnly = appRb ? /config\.api_only\s*=\s*true/.test(appRb) : false;

  let framework: Framework = "unknown";
  let methodOverride: ParsedApp["methodOverride"] = "unknown";
  if (railsVersion) {
    framework = apiOnly ? "rails-api-only" : "rails";
    // Default Rails mounts Rack::MethodOverride; api_only apps
    // may not. The middleware stack is not read here, so the
    // api_only case stays "unknown" rather than assumed present.
    methodOverride = apiOnly ? "unknown" : "framework-default";
  } else if (sinatraVersion) {
    const style = detectSinatraStyle([
      configRu ?? "",
      readIfExists(join(appDir, "app.rb")) ?? "",
      readIfExists(join(appDir, "app", "app.rb")) ?? "",
    ]);
    framework =
      style === "classic"
        ? "sinatra-classic"
        : style === "modular"
          ? "sinatra-modular"
          : "sinatra-classic";
    // Classic Sinatra mounts Rack::MethodOverride by default;
    // modular apps only do so when they add it themselves.
    methodOverride =
      framework === "sinatra-classic" ? "framework-default" : "unknown";
    if (
      configRu &&
      /Rack::MethodOverride/.test(configRu) &&
      methodOverride === "unknown"
    ) {
      methodOverride = "present";
    }
  } else if (rackVersion || configRu) {
    framework = "rack";
    methodOverride =
      configRu && /Rack::MethodOverride/.test(configRu) ? "present" : "absent";
  } else if (lockText || gemfileText) {
    framework = "other";
  }

  // An explicit `use Rack::MethodOverride` in config.ru is direct
  // evidence, whatever the framework.
  if (configRu && /use\s+Rack::MethodOverride/.test(configRu)) {
    methodOverride = "present";
  }

  const caseConversionSites = scanCaseConversionSites(appDir);

  let summary: string;
  switch (framework) {
    case "rails":
      summary = `Rails ${railsVersion ?? ""} (default config) - pre-auth reachable via Rack::MethodOverride`;
      break;
    case "rails-api-only":
      summary = `Rails ${railsVersion ?? ""} (api_only) - MethodOverride may be absent, reachability not settled`;
      break;
    case "sinatra-classic":
      summary = `Sinatra ${sinatraVersion ?? ""} (classic style) - pre-auth reachable via Rack::MethodOverride`;
      break;
    case "sinatra-modular":
      summary = `Sinatra ${sinatraVersion ?? ""} (modular style) - not exposed by default`;
      break;
    case "rack":
      summary = "plain Rack - not exposed by default";
      break;
    case "other":
      summary = "Ruby app, framework not recognised - not exposed by default";
      break;
    default:
      summary = "no framework evidence found";
  }

  return {
    framework,
    railsVersion,
    sinatraVersion,
    rackVersion,
    apiOnly,
    methodOverride,
    dockerRuby,
    rubyVersionFile,
    caseConversionSites,
    evidencePaths,
    summary,
  };
}

/** Parse a config target for config-scan: a file, or a directory holding app files. */
export function parseConfigTarget(
  target: string,
): { parsed: ParsedApp; source: string } | { error: string } {
  if (!existsSync(target)) {
    return { error: `app dir not found: ${target}` };
  }
  const st = statSync(target);
  if (!st.isDirectory()) {
    return {
      error: `config-scan needs an app directory, got a file: ${target}`,
    };
  }
  const parsed = parseAppDir(target);
  if (parsed.evidencePaths.length === 0) {
    return {
      error: `no app evidence found in ${target} (looked for Gemfile, Gemfile.lock, config.ru, Dockerfile, .ruby-version)`,
    };
  }
  return { parsed, source: target };
}
