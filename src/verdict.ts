/**
 * Condition-based verdicts for Ruby2Shell (CVE-2026-132825 /
 * GHSA-34m4-m9fh-gqp5).
 *
 * Exposure needs the version AND the framework condition
 * together: a version in the affected range on a plain-Rack app
 * is not exposed by default, and a fixed Ruby is safe whatever
 * the framework. Ruby 3.2 and earlier are end of life with no
 * fix: affected on those lines is AT-RISK, never SAFE.
 *
 * - EXPOSED: affected version + default Rails or classic Sinatra
 *   (or an explicit Rack::MethodOverride in the middleware
 *   evidence), or an affected self-hosted product version.
 * - SAFE: fixed version, or version before 2.4.0 (predates the
 *   flaw), or affected version on plain Rack / another framework
 *   with no case-conversion evidence (not exposed by default),
 *   or a patched self-hosted product version.
 * - AT-RISK: affected version but framework unknown, or EOL
 *   line with no fix, or Rails api_only (MethodOverride may be
 *   absent - reachability not settled).
 * - UNKNOWN: version unparseable, distro build (backport
 *   unconfirmed), non-CRuby engine, Ruby line not in the
 *   18/11/2026 fixed-build table, product version not covered
 *   by the vendor table, or the binary could not be probed.
 */
import type { ParsedApp } from "./appconfig.js";
import type { ProductCheck } from "./products.js";
import {
  fixedBuildFor,
  patchVerdictFor,
  patchVerdictText,
  type ParsedVersion,
} from "./versions.js";

export type Verdict = "EXPOSED" | "AT-RISK" | "SAFE" | "UNKNOWN";

export interface VerdictInput {
  version: ParsedVersion | null;
  /** Null when no app evidence was read. */
  app: ParsedApp | null;
  /** Where the app evidence came from, for evidence (or "" when none). */
  appSource: string;
  /** Raw `ruby -v` output, for evidence. */
  rawVersion: string;
  /** Self-hosted product check, when --product was given. */
  product: ProductCheck | null;
  productName: string | null;
}

export interface VerdictResult {
  verdict: Verdict;
  reasons: string[];
  /** The single condition that decides the verdict, for tables. */
  deciding: string;
  /** Patch verdict for the Ruby version (null when no version). */
  patch: string | null;
}

function frameworkExposed(app: ParsedApp): boolean {
  if (app.framework === "rails" || app.framework === "sinatra-classic")
    return true;
  // An explicit Rack::MethodOverride in the middleware stack
  // reaches the same path whatever the framework.
  if (app.methodOverride === "present") return true;
  return false;
}

export function decideVerdict(input: VerdictInput): VerdictResult {
  const { version, app, product } = input;

  if (product) {
    if (product.status === "patched") {
      return {
        verdict: "SAFE",
        reasons: [product.reason],
        deciding: "patched product release",
        patch: null,
      };
    }
    if (product.status === "vulnerable") {
      return {
        verdict: "EXPOSED",
        reasons: [
          product.reason,
          product.fixedVersions.length > 0
            ? `install the vendor fixed release (${product.fixedVersions.join(", ")})`
            : "no fixed release has been published yet - watch the vendor and treat this install as exposed",
        ],
        deciding: "affected product release",
        patch: null,
      };
    }
    return {
      verdict: "UNKNOWN",
      reasons: [product.reason],
      deciding: "product version not covered by the vendor table",
      patch: null,
    };
  }

  if (!version) {
    return {
      verdict: "UNKNOWN",
      reasons: ["ruby -v output could not be parsed"],
      deciding: "version unparseable",
      patch: null,
    };
  }
  if (version.engine) {
    return {
      verdict: "UNKNOWN",
      reasons: [
        `${version.engine} detected (${version.raw}) - this is not CRuby, so the CRuby case-conversion table does not apply`,
        "confirm the engine in its own advisory before calling this SAFE",
      ],
      deciding: "non-CRuby engine",
      patch: null,
    };
  }
  if (version.distroSuffix) {
    return {
      verdict: "UNKNOWN",
      reasons: [
        `distro build detected (${version.raw}${version.distroSuffix}) - the distro may have backported the fix, so the version number alone cannot decide`,
        "confirm the backport in the distro advisory (e.g. Ubuntu CVE-2026-132825) before calling this SAFE",
      ],
      deciding: "distro build, backport unconfirmed",
      patch: null,
    };
  }

  const patch = patchVerdictFor(version);
  if (patch === "fixed") {
    return {
      verdict: "SAFE",
      reasons: [patchVerdictText(version)],
      deciding: "fixed build",
      patch,
    };
  }
  if (patch === "predates") {
    return {
      verdict: "SAFE",
      reasons: [patchVerdictText(version)],
      deciding: "predates the flaw (before 2.4.0)",
      patch,
    };
  }
  if (patch === "unknown-line") {
    return {
      verdict: "UNKNOWN",
      reasons: [patchVerdictText(version)],
      deciding: "Ruby line not in the 18/11/2026 fixed-build table",
      patch,
    };
  }
  if (patch === "eol-no-fix") {
    return {
      verdict: "AT-RISK",
      reasons: [
        patchVerdictText(version),
        "there is no patch for this line - upgrade to a supported Ruby (3.3.14, 3.4.13 or 4.0.10)",
      ],
      deciding: "EOL line, no fix exists",
      patch,
    };
  }

  // From here the version is in the affected range.
  if (!app) {
    return {
      verdict: "AT-RISK",
      reasons: [
        patchVerdictText(version),
        "no app evidence was read, so framework exposure is unknown - pass --app <dir> with the app to decide",
      ],
      deciding: "framework unknown",
      patch,
    };
  }
  if (frameworkExposed(app)) {
    const reasons = [patchVerdictText(version), app.summary];
    if (app.methodOverride === "framework-default") {
      reasons.push(
        "Rack::MethodOverride calls .upcase on the attacker-controlled _method parameter with no authentication",
      );
    } else if (app.methodOverride === "present") {
      reasons.push(
        "Rack::MethodOverride is in the middleware stack (config.ru) and calls .upcase on the _method parameter",
      );
    }
    if (app.caseConversionSites.length > 0) {
      reasons.push(
        `app code also case-converts request params (REVIEW): ${app.caseConversionSites
          .map((s) => `${s.file}:${s.line}`)
          .join(", ")}`,
      );
    }
    return {
      verdict: "EXPOSED",
      reasons,
      deciding: "affected version + exposed framework",
      patch,
    };
  }
  if (app.framework === "rails-api-only") {
    return {
      verdict: "AT-RISK",
      reasons: [
        patchVerdictText(version),
        "Rails api_only: Rack::MethodOverride may be absent, so reachability is not settled - check the middleware stack",
      ],
      deciding: "api_only, reachability not settled",
      patch,
    };
  }
  if (app.framework === "unknown") {
    return {
      verdict: "AT-RISK",
      reasons: [
        patchVerdictText(version),
        "no framework evidence found in the app dir, so exposure cannot be decided",
      ],
      deciding: "framework unknown",
      patch,
    };
  }
  const reasons = [patchVerdictText(version), app.summary];
  if (app.caseConversionSites.length > 0) {
    reasons.push(
      `note: app code case-converts request params (REVIEW, not proof of exploitability): ${app.caseConversionSites
        .map((s) => `${s.file}:${s.line}`)
        .join(", ")}`,
    );
    return {
      verdict: "AT-RISK",
      reasons,
      deciding: "not exposed by default, but app code case-converts params",
      patch,
    };
  }
  return {
    verdict: "SAFE",
    reasons,
    deciding: "affected version, not exposed by default",
    patch,
  };
}

/** Fixed-build hint for the version's line ("" when unknown). */
export function fixedHintFor(version: ParsedVersion): string {
  const fixed = fixedBuildFor(version.line);
  return fixed ? `upgrade to Ruby ${fixed}` : "";
}
