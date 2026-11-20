/**
 * Self-hosted products that bundle their own Ruby, with the
 * fixed releases per vendor. The fix has to come from the vendor:
 * upgrading Ruby alone does not fix these products.
 *
 * Table source (checked 2026-11-20): Veria Labs,
 * verialabs.com/ruby2shell/, status table updated 2026-11-20
 * 06:30 UTC. GitLab 19.6.1 / 19.5.8 / 19.4.10, Mastodon 4.7.6 /
 * 4.6.12 / 4.5.22 / 4.4.29, OpenProject 17.9.8 / 17.8.3 and the
 * Discourse base image 2.0.20261119-0203 were already shipping
 * the fixed Ruby on 20/11/2026. GitHub Enterprise Server and
 * Chatwoot had no fixed release yet on 20/11/2026.
 */

export interface ProductCheck {
  status: "patched" | "vulnerable" | "unknown";
  reason: string;
  /** Fixed releases to name in output (empty when none yet). */
  fixedVersions: string[];
}

interface FixedBranch {
  branch: string;
  fixed: string;
}

interface ProductEntry {
  name: string;
  aliases: string[];
  /** A version at or below this is affected when no fixed branch covers it. */
  affectedThrough: string;
  fixedBranches: FixedBranch[];
  /** True when a version newer than every known fixed branch is assumed patched. */
  newerThanFixedIsPatched: boolean;
  displayName: string;
}

const PRODUCTS: ProductEntry[] = [
  {
    name: "gitlab",
    aliases: ["gitlab"],
    affectedThrough: "19.6.0",
    fixedBranches: [
      { branch: "19.6", fixed: "19.6.1" },
      { branch: "19.5", fixed: "19.5.8" },
      { branch: "19.4", fixed: "19.4.10" },
    ],
    newerThanFixedIsPatched: true,
    displayName: "GitLab",
  },
  {
    name: "ghes",
    aliases: ["ghes", "github-enterprise-server", "github-enterprise"],
    affectedThrough: "3.22.5",
    fixedBranches: [],
    newerThanFixedIsPatched: false,
    displayName: "GitHub Enterprise Server",
  },
  {
    name: "chatwoot",
    aliases: ["chatwoot"],
    affectedThrough: "4.20.0",
    fixedBranches: [],
    newerThanFixedIsPatched: false,
    displayName: "Chatwoot",
  },
  {
    name: "mastodon",
    aliases: ["mastodon"],
    affectedThrough: "4.7.5",
    fixedBranches: [
      { branch: "4.7", fixed: "4.7.6" },
      { branch: "4.6", fixed: "4.6.12" },
      { branch: "4.5", fixed: "4.5.22" },
      { branch: "4.4", fixed: "4.4.29" },
    ],
    newerThanFixedIsPatched: true,
    displayName: "Mastodon",
  },
  {
    name: "openproject",
    aliases: ["openproject"],
    affectedThrough: "17.9.7",
    fixedBranches: [
      { branch: "17.9", fixed: "17.9.8" },
      { branch: "17.8", fixed: "17.8.3" },
    ],
    newerThanFixedIsPatched: true,
    displayName: "OpenProject",
  },
  {
    name: "discourse",
    aliases: ["discourse"],
    affectedThrough: "2.0.20261119-0202",
    fixedBranches: [{ branch: "2.0", fixed: "2.0.20261119-0203" }],
    newerThanFixedIsPatched: true,
    displayName: "Discourse (base image)",
  },
];

/** Split a version into numeric parts for comparison. */
export function splitVersion(v: string): number[] {
  return v
    .split(/[^0-9]+/)
    .filter((p) => p.length > 0)
    .map(Number);
}

/** Compare two dotted/date versions: -1, 0 or 1. */
export function compareProductVersions(a: string, b: string): number {
  const pa = splitVersion(a);
  const pb = splitVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/** Branch of a version: first two numeric parts joined with a dot. */
export function branchOf(v: string): string {
  const parts = splitVersion(v);
  return `${parts[0] ?? 0}.${parts[1] ?? 0}`;
}

export function findProduct(name: string): ProductEntry | null {
  const lower = name.toLowerCase();
  return (
    PRODUCTS.find((p) => p.name === lower || p.aliases.includes(lower)) ?? null
  );
}

export function productNames(): string[] {
  return PRODUCTS.map((p) => p.name);
}

/** Fixed-release list for display, e.g. "19.6.1, 19.5.8, 19.4.10". */
export function fixedVersionsText(entry: ProductEntry): string {
  return entry.fixedBranches.map((b) => b.fixed).join(", ");
}

export function checkProduct(name: string, version: string): ProductCheck {
  const entry = findProduct(name);
  if (!entry) {
    return {
      status: "unknown",
      reason: `unknown product: ${name}. Known products: ${productNames().join(", ")}`,
      fixedVersions: [],
    };
  }
  if (!/^\d/.test(version)) {
    return {
      status: "unknown",
      reason: `product version could not be parsed: ${version}`,
      fixedVersions: entry.fixedBranches.map((b) => b.fixed),
    };
  }
  const branch = branchOf(version);
  const fixedOnBranch = entry.fixedBranches.find((b) => b.branch === branch);
  if (fixedOnBranch) {
    if (compareProductVersions(version, fixedOnBranch.fixed) >= 0) {
      return {
        status: "patched",
        reason: `${entry.displayName} ${version} is at or above the fixed release ${fixedOnBranch.fixed} for its branch (Veria Labs, 20/11/2026)`,
        fixedVersions: entry.fixedBranches.map((b) => b.fixed),
      };
    }
    return {
      status: "vulnerable",
      reason: `${entry.displayName} ${version} bundles an affected Ruby (fixed release for this branch is ${fixedOnBranch.fixed})`,
      fixedVersions: entry.fixedBranches.map((b) => b.fixed),
    };
  }
  // Newer than every known fixed branch: a later release contains
  // the fix (only claimed for products whose vendor ships fixed
  // releases; GHES/Chatwoot have none yet, so this never fires).
  const highestFixed =
    entry.fixedBranches.length > 0
      ? entry.fixedBranches
          .map((b) => b.fixed)
          .sort(compareProductVersions)
          .pop()!
      : null;
  if (
    entry.newerThanFixedIsPatched &&
    highestFixed &&
    compareProductVersions(version, highestFixed) > 0 &&
    compareProductVersions(version, entry.affectedThrough) > 0
  ) {
    return {
      status: "patched",
      reason: `${entry.displayName} ${version} is newer than the fixed releases (${fixedVersionsText(entry)}) and bundles the fixed Ruby`,
      fixedVersions: entry.fixedBranches.map((b) => b.fixed),
    };
  }
  if (compareProductVersions(version, entry.affectedThrough) <= 0) {
    if (entry.fixedBranches.length === 0) {
      return {
        status: "vulnerable",
        reason: `${entry.displayName} ${version} bundles an affected Ruby and no fixed release has been published yet (Veria Labs, 20/11/2026) - watch the vendor`,
        fixedVersions: [],
      };
    }
    return {
      status: "vulnerable",
      reason: `${entry.displayName} ${version} bundles an affected Ruby (fixed releases: ${fixedVersionsText(entry)})`,
      fixedVersions: entry.fixedBranches.map((b) => b.fixed),
    };
  }
  return {
    status: "unknown",
    reason: `${entry.displayName} ${version} is not covered by the Veria Labs status table of 20/11/2026 - confirm the bundled Ruby with the vendor before calling this safe`,
    fixedVersions: entry.fixedBranches.map((b) => b.fixed),
  };
}
