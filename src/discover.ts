/**
 * Discovery and probing of Ruby installs on the live host.
 *
 * Sources, in order: PATH `ruby`, rbenv versions, rvm rubies,
 * well-known system dirs per OS, plus --dirs. Each candidate is
 * a directory holding bin/ruby (or ruby directly). Probing runs
 * only `ruby -v` - it prints a version string and nothing else;
 * no payload, no code execution beyond the interpreter's own
 * startup.
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { parseRubyVersion, type ParsedVersion } from "./versions.js";

export interface RubyInstall {
  /** Directory holding the install (bin/ruby lives under it, or ruby directly). */
  dir: string;
  binary: string;
  /** Raw `ruby -v` output (stdout + stderr joined). */
  rawVersion: string;
  version: ParsedVersion | null;
  /** Probe failure text, when ruby -v did not run. */
  error: string | null;
}

function candidateBaseDirs(extraDirs: string[]): string[] {
  const home = homedir();
  return [
    join(home, ".rbenv", "versions"),
    join(home, ".rvm", "rubies"),
    "/usr/local",
    "/usr",
    "/opt",
    ...extraDirs,
  ];
}

function binaryIn(dir: string): string | null {
  const bin = join(dir, "bin", "ruby");
  if (existsSync(bin)) return bin;
  const direct = join(dir, "ruby");
  if (existsSync(direct)) return direct;
  return null;
}

function pathRuby(): string | null {
  const path = process.env.PATH ?? "";
  for (const dir of path.split(delimiter)) {
    if (!dir) continue;
    const bin = join(dir, "ruby");
    if (existsSync(bin)) return bin;
  }
  return null;
}

/** Discover Ruby installs: PATH ruby, rbenv/rvm/system dirs, --dirs. */
export function discoverRuby(
  extraDirs: string[],
  opts: { system?: boolean } = {},
): string[] {
  const includeSystem = opts.system !== false;
  const found: string[] = [];
  const seen = new Set<string>();
  const addBinary = (bin: string | null): void => {
    if (!bin) return;
    const key = resolve(bin);
    if (seen.has(key)) return;
    seen.add(key);
    found.push(bin);
  };
  if (includeSystem) addBinary(pathRuby());
  const bases = includeSystem ? candidateBaseDirs(extraDirs) : [...extraDirs];
  for (const base of bases) {
    if (!existsSync(base)) continue;
    // A system dir holds bin/ruby directly; a version dir
    // (rbenv/rvm) holds one subdir per Ruby.
    const direct = binaryIn(base);
    if (direct) {
      addBinary(direct);
      continue;
    }
    let entries: string[];
    try {
      entries = readdirSync(base);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.startsWith(".")) continue;
      addBinary(binaryIn(join(base, entry)));
    }
  }
  return found;
}

/** Run `ruby -v` and parse the output. Never runs anything else. */
export function probeRuby(binary: string): RubyInstall {
  const dir = binary.endsWith("/bin/ruby")
    ? dirname(dirname(binary))
    : dirname(binary);
  const res = spawnSync(binary, ["-v"], { encoding: "utf8" });
  const raw = `${res.stdout ?? ""}${res.stderr ?? ""}`.trim();
  if (res.error || res.status !== 0) {
    return {
      dir,
      binary,
      rawVersion: raw,
      version: null,
      error: res.error
        ? String(res.error)
        : `ruby -v exited ${res.status}: ${raw.slice(0, 200)}`,
    };
  }
  return {
    dir,
    binary,
    rawVersion: raw,
    version: parseRubyVersion(raw),
    error: null,
  };
}

/** Resolve a check target: a dir (find its ruby) or a binary path. */
export function resolveBinary(target: string): string | null {
  if (!existsSync(target)) return null;
  const st = statSync(target);
  if (st.isFile()) return target;
  return binaryIn(target);
}
