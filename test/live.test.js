/**
 * Live smoke tests (blueprint section 6).
 * Soft-skip on network failure: these assert the pre-creation state
 * (npm + GitHub names still free, advisories live), never hard-fail CI.
 */
import test from "node:test";
import assert from "node:assert/strict";

async function getStatus(url, timeoutMs = 10000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: ctrl.signal,
      redirect: "follow",
      headers: { "User-Agent": "ruby2shell-live-smoke/0.1.0" },
    });
    return res.status;
  } finally {
    clearTimeout(t);
  }
}

function softSkip(t, err) {
  t.skip(`network unavailable: ${err.message}`);
}

test("npm ruby2shell is still 404 (pre-creation)", async (t) => {
  let status;
  try {
    status = await getStatus("https://registry.npmjs.org/ruby2shell");
  } catch (err) {
    softSkip(t, err);
    return;
  }
  assert.equal(status, 404);
});

test("npm search returns 0 packages for ruby2shell", async (t) => {
  let res;
  try {
    res = await fetch(
      "https://registry.npmjs.org/-/v1/search?text=ruby2shell&size=5",
      { signal: AbortSignal.timeout(10000) },
    );
  } catch (err) {
    softSkip(t, err);
    return;
  }
  const data = await res.json();
  assert.equal(data.total, 0);
});

test("GitHub org repo techdevfun/ruby2shell is still 404 (pre-creation)", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://api.github.com/repos/techdevfun/ruby2shell",
    );
  } catch (err) {
    softSkip(t, err);
    return;
  }
  // 403 when unauthenticated rate-limited: soft-skip, because
  // the authoritative 404 check runs via PAT-A before creation
  // (see the build note). 404 is the clean pre-creation state.
  if (status === 403) {
    t.skip("GitHub API returned 403 (unauthenticated rate limit)");
    return;
  }
  assert.equal(status, 404);
});

test("Veria Labs disclosure page returns 200", async (t) => {
  let status;
  try {
    status = await getStatus("https://verialabs.com/ruby2shell/");
  } catch (err) {
    softSkip(t, err);
    return;
  }
  assert.equal(status, 200);
});

test("Ruby security advisory returns 200", async (t) => {
  let status;
  try {
    status = await getStatus(
      "https://www.ruby-lang.org/en/news/2026/11/18/multiple-vulnerabilities-in-regexp-and-string/",
    );
  } catch (err) {
    softSkip(t, err);
    return;
  }
  assert.equal(status, 200);
});

test("NVD CVE-2026-132825 is published (API, no key)", async (t) => {
  let res;
  try {
    res = await fetch(
      "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-132825",
      {
        signal: AbortSignal.timeout(15000),
        headers: { "User-Agent": "ruby2shell-live-smoke/0.1.0" },
      },
    );
  } catch (err) {
    softSkip(t, err);
    return;
  }
  if (res.status === 403 || res.status === 429) {
    t.skip(`NVD API returned ${res.status} (rate limit / bot wall)`);
    return;
  }
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.totalResults, 1);
  assert.equal(data.vulnerabilities[0].cve.id, "CVE-2026-132825");
});
