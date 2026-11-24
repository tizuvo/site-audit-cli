import { performance } from "node:perf_hooks";
import {
  DEFAULT_TIMEOUT_MS,
  InvalidUrlError,
  NetworkError,
  fetchAuxiliary,
  fetchDocument,
  inspectTls,
  normalizeUrl,
} from "./http.mjs";
import { runPerformanceChecks } from "./checks/performance.mjs";
import { runSecurityChecks } from "./checks/security.mjs";
import { runSeoChecks } from "./checks/seo.mjs";

export { InvalidUrlError, NetworkError, normalizeUrl };

const STATUS_POINTS = {
  pass: 100,
  warn: 55,
  fail: 0,
};

const WEIGHTS = {
  performance: 0.3,
  security: 0.4,
  seo: 0.3,
};

/**
 * Convert a numeric score (0–100) into a letter grade.
 */
export function calculateGrade(score) {
  if (score >= 95) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

/**
 * Compute per-category scores, overall weighted score, grade, and pass/warn/fail counts.
 */
export function calculateScore(checks) {
  const counts = { pass: 0, warn: 0, fail: 0 };
  const buckets = {
    performance: [],
    security: [],
    seo: [],
  };

  for (const check of checks) {
    if (check.status in counts) {
      counts[check.status] += 1;
    }
    if (check.category in buckets) {
      buckets[check.category].push(STATUS_POINTS[check.status] ?? 0);
    }
  }

  const avg = (arr) =>
    arr.length === 0 ? 0 : Math.round(arr.reduce((a, b) => a + b, 0) / arr.length);

  const categories = {
    performance: avg(buckets.performance),
    security: avg(buckets.security),
    seo: avg(buckets.seo),
  };

  const overall_score = Math.round(
    categories.performance * WEIGHTS.performance +
      categories.security * WEIGHTS.security +
      categories.seo * WEIGHTS.seo
  );

  return {
    overall_score,
    grade: calculateGrade(overall_score),
    counts,
    categories,
  };
}

/**
 * Run a full 3-pillar site audit against the target URL.
 *
 * @param {string} inputUrl Bare domain or full http(s) URL
 * @param {{ timeoutMs?: number }} [options]
 */
export async function auditSite(inputUrl, options = {}) {
  const timeoutMs =
    typeof options.timeoutMs === "number" && options.timeoutMs > 0
      ? options.timeoutMs
      : DEFAULT_TIMEOUT_MS;

  const normalized = normalizeUrl(inputUrl);
  const start = performance.now();

  const doc = await fetchDocument(normalized.toString(), { timeoutMs });
  const finalParsed = new URL(doc.finalUrl);
  const origin = finalParsed.origin;

  // Run TLS inspection and auxiliary endpoint fetches in parallel
  const [tlsInfo, robotsTxt, sitemapXml] = await Promise.all([
    inspectTls(doc.finalUrl, { timeoutMs }),
    fetchAuxiliary(origin, "/robots.txt", { timeoutMs }),
    fetchAuxiliary(origin, "/sitemap.xml", { timeoutMs }),
  ]);

  const checks = [
    ...runPerformanceChecks(doc, tlsInfo),
    ...runSecurityChecks(doc, tlsInfo),
    ...runSeoChecks(doc, robotsTxt, sitemapXml),
  ];

  const { overall_score, grade, counts, categories } = calculateScore(checks);
  const duration_ms = Math.round(performance.now() - start);

  return {
    ok: true,
    host: finalParsed.hostname,
    audited_url: doc.finalUrl,
    status_code: doc.statusCode,
    duration_ms,
    overall_score,
    grade,
    counts,
    categories,
    checks,
  };
}
