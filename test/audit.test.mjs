import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import zlib from "node:zlib";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import {
  auditSite,
  calculateGrade,
  calculateScore,
  normalizeUrl,
  InvalidUrlError,
} from "../src/audit.mjs";
import { runPerformanceChecks } from "../src/checks/performance.mjs";
import { runSecurityChecks } from "../src/checks/security.mjs";
import { runSeoChecks } from "../src/checks/seo.mjs";
import { formatTerminal } from "../src/format.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = resolve(__dirname, "../bin/cli.mjs");

function startMockServer(handler) {
  return new Promise((resolveServer) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolveServer({
        server,
        url: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

function runCli(args, env = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", rejectRun);
    child.on("close", (status) => {
      resolveRun({ status, stdout, stderr });
    });
  });
}

const CLEAN_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Tizuvo Studio — High-Velocity Web &amp; Security Systems</title>
  <meta name="description" content="Tizuvo builds fast, secure, search-optimized web platforms with modern architecture and measurable performance across every release." />
  <link rel="canonical" href="https://example.com/" />
  <meta property="og:title" content="Tizuvo Studio" />
  <meta property="og:description" content="High-velocity web platforms and security audits." />
  <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Tizuvo"}</script>
</head>
<body>
  <h1>Building fast, resilient websites</h1>
  <p>Welcome to the mock test page.</p>
</body>
</html>`;

describe("URL normalization", () => {
  it("normalizes bare domains to https://", () => {
    assert.equal(normalizeUrl("tizuvo.com").toString(), "https://tizuvo.com/");
    assert.equal(
      normalizeUrl("tizuvo.com/audit").toString(),
      "https://tizuvo.com/audit"
    );
    assert.equal(
      normalizeUrl("https://tizuvo.com/path?a=1").toString(),
      "https://tizuvo.com/path?a=1"
    );
    assert.equal(
      normalizeUrl("http://127.0.0.1:8080/test").toString(),
      "http://127.0.0.1:8080/test"
    );
  });

  it("rejects invalid URLs and unsupported schemes with InvalidUrlError", () => {
    const badInputs = [
      "",
      "   ",
      "not a url",
      "justaword",
      "ftp://example.com",
      "javascript:alert(1)",
      "https://-bad.example.com",
      "https://foo..bar.com",
      "http://",
    ];
    for (const bad of badInputs) {
      assert.throws(() => normalizeUrl(bad), InvalidUrlError, `Expected failure for "${bad}"`);
    }
  });
});

describe("Scoring engine & grade calculator", () => {
  it("computes exact weighted scores and grades across 20 checks (6+7+7)", () => {
    const checks = [
      // 6 performance: all pass => 100
      ...Array.from({ length: 6 }, (_, i) => ({
        id: `p${i}`,
        category: "performance",
        status: "pass",
      })),
      // 7 security: all pass => 100
      ...Array.from({ length: 7 }, (_, i) => ({
        id: `s${i}`,
        category: "security",
        status: "pass",
      })),
      // 7 seo: 6 pass (600) + 1 warn (55) = 655 / 7 = 93.57 => 94
      ...Array.from({ length: 6 }, (_, i) => ({
        id: `o${i}`,
        category: "seo",
        status: "pass",
      })),
      { id: "o6", category: "seo", status: "warn" },
    ];

    const result = calculateScore(checks);
    assert.deepEqual(result.counts, { pass: 19, warn: 1, fail: 0 });
    assert.deepEqual(result.categories, { performance: 100, security: 100, seo: 94 });
    // 100*0.3 + 100*0.4 + 94*0.3 = 30 + 40 + 28.2 = 98.2 => 98
    assert.equal(result.overall_score, 98);
    assert.equal(result.grade, "A+");
  });

  it("maps grade boundaries accurately", () => {
    assert.equal(calculateGrade(100), "A+");
    assert.equal(calculateGrade(95), "A+");
    assert.equal(calculateGrade(94), "A");
    assert.equal(calculateGrade(90), "A");
    assert.equal(calculateGrade(80), "B");
    assert.equal(calculateGrade(70), "C");
    assert.equal(calculateGrade(60), "D");
    assert.equal(calculateGrade(59), "F");
  });
});

describe("Unit checks: Performance, Security & SEO (20-check matrix)", () => {
  it("evaluates http_protocol (h2/h3 -> pass, http/1.1 -> warn)", () => {
    const baseDoc = {
      ttfbMs: 120,
      redirectCount: 0,
      redirectLoop: false,
      headers: new Headers({ "content-encoding": "br", "cache-control": "max-age=60" }),
      htmlBytes: 12 * 1024,
    };

    const h2Checks = runPerformanceChecks(baseDoc, { alpnProtocol: "h2" });
    assert.equal(h2Checks.length, 6);
    assert.equal(h2Checks[0].id, "http_protocol");
    assert.equal(h2Checks[0].status, "pass");
    assert.match(h2Checks[0].detail, /HTTP\/2/);

    const h3Checks = runPerformanceChecks(baseDoc, { alpnProtocol: "h3" });
    assert.equal(h3Checks[0].status, "pass");
    assert.match(h3Checks[0].detail, /HTTP\/3/);

    const h1Checks = runPerformanceChecks(baseDoc, { alpnProtocol: "http/1.1" });
    assert.equal(h1Checks[0].status, "warn");
    assert.match(h1Checks[0].detail, /HTTP\/1\.1/);

    const plainChecks = runPerformanceChecks(baseDoc, { alpnProtocol: null });
    assert.equal(plainChecks[0].status, "warn");
  });

  it("evaluates TLS 1.3, TLS 1.2, expiring certs, HSTS, and server_hygiene", () => {
    const cleanHeaders = new Headers({
      server: "nginx",
      "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "strict-origin-when-cross-origin",
      "permissions-policy": "camera=(), microphone=()",
    });
    const doc = { headers: cleanHeaders };

    // TLS 1.3 + 80 days + clean Server: nginx => all 7 pass
    const passChecks = runSecurityChecks(doc, {
      isHttps: true,
      protocol: "TLSv1.3",
      authorized: true,
      daysRemaining: 80,
      expired: false,
    });
    assert.equal(passChecks.length, 7);
    assert.equal(passChecks.find((c) => c.id === "https_tls").status, "pass");
    assert.equal(passChecks.find((c) => c.id === "hsts").status, "pass");
    assert.equal(passChecks.find((c) => c.id === "csp").status, "pass");
    assert.equal(passChecks.find((c) => c.id === "framing").status, "pass");
    assert.equal(passChecks.find((c) => c.id === "server_hygiene").status, "pass");
    assert.equal(
      passChecks.find((c) => c.id === "server_hygiene").detail,
      "No software version exposed"
    );

    // Server: nginx/1.24.0 => warn
    const versionedServer = runSecurityChecks(
      { headers: new Headers({ server: "nginx/1.24.0" }) },
      { isHttps: true, protocol: "TLSv1.3", authorized: true, daysRemaining: 80, expired: false }
    );
    const serverWarn = versionedServer.find((c) => c.id === "server_hygiene");
    assert.equal(serverWarn.status, "warn");
    assert.match(serverWarn.detail, /nginx\/1\.24\.0/);

    // X-Powered-By: Express => warn
    const poweredByServer = runSecurityChecks(
      { headers: new Headers({ server: "cloudflare", "x-powered-by": "Express" }) },
      { isHttps: true, protocol: "TLSv1.3", authorized: true, daysRemaining: 80, expired: false }
    );
    const poweredWarn = poweredByServer.find((c) => c.id === "server_hygiene");
    assert.equal(poweredWarn.status, "warn");
    assert.match(poweredWarn.detail, /Express/);

    // TLS 1.2 => warn
    const tls12 = runSecurityChecks(doc, {
      isHttps: true,
      protocol: "TLSv1.2",
      authorized: true,
      daysRemaining: 80,
      expired: false,
    });
    assert.equal(tls12.find((c) => c.id === "https_tls").status, "warn");

    // Cert expiring in 20 days => warn
    const expiringSoon = runSecurityChecks(doc, {
      isHttps: true,
      protocol: "TLSv1.3",
      authorized: true,
      daysRemaining: 20,
      expired: false,
    });
    assert.equal(expiringSoon.find((c) => c.id === "https_tls").status, "warn");

    // Cert expiring in 5 days => fail
    const criticalCert = runSecurityChecks(doc, {
      isHttps: true,
      protocol: "TLSv1.3",
      authorized: true,
      daysRemaining: 5,
      expired: false,
    });
    assert.equal(criticalCert.find((c) => c.id === "https_tls").status, "fail");
  });

  it("evaluates performance thresholds (TTFB, compression, HTML size)", () => {
    const slowDoc = {
      ttfbMs: 950,
      redirectCount: 2,
      redirectLoop: false,
      headers: new Headers(),
      htmlBytes: 15 * 1024,
    };
    const checks = runPerformanceChecks(slowDoc, { alpnProtocol: "http/1.1" });
    assert.equal(checks.find((c) => c.id === "http_protocol").status, "warn");
    assert.equal(checks.find((c) => c.id === "ttfb").status, "fail");
    assert.equal(checks.find((c) => c.id === "redirects").status, "warn");
    assert.equal(checks.find((c) => c.id === "compression").status, "warn");
    assert.equal(checks.find((c) => c.id === "html_size").status, "pass");
    assert.equal(checks.find((c) => c.id === "caching").status, "warn");
  });

  it("evaluates separate open_graph and json_ld checks including malformed JSON-LD", () => {
    const robotsOk = { ok: true, status: 200 };
    const sitemapOk = { ok: true, status: 200 };

    // Valid OG + valid JSON-LD => both pass
    const validChecks = runSeoChecks(
      { html: CLEAN_HTML, headers: new Headers() },
      robotsOk,
      sitemapOk
    );
    assert.equal(validChecks.length, 7);
    assert.equal(validChecks.find((c) => c.id === "open_graph").status, "pass");
    assert.equal(validChecks.find((c) => c.id === "json_ld").status, "pass");

    // Partial OG (missing og:description) + malformed JSON-LD => both warn
    const badJsonLdHtml = `<!doctype html>
    <html lang="en"><head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Valid Title For Testing SEO Checks Here</title>
      <meta name="description" content="A sufficiently long meta description for testing purposes so that it passes the seventy to one hundred sixty five character requirement.">
      <link rel="canonical" href="https://example.com/">
      <meta property="og:title" content="Only Title">
      <script type="application/ld+json">{ invalid json: [ }</script>
    </head><body><h1>Hello</h1></body></html>`;

    const badChecks = runSeoChecks(
      { html: badJsonLdHtml, headers: new Headers() },
      robotsOk,
      sitemapOk
    );
    assert.equal(badChecks.find((c) => c.id === "open_graph").status, "warn");
    assert.equal(badChecks.find((c) => c.id === "json_ld").status, "warn");
    assert.match(badChecks.find((c) => c.id === "json_ld").detail, /invalid/i);
  });
});

describe("Integration tests with local mock HTTP servers", () => {
  let cleanServer;
  let insecureServer;
  let noindexServer;
  let redirectServer;

  before(async () => {
    // 1. Clean site (all headers, gzipped, valid SEO, robots, sitemap, clean Server header)
    cleanServer = await startMockServer((req, res) => {
      if (req.url === "/robots.txt") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        return res.end("User-agent: *\nAllow: /\n");
      }
      if (req.url === "/sitemap.xml") {
        res.writeHead(200, { "Content-Type": "application/xml" });
        return res.end('<?xml version="1.0"?><urlset></urlset>');
      }
      const gz = zlib.gzipSync(Buffer.from(CLEAN_HTML, "utf8"));
      res.writeHead(200, {
        Server: "nginx",
        "Content-Type": "text/html; charset=utf-8",
        "Content-Encoding": "gzip",
        "Cache-Control": "public, max-age=300",
        ETag: '"abc123"',
        "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
      });
      return res.end(gz);
    });

    // 2. Missing security headers + leaky Server / X-Powered-By headers
    insecureServer = await startMockServer((req, res) => {
      if (req.url === "/robots.txt" || req.url === "/sitemap.xml") {
        res.writeHead(404);
        return res.end("Not found");
      }
      res.writeHead(200, {
        Server: "nginx/1.24.0",
        "X-Powered-By": "Express",
        "Content-Type": "text/html; charset=utf-8",
      });
      return res.end(CLEAN_HTML);
    });

    // 3. Noindex SEO failure + missing title/h1/OG/JSON-LD
    noindexServer = await startMockServer((req, res) => {
      if (req.url !== "/") {
        res.writeHead(404);
        return res.end("Not found");
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      return res.end(
        `<!doctype html><html><head><meta name="robots" content="noindex, nofollow"></head><body><p>No H1, no title, no viewport</p></body></html>`
      );
    });

    // 4. Redirect chain & redirect loop
    redirectServer = await startMockServer((req, res) => {
      if (req.url === "/hop1") {
        res.writeHead(301, { Location: "/hop2" });
        return res.end();
      }
      if (req.url === "/hop2") {
        res.writeHead(302, { Location: "/hop3" });
        return res.end();
      }
      if (req.url === "/hop3") {
        res.writeHead(302, { Location: "/final" });
        return res.end();
      }
      if (req.url === "/loop-a") {
        res.writeHead(302, { Location: "/loop-b" });
        return res.end();
      }
      if (req.url === "/loop-b") {
        res.writeHead(302, { Location: "/loop-a" });
        return res.end();
      }
      if (req.url === "/final") {
        res.writeHead(200, { "Content-Type": "text/html" });
        return res.end(CLEAN_HTML);
      }
      res.writeHead(404);
      return res.end("Not found");
    });
  });

  after(async () => {
    await Promise.all([
      cleanServer.close(),
      insecureServer.close(),
      noindexServer.close(),
      redirectServer.close(),
    ]);
  });

  it("audits a clean site and matches the exact 20-check JSON schema (6+7+7)", async () => {
    const report = await auditSite(cleanServer.url);

    assert.equal(report.ok, true);
    assert.equal(report.host, "127.0.0.1");
    assert.equal(report.audited_url, `${cleanServer.url}/`);
    assert.equal(report.status_code, 200);
    assert.equal(typeof report.duration_ms, "number");
    assert.equal(typeof report.overall_score, "number");
    assert.equal(typeof report.grade, "string");
    assert.equal(report.checks.length, 20);
    assert.equal(
      report.counts.pass + report.counts.warn + report.counts.fail,
      20
    );

    const perfChecks = report.checks.filter((c) => c.category === "performance");
    const secChecks = report.checks.filter((c) => c.category === "security");
    const seoChecks = report.checks.filter((c) => c.category === "seo");
    assert.equal(perfChecks.length, 6);
    assert.equal(secChecks.length, 7);
    assert.equal(seoChecks.length, 7);

    // SEO should be 100; Performance has 5 pass + 1 warn (plain HTTP http_protocol) => 93
    assert.equal(report.categories.seo, 100);
    assert.equal(report.categories.performance, 93);

    // Security headers pass; only https_tls and hsts fail because mock server is HTTP
    const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));
    assert.equal(byId.http_protocol.status, "warn");
    assert.equal(byId.csp.status, "pass");
    assert.equal(byId.xcto.status, "pass");
    assert.equal(byId.framing.status, "pass");
    assert.equal(byId.referrer_permissions.status, "pass");
    assert.equal(byId.server_hygiene.status, "pass");
    assert.equal(byId.https_tls.status, "fail");
    assert.equal(byId.hsts.status, "fail");
    assert.equal(byId.open_graph.status, "pass");
    assert.equal(byId.json_ld.status, "pass");
  });

  it("flags missing security headers and exposed server versions accurately", async () => {
    const report = await auditSite(insecureServer.url);
    const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));

    assert.equal(byId.csp.status, "fail");
    assert.equal(byId.xcto.status, "fail");
    assert.equal(byId.framing.status, "fail");
    assert.equal(byId.referrer_permissions.status, "fail");
    assert.equal(byId.server_hygiene.status, "warn");
    assert.match(byId.server_hygiene.detail, /Express/);
    assert.match(byId.server_hygiene.detail, /nginx\/1\.24\.0/);
  });

  it("flags noindex and missing SEO metadata as failures", async () => {
    const report = await auditSite(noindexServer.url);
    const byId = Object.fromEntries(report.checks.map((c) => [c.id, c]));

    assert.equal(byId.canonical_indexable.status, "fail");
    assert.equal(byId.title.status, "fail");
    assert.equal(byId.meta_description.status, "fail");
    assert.equal(byId.h1_and_lang.status, "fail");
    assert.equal(byId.robots_sitemap.status, "fail");
    assert.equal(byId.open_graph.status, "warn");
    assert.equal(byId.json_ld.status, "warn");
  });

  it("traces 3-hop redirect chains and detects redirect loops without crashing", async () => {
    const chainReport = await auditSite(`${redirectServer.url}/hop1`);
    assert.equal(chainReport.audited_url, `${redirectServer.url}/final`);
    assert.equal(
      chainReport.checks.find((c) => c.id === "redirects").status,
      "fail"
    );

    const loopReport = await auditSite(`${redirectServer.url}/loop-a`);
    assert.equal(loopReport.ok, true);
    assert.equal(
      loopReport.checks.find((c) => c.id === "redirects").status,
      "fail"
    );
  });

  it("CLI --json outputs valid JSON with 20 checks and no ANSI codes", async () => {
    const res = await runCli([cleanServer.url, "--json"]);
    assert.equal(res.status, 0);
    assert.equal(res.stderr, "");
    assert.doesNotMatch(res.stdout, /\x1b\[/);

    const data = JSON.parse(res.stdout);
    assert.equal(data.ok, true);
    assert.equal(data.checks.length, 20);
    assert.equal(data.counts.pass + data.counts.warn + data.counts.fail, 20);
    assert.equal(data.categories.seo, 100);
  });

  it("CLI --min-score and --fail-on enforce exit codes 0 and 1", async () => {
    const passMin = await runCli([cleanServer.url, "--min-score", "50", "--no-color"]);
    assert.equal(passMin.status, 0);

    const failMin = await runCli([cleanServer.url, "--min-score", "99", "--no-color"]);
    assert.equal(failMin.status, 1);

    const failOnFail = await runCli([cleanServer.url, "--fail-on", "fail", "--no-color"]);
    assert.equal(failOnFail.status, 1);

    const failOnWarn = await runCli([cleanServer.url, "--fail-on", "warn", "--no-color"]);
    assert.equal(failOnWarn.status, 1);
  });

  it("CLI exits with code 2 on invalid URL or bad flags, and 0 on --help/--version", async () => {
    const badUrl = await runCli(["not a valid url"]);
    assert.equal(badUrl.status, 2);

    const badFlag = await runCli(["--unknown-flag"]);
    assert.equal(badFlag.status, 2);

    const help = await runCli(["--help"]);
    assert.equal(help.status, 0);
    assert.match(help.stdout, /Usage: tizuvo-audit/);

    const version = await runCli(["--version"]);
    assert.equal(version.status, 0);
    assert.equal(version.stdout.trim(), "1.1.0");
  });

  it("formatter renders clean plain-text output when color is disabled", async () => {
    const report = await auditSite(cleanServer.url);
    const out = formatTerminal(report, { color: false });
    assert.doesNotMatch(out, /\x1b\[/);
    assert.match(out, /TIZUVO SITE AUDIT/);
    assert.match(out, /Performance & Transport/);
    assert.match(out, /Security & TLS/);
    assert.match(out, /Technical SEO/);
  });
});
