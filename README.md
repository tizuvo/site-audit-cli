<p align="center">
  <a href="https://tizuvo.com/audit">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://tizuvo.com/assets/svg/tizuvo-lockup-dark.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://tizuvo.com/assets/svg/tizuvo-lockup-light.svg" />
      <img alt="Tizuvo" src="https://tizuvo.com/assets/svg/tizuvo-lockup-light.svg" height="40" />
    </picture>
  </a>
</p>

<h1 align="center">@tizuvo/audit</h1>

<p align="center">
  <strong>Zero-dependency Node.js 20+ CLI that audits any website's Performance &amp; Transport, Security &amp; TLS, and Technical SEO in ~3 seconds.</strong>
</p>

<p align="center">
  <a href="https://tizuvo.com/audit">Web Version</a> &middot;
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#cli-options">CLI Options</a> &middot;
  <a href="#programmatic-api">Programmatic API</a> &middot;
  <a href="#github-actions">GitHub Actions</a>
</p>

---

## Why `@tizuvo/audit`?

- **Zero dependencies** — Built exclusively on Node.js 20+ built-ins (`fetch`, `node:tls`, `node:http`, `node:https`, `node:util`, `node:perf_hooks`). Fast cold start, zero supply-chain bloat.
- **3 pillars, 18 high-signal checks** — Mirrors the exact scoring engine and JSON schema of [tizuvo.com/audit](https://tizuvo.com/audit):
  - **Performance & Transport (30%)**: TTFB, redirect hops, compression, HTML size, caching headers.
  - **Security & TLS (40%)**: TLS protocol & certificate expiry, HSTS, CSP, `X-Content-Type-Options`, framing protection, `Referrer-Policy` / `Permissions-Policy`, `security.txt`.
  - **Technical SEO (30%)**: `<title>`, meta description, `<h1>` / `lang` / viewport, canonical & indexability, `robots.txt` & `sitemap.xml`, JSON-LD & Open Graph.
- **CI-ready** — Built-in `--min-score`, `--fail-on`, and `--json` flags with clean exit codes (`0`, `1`, `2`).
- **Resilient** — Never crashes on unreachable hosts, expired/self-signed certs, redirect loops, missing headers, or malformed HTML.

Prefer a browser UI? Run the same audit instantly at **[https://tizuvo.com/audit](https://tizuvo.com/audit)**.

---

## Quick Start

Requires **Node.js >= 20.0.0**.

```bash
npx @tizuvo/audit https://yourcompany.com
```

Bare domains default to `https://`:

```bash
npx @tizuvo/audit yourcompany.com
```

Or install globally:

```bash
npm install -g @tizuvo/audit
tizuvo-audit https://yourcompany.com
```

---

## Sample Output

```text
  TIZUVO SITE AUDIT
  https://tizuvo.com/  ·  HTTP 200  ·  385ms

  OVERALL  98/100 (A+)   17 pass · 1 warn · 0 fail

  Performance & Transport                                      100/100
  ────────────────────────────────────────────────────────────────────
  ✓  Time to First Byte          142ms (target <400ms)
  ✓  Redirect Chain              0 hops
  ✓  Compression                 br (Brotli)
  ✓  HTML Payload Size           24.6 KB (target <100 KB)
  ✓  Cache Headers               Cache-Control, ETag

  Security & TLS                                               100/100
  ────────────────────────────────────────────────────────────────────
  ✓  HTTPS & TLS                 TLSv1.3 · cert valid 82 days
  ✓  HSTS                        max-age=63072000; includeSubDomains; preload
  ✓  Content-Security-Policy     Present (no unsafe-inline/unsafe-eval)
  ✓  X-Content-Type-Options      nosniff
  ✓  Clickjacking Protection     frame-ancestors + X-Frame-Options
  ✓  Referrer & Permissions      Both Referrer-Policy and Permissions-Policy set
  ✓  security.txt                Found at /.well-known/security.txt with Contact

  Technical SEO                                                 94/100
  ────────────────────────────────────────────────────────────────────
  ✓  Title Tag                   48 chars (target 20–65)
  ✓  Meta Description            134 chars (target 70–165)
  ✓  H1, Lang & Viewport         1 H1 · lang="en" · viewport set
  ✓  Canonical & Indexability    Canonical set · indexable
  ✓  robots.txt & sitemap.xml    Both reachable (HTTP 200)
  !  Structured Data & Social    Open Graph set · JSON-LD missing
```

---

## CLI Options

| Flag | Description | Default |
| --- | --- | --- |
| `<url>` | Target URL or bare domain (e.g. `tizuvo.com` or `https://tizuvo.com/path`) | *required* |
| `--json` | Emit raw JSON to `stdout` (no ANSI colors, no extra output) | `false` |
| `--min-score <n>` | Exit with code `1` if `overall_score < n` (0–100) | — |
| `--fail-on <fail\|warn>` | Exit with code `1` if any check has status `fail` (or `fail`/`warn` for `warn`) | — |
| `--timeout <ms>` | Per-request timeout in milliseconds | `8000` |
| `--no-color` | Disable ANSI colors (also respects `NO_COLOR` env var and non-TTY `stdout`) | `false` |
| `-h`, `--help` | Print usage help and exit | — |
| `-v`, `--version` | Print package version and exit | — |

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Audit completed and passed all configured thresholds |
| `1` | Audit completed but violated `--min-score` or `--fail-on` |
| `2` | Invalid CLI arguments, invalid URL, or unrecoverable network error |

---

## Programmatic API

`@tizuvo/audit` is pure ESM and exports `auditSite(url, options)`:

```js
import { auditSite } from "@tizuvo/audit";

const report = await auditSite("https://tizuvo.com", {
  timeoutMs: 8000,
});

console.log(report.overall_score, report.grade);
// 98 'A+'
```

### JSON Output Schema

`--json` and `auditSite()` return the exact schema used by [https://tizuvo.com/audit](https://tizuvo.com/audit):

```json
{
  "ok": true,
  "host": "tizuvo.com",
  "audited_url": "https://tizuvo.com/",
  "status_code": 200,
  "duration_ms": 385,
  "overall_score": 98,
  "grade": "A+",
  "counts": {
    "pass": 17,
    "warn": 1,
    "fail": 0
  },
  "categories": {
    "performance": 100,
    "security": 100,
    "seo": 94
  },
  "checks": [
    {
      "id": "ttfb",
      "category": "performance",
      "status": "pass",
      "label": "Time to First Byte",
      "detail": "142ms (target <400ms)"
    }
  ]
}
```

---

## Scoring Model

- **Per-check points**: `pass` = 100, `warn` = 55, `fail` = 0.
- **Category score**: Rounded arithmetic mean of checks in that category.
- **Overall score**: `Math.round(performance * 0.30 + security * 0.40 + seo * 0.30)`.
- **Letter grade**: `A+` (`>=95`), `A` (`>=90`), `B` (`>=80`), `C` (`>=70`), `D` (`>=60`), `F` (`<60`).

---

## GitHub Actions

Add a scheduled or post-deploy site audit to any repository:

```yaml
name: Site Audit

on:
  push:
    branches: [main]
  schedule:
    - cron: "0 9 * * 1"

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Run Tizuvo Site Audit
        run: npx -y @tizuvo/audit https://yourcompany.com --min-score 90 --fail-on fail
```

---

## License

MIT &copy; 2026 [Tizuvo](https://tizuvo.com)
