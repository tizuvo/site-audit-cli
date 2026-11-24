#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { auditSite, InvalidUrlError, NetworkError } from "../src/audit.mjs";
import { DEFAULT_TIMEOUT_MS } from "../src/http.mjs";
import { formatJson, formatTerminal } from "../src/format.mjs";

const PKG = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8")
);

const HELP_TEXT = `
Usage: tizuvo-audit <url> [options]

Audit any website's Performance & Transport, Security & TLS, and Technical SEO.

Options:
  --json                 Emit raw JSON output to stdout
  --min-score <n>        Exit with code 1 if overall_score < n (0-100)
  --fail-on <fail|warn>  Exit with code 1 if any check has status fail (or warn)
  --timeout <ms>         Per-request timeout in milliseconds (default: ${DEFAULT_TIMEOUT_MS})
  --no-color             Disable ANSI color codes (also respects NO_COLOR)
  -h, --help             Show this help message
  -v, --version          Print version number

Exit codes:
  0  Audit completed and passed all configured thresholds
  1  Audit completed but violated --min-score or --fail-on
  2  Invalid CLI arguments, invalid URL, or unrecoverable network error

Examples:
  tizuvo-audit https://tizuvo.com
  tizuvo-audit tizuvo.com --json
  tizuvo-audit https://tizuvo.com --min-score 90 --fail-on fail
`.trim();

function failCli(message) {
  process.stderr.write(`Error: ${message}\n`);
  process.exit(2);
}

async function main() {
  let parsed;
  try {
    parsed = parseArgs({
      args: process.argv.slice(2),
      allowPositionals: true,
      strict: true,
      options: {
        json: { type: "boolean", default: false },
        "min-score": { type: "string" },
        "fail-on": { type: "string" },
        timeout: { type: "string" },
        "no-color": { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
        version: { type: "boolean", short: "v", default: false },
      },
    });
  } catch (err) {
    failCli(`${err.message}\nRun "tizuvo-audit --help" for usage.`);
  }

  const { values, positionals } = parsed;

  if (values.help) {
    process.stdout.write(`${HELP_TEXT}\n`);
    process.exit(0);
  }

  if (values.version) {
    process.stdout.write(`${PKG.version}\n`);
    process.exit(0);
  }

  if (positionals.length === 0) {
    failCli('Missing required <url> argument.\nRun "tizuvo-audit --help" for usage.');
  }

  if (positionals.length > 1) {
    failCli(`Unexpected extra argument: "${positionals[1]}".`);
  }

  let minScore = null;
  if (values["min-score"] !== undefined) {
    const n = Number(values["min-score"]);
    if (!Number.isFinite(n) || n < 0 || n > 100 || values["min-score"].trim() === "") {
      failCli(`Invalid --min-score value "${values["min-score"]}". Must be a number between 0 and 100.`);
    }
    minScore = n;
  }

  let failOn = null;
  if (values["fail-on"] !== undefined) {
    const mode = values["fail-on"].trim().toLowerCase();
    if (mode !== "fail" && mode !== "warn") {
      failCli(`Invalid --fail-on value "${values["fail-on"]}". Expected "fail" or "warn".`);
    }
    failOn = mode;
  }

  let timeoutMs = DEFAULT_TIMEOUT_MS;
  if (values.timeout !== undefined) {
    const t = Number(values.timeout);
    if (!Number.isInteger(t) || t <= 0) {
      failCli(`Invalid --timeout value "${values.timeout}". Must be a positive integer in ms.`);
    }
    timeoutMs = t;
  }

  const targetUrl = positionals[0];
  let report;
  try {
    report = await auditSite(targetUrl, { timeoutMs });
  } catch (err) {
    if (err instanceof InvalidUrlError || err instanceof NetworkError) {
      failCli(err.message);
    }
    failCli(err?.message || "Unexpected error while running audit.");
  }

  if (values.json) {
    process.stdout.write(`${formatJson(report)}\n`);
  } else {
    const useColor =
      !values["no-color"] &&
      !("NO_COLOR" in process.env) &&
      Boolean(process.stdout.isTTY);
    process.stdout.write(`${formatTerminal(report, { color: useColor })}\n`);
  }

  let violated = false;
  if (minScore !== null && report.overall_score < minScore) {
    violated = true;
  }
  if (failOn === "fail" && report.counts.fail > 0) {
    violated = true;
  }
  if (failOn === "warn" && (report.counts.fail > 0 || report.counts.warn > 0)) {
    violated = true;
  }

  process.exit(violated ? 1 : 0);
}

main();
