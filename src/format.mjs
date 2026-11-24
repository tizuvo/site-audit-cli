/**
 * Terminal ANSI scorecard formatter and JSON serializer.
 */

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
};

const PILLARS = [
  { key: "performance", title: "Performance & Transport" },
  { key: "security", title: "Security & TLS" },
  { key: "seo", title: "Technical SEO" },
];

const WIDTH = 72;
const LABEL_WIDTH = 26;

function paint(text, code, enabled) {
  return enabled ? `${code}${text}${ANSI.reset}` : text;
}

function scoreColor(score) {
  if (score >= 90) return ANSI.green;
  if (score >= 70) return ANSI.yellow;
  return ANSI.red;
}

function statusBadge(status, color) {
  if (status === "pass") return paint("✓", `${ANSI.bold}${ANSI.green}`, color);
  if (status === "warn") return paint("!", `${ANSI.bold}${ANSI.yellow}`, color);
  return paint("✗", `${ANSI.bold}${ANSI.red}`, color);
}

/**
 * Serialize audit report as formatted JSON (no ANSI codes).
 */
export function formatJson(report) {
  return JSON.stringify(report, null, 2);
}

/**
 * Render a clean, aligned terminal scorecard.
 */
export function formatTerminal(report, { color = true } = {}) {
  const lines = [];
  const rule = paint("─".repeat(WIDTH), ANSI.gray, color);

  lines.push("");
  lines.push(`  ${paint("TIZUVO SITE AUDIT", `${ANSI.bold}${ANSI.cyan}`, color)}`);
  lines.push(
    `  ${paint(report.audited_url, ANSI.bold, color)}  ${paint("·", ANSI.gray, color)}  HTTP ${report.status_code}  ${paint("·", ANSI.gray, color)}  ${report.duration_ms}ms`
  );
  lines.push("");

  const gradeText = `${report.overall_score}/100 (${report.grade})`;
  const countsText = [
    paint(`${report.counts.pass} pass`, ANSI.green, color),
    paint(`${report.counts.warn} warn`, ANSI.yellow, color),
    paint(`${report.counts.fail} fail`, ANSI.red, color),
  ].join(paint(" · ", ANSI.gray, color));

  lines.push(
    `  ${paint("OVERALL", ANSI.bold, color)}  ${paint(gradeText, `${ANSI.bold}${scoreColor(report.overall_score)}`, color)}   ${countsText}`
  );
  lines.push("");

  for (const pillar of PILLARS) {
    const score = report.categories[pillar.key] ?? 0;
    const scoreLabel = `${score}/100`;
    const padLen = Math.max(2, WIDTH - pillar.title.length - scoreLabel.length);

    lines.push(
      `  ${paint(pillar.title, ANSI.bold, color)}${" ".repeat(padLen)}${paint(scoreLabel, `${ANSI.bold}${scoreColor(score)}`, color)}`
    );
    lines.push(`  ${rule}`);

    const pillarChecks = report.checks.filter((c) => c.category === pillar.key);
    for (const check of pillarChecks) {
      const icon = statusBadge(check.status, color);
      const paddedLabel = check.label.padEnd(LABEL_WIDTH);
      const detailText =
        check.status === "pass"
          ? paint(check.detail, ANSI.dim, color)
          : check.status === "warn"
            ? paint(check.detail, ANSI.yellow, color)
            : paint(check.detail, ANSI.red, color);
      lines.push(`  ${icon}  ${paddedLabel}  ${detailText}`);
    }

    lines.push("");
  }

  lines.push(
    `  ${paint("Full interactive report:", ANSI.dim, color)} ${paint("https://tizuvo.com/audit", ANSI.cyan, color)}`
  );
  lines.push("");

  return lines.join("\n");
}
