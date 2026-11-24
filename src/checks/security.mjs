/**
 * Pillar 2: Security & TLS (7 checks)
 */

/**
 * Parse a Content-Security-Policy header into a Map<directive, tokens[]>.
 */
function parseCsp(cspHeader) {
  const directives = new Map();
  if (!cspHeader) return directives;

  for (const part of cspHeader.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = tokens[0].toLowerCase();
    const values = tokens.slice(1).map((v) => v.toLowerCase());
    if (!directives.has(name)) {
      directives.set(name, values);
    }
  }
  return directives;
}

/**
 * Run all 7 Security & TLS checks.
 */
export function runSecurityChecks(doc, tlsInfo, securityTxt) {
  return [
    checkHttpsTls(tlsInfo),
    checkHsts(doc, tlsInfo),
    checkCsp(doc),
    checkXcto(doc),
    checkFraming(doc),
    checkReferrerPermissions(doc),
    checkSecurityTxt(securityTxt),
  ];
}

function checkHttpsTls(tls) {
  if (!tls || !tls.isHttps) {
    return {
      id: "https_tls",
      category: "security",
      status: "fail",
      label: "HTTPS & TLS",
      detail: "Site served over insecure HTTP",
    };
  }

  if (tls.error || !tls.protocol) {
    return {
      id: "https_tls",
      category: "security",
      status: "fail",
      label: "HTTPS & TLS",
      detail: `TLS inspection failed (${tls.error || "no handshake"})`,
    };
  }

  if (tls.expired || (tls.daysRemaining !== null && tls.daysRemaining <= 0)) {
    return {
      id: "https_tls",
      category: "security",
      status: "fail",
      label: "HTTPS & TLS",
      detail: `${tls.protocol} · certificate expired`,
    };
  }

  if (!tls.authorized) {
    const reason = tls.authorizationError || "untrusted certificate";
    return {
      id: "https_tls",
      category: "security",
      status: "fail",
      label: "HTTPS & TLS",
      detail: `${tls.protocol} · invalid certificate (${reason})`,
    };
  }

  if (tls.daysRemaining !== null && tls.daysRemaining < 14) {
    return {
      id: "https_tls",
      category: "security",
      status: "fail",
      label: "HTTPS & TLS",
      detail: `${tls.protocol} · cert expires in ${tls.daysRemaining}d (<14d)`,
    };
  }

  const isTls13 = tls.protocol === "TLSv1.3";
  const isTls12 = tls.protocol === "TLSv1.2";

  if (!isTls13 && !isTls12) {
    return {
      id: "https_tls",
      category: "security",
      status: "fail",
      label: "HTTPS & TLS",
      detail: `Deprecated protocol ${tls.protocol} (upgrade to TLSv1.3)`,
    };
  }

  const daysText =
    tls.daysRemaining !== null ? `cert valid ${tls.daysRemaining} days` : "cert valid";

  if (tls.daysRemaining !== null && tls.daysRemaining <= 30) {
    return {
      id: "https_tls",
      category: "security",
      status: "warn",
      label: "HTTPS & TLS",
      detail: `${tls.protocol} · ${daysText} (renew soon)`,
    };
  }

  if (isTls12) {
    return {
      id: "https_tls",
      category: "security",
      status: "warn",
      label: "HTTPS & TLS",
      detail: `${tls.protocol} · ${daysText} (TLSv1.3 recommended)`,
    };
  }

  return {
    id: "https_tls",
    category: "security",
    status: "pass",
    label: "HTTPS & TLS",
    detail: `${tls.protocol} · ${daysText}`,
  };
}

function checkHsts(doc, tls) {
  if (!tls?.isHttps) {
    return {
      id: "hsts",
      category: "security",
      status: "fail",
      label: "HSTS",
      detail: "Requires HTTPS (Strict-Transport-Security ignored on HTTP)",
    };
  }

  const header = doc.headers?.get?.("strict-transport-security")?.trim() || "";
  if (!header) {
    return {
      id: "hsts",
      category: "security",
      status: "fail",
      label: "HSTS",
      detail: "Missing Strict-Transport-Security header",
    };
  }

  const maxAgeMatch = header.match(/max-age\s*=\s*(\d+)/i);
  const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : 0;
  const hasIncludeSubDomains = /includesubdomains/i.test(header);
  const hasPreload = /\bpreload\b/i.test(header);

  const flags = [];
  if (hasIncludeSubDomains) flags.push("includeSubDomains");
  if (hasPreload) flags.push("preload");
  const flagStr = flags.length > 0 ? `; ${flags.join("; ")}` : "";

  if (maxAge >= 31536000) {
    return {
      id: "hsts",
      category: "security",
      status: "pass",
      label: "HSTS",
      detail: `max-age=${maxAge}${flagStr}`,
    };
  }

  return {
    id: "hsts",
    category: "security",
    status: "warn",
    label: "HSTS",
    detail: `Short max-age=${maxAge}${flagStr} (target >=31536000)`,
  };
}

function checkCsp(doc) {
  const header = doc.headers?.get?.("content-security-policy")?.trim() || "";
  if (!header) {
    return {
      id: "csp",
      category: "security",
      status: "fail",
      label: "Content-Security-Policy",
      detail: "Missing Content-Security-Policy header",
    };
  }

  const directives = parseCsp(header);
  const scriptTokens = directives.get("script-src") || [];
  const defaultTokens = directives.get("default-src") || [];
  const effectiveScript = scriptTokens.length > 0 ? scriptTokens : defaultTokens;

  const issues = [];
  if (
    effectiveScript.includes("'unsafe-inline'") ||
    defaultTokens.includes("'unsafe-inline'")
  ) {
    issues.push("unsafe-inline");
  }
  if (
    effectiveScript.includes("'unsafe-eval'") ||
    defaultTokens.includes("'unsafe-eval'")
  ) {
    issues.push("unsafe-eval");
  }

  if (issues.length > 0) {
    return {
      id: "csp",
      category: "security",
      status: "warn",
      label: "Content-Security-Policy",
      detail: `Present but allows ${issues.join(" and ")}`,
    };
  }

  return {
    id: "csp",
    category: "security",
    status: "pass",
    label: "Content-Security-Policy",
    detail: "Present without unsafe-inline or unsafe-eval",
  };
}

function checkXcto(doc) {
  const header = (doc.headers?.get?.("x-content-type-options") || "")
    .trim()
    .toLowerCase();

  if (header === "nosniff") {
    return {
      id: "xcto",
      category: "security",
      status: "pass",
      label: "X-Content-Type-Options",
      detail: "nosniff",
    };
  }

  return {
    id: "xcto",
    category: "security",
    status: "fail",
    label: "X-Content-Type-Options",
    detail: header ? `Invalid value "${header}" (expected nosniff)` : "Missing header",
  };
}

function checkFraming(doc) {
  const xfo = (doc.headers?.get?.("x-frame-options") || "").trim().toUpperCase();
  const validXfo = xfo === "DENY" || xfo === "SAMEORIGIN";

  const csp = doc.headers?.get?.("content-security-policy") || "";
  const directives = parseCsp(csp);
  const frameAncestors = directives.get("frame-ancestors");
  const hasFrameAncestors = Array.isArray(frameAncestors) && frameAncestors.length > 0;

  if (hasFrameAncestors && validXfo) {
    return {
      id: "framing",
      category: "security",
      status: "pass",
      label: "Clickjacking Protection",
      detail: `CSP frame-ancestors + X-Frame-Options: ${xfo}`,
    };
  }

  if (hasFrameAncestors) {
    return {
      id: "framing",
      category: "security",
      status: "pass",
      label: "Clickjacking Protection",
      detail: `CSP frame-ancestors ${frameAncestors.join(" ")}`,
    };
  }

  if (validXfo) {
    return {
      id: "framing",
      category: "security",
      status: "pass",
      label: "Clickjacking Protection",
      detail: `X-Frame-Options: ${xfo}`,
    };
  }

  return {
    id: "framing",
    category: "security",
    status: "fail",
    label: "Clickjacking Protection",
    detail: "Missing X-Frame-Options (DENY/SAMEORIGIN) and CSP frame-ancestors",
  };
}

function checkReferrerPermissions(doc) {
  const referrer = doc.headers?.get?.("referrer-policy")?.trim() || "";
  const permissions = doc.headers?.get?.("permissions-policy")?.trim() || "";

  if (referrer && permissions) {
    return {
      id: "referrer_permissions",
      category: "security",
      status: "pass",
      label: "Referrer & Permissions",
      detail: "Referrer-Policy and Permissions-Policy set",
    };
  }

  if (referrer) {
    return {
      id: "referrer_permissions",
      category: "security",
      status: "warn",
      label: "Referrer & Permissions",
      detail: "Referrer-Policy set · Permissions-Policy missing",
    };
  }

  if (permissions) {
    return {
      id: "referrer_permissions",
      category: "security",
      status: "warn",
      label: "Referrer & Permissions",
      detail: "Permissions-Policy set · Referrer-Policy missing",
    };
  }

  return {
    id: "referrer_permissions",
    category: "security",
    status: "fail",
    label: "Referrer & Permissions",
    detail: "Missing both Referrer-Policy and Permissions-Policy",
  };
}

function checkSecurityTxt(securityTxt) {
  if (securityTxt?.ok && /^\s*contact\s*:\s*\S+/im.test(securityTxt.text || "")) {
    return {
      id: "security_txt",
      category: "security",
      status: "pass",
      label: "security.txt",
      detail: "Found at /.well-known/security.txt with Contact",
    };
  }

  if (securityTxt?.ok) {
    return {
      id: "security_txt",
      category: "security",
      status: "warn",
      label: "security.txt",
      detail: "Found /.well-known/security.txt but missing Contact field",
    };
  }

  return {
    id: "security_txt",
    category: "security",
    status: "warn",
    label: "security.txt",
    detail: "Not found at /.well-known/security.txt",
  };
}
