/**
 * Pillar 1: Performance & Transport (6 checks)
 */

const COMPRESSION_LABELS = {
  br: "br (Brotli)",
  zstd: "zstd (Zstandard)",
  gzip: "gzip",
};

/**
 * Run all 6 Performance & Transport checks.
 */
export function runPerformanceChecks(doc, tlsInfo) {
  return [
    checkHttpProtocol(tlsInfo),
    checkTtfb(doc),
    checkRedirects(doc),
    checkCompression(doc),
    checkHtmlSize(doc),
    checkCaching(doc),
  ];
}

function checkHttpProtocol(tlsInfo) {
  const alpn = (tlsInfo?.alpnProtocol || "").toLowerCase();

  if (alpn === "h3") {
    return {
      id: "http_protocol",
      category: "performance",
      status: "pass",
      label: "HTTP Protocol",
      detail: "HTTP/3 enabled",
    };
  }

  if (alpn === "h2") {
    return {
      id: "http_protocol",
      category: "performance",
      status: "pass",
      label: "HTTP Protocol",
      detail: "HTTP/2 enabled",
    };
  }

  return {
    id: "http_protocol",
    category: "performance",
    status: "warn",
    label: "HTTP Protocol",
    detail: "HTTP/1.1 only — consider enabling HTTP/2",
  };
}

function checkTtfb(doc) {
  const ms = Math.max(0, Math.round(doc.ttfbMs ?? 0));
  let status;
  if (ms < 400) {
    status = "pass";
  } else if (ms <= 900) {
    status = "warn";
  } else {
    status = "fail";
  }

  return {
    id: "ttfb",
    category: "performance",
    status,
    label: "Time to First Byte",
    detail: `${ms}ms (target <400ms)`,
  };
}

function checkRedirects(doc) {
  const hops = doc.redirectCount ?? 0;
  const loop = Boolean(doc.redirectLoop);

  if (loop) {
    return {
      id: "redirects",
      category: "performance",
      status: "fail",
      label: "Redirect Chain",
      detail: `Redirect loop or >5 hops detected (${hops} hops)`,
    };
  }

  let status;
  if (hops <= 1) {
    status = "pass";
  } else if (hops === 2) {
    status = "warn";
  } else {
    status = "fail";
  }

  const hopWord = hops === 1 ? "hop" : "hops";
  const suffix = hops <= 1 ? "" : " (target <=1)";

  return {
    id: "redirects",
    category: "performance",
    status,
    label: "Redirect Chain",
    detail: `${hops} ${hopWord}${suffix}`,
  };
}

function checkCompression(doc) {
  const rawEncoding = (doc.headers?.get?.("content-encoding") || "")
    .toLowerCase()
    .trim();
  const encodings = rawEncoding
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean);

  const matched = encodings.find((e) => e === "br" || e === "zstd" || e === "gzip");
  if (matched) {
    return {
      id: "compression",
      category: "performance",
      status: "pass",
      label: "Compression",
      detail: COMPRESSION_LABELS[matched] || matched,
    };
  }

  const bytes = doc.htmlBytes ?? 0;
  const kb = (bytes / 1024).toFixed(1);

  if (bytes < 10 * 1024) {
    return {
      id: "compression",
      category: "performance",
      status: "pass",
      label: "Compression",
      detail: `Uncompressed (${kb} KB — under 10 KB threshold)`,
    };
  }

  return {
    id: "compression",
    category: "performance",
    status: "warn",
    label: "Compression",
    detail: `Uncompressed HTML (${kb} KB — enable br, zstd, or gzip)`,
  };
}

function checkHtmlSize(doc) {
  const bytes = doc.htmlBytes ?? 0;
  const kb = bytes / 1024;
  const formatted = kb.toFixed(1);

  let status;
  if (kb < 100) {
    status = "pass";
  } else if (kb <= 250) {
    status = "warn";
  } else {
    status = "fail";
  }

  return {
    id: "html_size",
    category: "performance",
    status,
    label: "HTML Payload Size",
    detail: `${formatted} KB (target <100 KB)`,
  };
}

function checkCaching(doc) {
  const cacheControl = doc.headers?.get?.("cache-control")?.trim() || "";
  const etag = doc.headers?.get?.("etag")?.trim() || "";

  if (cacheControl && etag) {
    return {
      id: "caching",
      category: "performance",
      status: "pass",
      label: "Cache Headers",
      detail: "Cache-Control and ETag present",
    };
  }

  if (cacheControl) {
    return {
      id: "caching",
      category: "performance",
      status: "pass",
      label: "Cache Headers",
      detail: `Cache-Control: ${truncate(cacheControl, 60)}`,
    };
  }

  if (etag) {
    return {
      id: "caching",
      category: "performance",
      status: "pass",
      label: "Cache Headers",
      detail: "ETag present",
    };
  }

  return {
    id: "caching",
    category: "performance",
    status: "warn",
    label: "Cache Headers",
    detail: "Missing both Cache-Control and ETag",
  };
}

function truncate(str, maxLen) {
  return str.length > maxLen ? `${str.slice(0, maxLen - 1)}…` : str;
}
