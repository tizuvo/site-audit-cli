import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import zlib from "node:zlib";
import { performance } from "node:perf_hooks";

export const DEFAULT_TIMEOUT_MS = 8000;
export const MAX_REDIRECTS = 5;
export const USER_AGENT = "@tizuvo/audit/1.0 (+https://tizuvo.com/audit)";

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const TLS_CERT_ERROR_CODES = new Set([
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "HOSTNAME_MISMATCH",
]);

export class InvalidUrlError extends Error {
  constructor(message) {
    super(message);
    this.name = "InvalidUrlError";
    this.code = "INVALID_URL";
  }
}

export class NetworkError extends Error {
  constructor(message, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = "NetworkError";
    this.code = "NETWORK_ERROR";
  }
}

/**
 * Validate hostname syntax (DNS name, localhost, IPv4, or bracketed IPv6).
 */
export function isValidHostname(hostname) {
  if (!hostname || typeof hostname !== "string") return false;
  if (hostname.length > 253) return false;

  // Strip IPv6 brackets if present
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return net.isIPv6(hostname.slice(1, -1));
  }

  if (net.isIPv4(hostname)) return true;

  const lower = hostname.toLowerCase();
  if (lower === "localhost") return true;

  // Must contain at least one dot for non-localhost domain names
  if (!lower.includes(".")) return false;
  if (lower.startsWith(".") || lower.endsWith(".") || lower.includes("..")) {
    return false;
  }

  const labels = lower.split(".");
  const labelRe = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  for (const label of labels) {
    if (!labelRe.test(label)) return false;
  }

  // TLD must be at least 2 chars and not all-numeric
  const tld = labels[labels.length - 1];
  if (tld.length < 2 || /^\d+$/.test(tld)) return false;

  return true;
}

/**
 * Normalize a bare domain or full URL into a validated URL object.
 * Bare domains default to https://.
 */
export function normalizeUrl(input) {
  if (typeof input !== "string") {
    throw new InvalidUrlError("URL must be a non-empty string.");
  }

  const trimmed = input.trim();
  if (!trimmed || /\s/.test(trimmed)) {
    throw new InvalidUrlError(`Invalid URL: "${input}"`);
  }

  let candidate = trimmed;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(candidate)) {
    if (!/^https?:\/\//i.test(candidate)) {
      throw new InvalidUrlError(
        `Unsupported URL protocol in "${input}". Only http:// and https:// are supported.`
      );
    }
  } else if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)) {
    // Reject schemes like javascript:, file:, mailto:, ftp:
    throw new InvalidUrlError(
      `Unsupported URL protocol in "${input}". Only http:// and https:// are supported.`
    );
  } else {
    candidate = `https://${candidate}`;
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new InvalidUrlError(`Malformed URL: "${input}"`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new InvalidUrlError(`Unsupported URL protocol: "${parsed.protocol}"`);
  }

  if (!isValidHostname(parsed.hostname)) {
    throw new InvalidUrlError(`Invalid hostname: "${parsed.hostname || input}"`);
  }

  return parsed;
}

/**
 * Extract error code from a fetch/TLS error or its cause chain.
 */
function getErrorCode(err) {
  return err?.cause?.code || err?.code || "";
}

/**
 * Low-level HTTP/HTTPS single-request fallback (used when fetch fails on
 * expired or self-signed certificates so the audit can still inspect headers/HTML).
 */
function requestSingleInsecure(urlString, timeoutMs) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlString);
    const mod = parsed.protocol === "https:" ? https : http;
    const start = performance.now();
    let settled = false;

    const req = mod.request(
      parsed,
      {
        method: "GET",
        rejectUnauthorized: false,
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Encoding": "br, gzip, deflate",
        },
      },
      (res) => {
        const ttfbMs = Math.round(performance.now() - start);
        const chunks = [];

        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          if (settled) return;
          settled = true;

          const rawBuffer = Buffer.concat(chunks);
          const encoding = String(res.headers["content-encoding"] || "")
            .toLowerCase()
            .trim();

          let decodedBuffer = rawBuffer;
          try {
            if (encoding === "gzip") {
              decodedBuffer = zlib.gunzipSync(rawBuffer);
            } else if (encoding === "br") {
              decodedBuffer = zlib.brotliDecompressSync(rawBuffer);
            } else if (encoding === "deflate") {
              decodedBuffer = zlib.inflateSync(rawBuffer);
            }
          } catch {
            decodedBuffer = rawBuffer;
          }

          const headers = new Headers();
          for (const [key, val] of Object.entries(res.headers)) {
            if (Array.isArray(val)) {
              for (const v of val) headers.append(key, v);
            } else if (val !== undefined) {
              headers.set(key, String(val));
            }
          }

          resolve({
            status: res.statusCode || 0,
            headers,
            html: decodedBuffer.toString("utf8"),
            ttfbMs,
          });
        });
        res.on("error", (err) => {
          if (!settled) {
            settled = true;
            reject(err);
          }
        });
      }
    );

    req.setTimeout(timeoutMs, () => {
      if (!settled) {
        settled = true;
        req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
      }
    });

    req.on("error", (err) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    });

    req.end();
  });
}

/**
 * Fetch a single URL using native fetch, falling back to insecure node:https
 * only if the remote server has an expired/self-signed TLS certificate.
 */
async function fetchHop(urlString, timeoutMs, isFinalExpected = false) {
  const start = performance.now();
  try {
    const res = await fetch(urlString, {
      method: "GET",
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
    const ttfbMs = Math.round(performance.now() - start);
    return { res, ttfbMs, insecureFallback: false };
  } catch (err) {
    const code = getErrorCode(err);
    if (urlString.startsWith("https://") && TLS_CERT_ERROR_CODES.has(code)) {
      const fallback = await requestSingleInsecure(urlString, timeoutMs);
      return {
        res: {
          status: fallback.status,
          headers: fallback.headers,
          text: async () => fallback.html,
          body: null,
        },
        ttfbMs: fallback.ttfbMs,
        insecureFallback: true,
      };
    }
    throw err;
  }
}

/**
 * Fetch target URL while manually tracing redirects (capped at MAX_REDIRECTS).
 * Returns final response metadata, TTFB, redirect chain, headers, and HTML body.
 */
export async function fetchDocument(startUrl, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let currentUrl = startUrl;
  const chain = [currentUrl];
  const visited = new Set([currentUrl]);
  let redirectCount = 0;
  let redirectLoop = false;
  let lastHop = null;

  for (let step = 0; step <= MAX_REDIRECTS; step++) {
    let hop;
    try {
      hop = await fetchHop(currentUrl, timeoutMs);
    } catch (err) {
      const reason = err?.cause?.message || err?.message || "Unknown network error";
      throw new NetworkError(`Failed to fetch ${currentUrl}: ${reason}`, err);
    }

    lastHop = hop;
    const { res } = hop;
    const location = res.headers.get("location");

    if (REDIRECT_STATUSES.has(res.status) && location) {
      // Cancel intermediate body to free socket
      try {
        await res.body?.cancel?.();
      } catch {
        // Ignore cancellation errors
      }

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        break;
      }

      if (visited.has(nextUrl)) {
        redirectLoop = true;
        redirectCount += 1;
        chain.push(nextUrl);
        break;
      }

      if (redirectCount >= MAX_REDIRECTS) {
        redirectLoop = true;
        break;
      }

      redirectCount += 1;
      visited.add(nextUrl);
      chain.push(nextUrl);
      currentUrl = nextUrl;
      continue;
    }

    // Reached final non-redirect response
    let html = "";
    try {
      html = await res.text();
    } catch {
      html = "";
    }

    return {
      finalUrl: currentUrl,
      statusCode: res.status,
      headers: res.headers,
      html,
      htmlBytes: Buffer.byteLength(html, "utf8"),
      ttfbMs: hop.ttfbMs,
      redirectCount,
      redirectLoop,
      chain,
    };
  }

  // Redirect loop or max hops exceeded without reaching a final 2xx/4xx/5xx page
  return {
    finalUrl: currentUrl,
    statusCode: lastHop?.res?.status ?? 0,
    headers: lastHop?.res?.headers ?? new Headers(),
    html: "",
    htmlBytes: 0,
    ttfbMs: lastHop?.ttfbMs ?? 0,
    redirectCount,
    redirectLoop: true,
    chain,
  };
}

/**
 * Inspect TLS protocol and peer certificate directly via node:tls.
 * Never throws; returns a structured diagnostic object.
 */
export function inspectTls(urlString, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return Promise.resolve({
      isHttps: false,
      protocol: null,
      authorized: false,
      authorizationError: null,
      cert: null,
      daysRemaining: null,
      expired: false,
      error: "Invalid URL",
    });
  }

  if (parsed.protocol !== "https:") {
    return Promise.resolve({
      isHttps: false,
      protocol: null,
      authorized: false,
      authorizationError: null,
      cert: null,
      daysRemaining: null,
      expired: false,
      error: null,
    });
  }

  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  const port = parsed.port ? Number(parsed.port) : 443;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const socket = tls.connect({
      host,
      port,
      servername: net.isIP(host) ? undefined : host,
      rejectUnauthorized: false,
    });

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finish({
        isHttps: true,
        protocol: null,
        authorized: false,
        authorizationError: null,
        cert: null,
        daysRemaining: null,
        expired: false,
        error: `TLS handshake timed out after ${timeoutMs}ms`,
      });
    });

    socket.once("secureConnect", () => {
      const protocol = socket.getProtocol() || null;
      const authorized = Boolean(socket.authorized);
      const authorizationError = socket.authorizationError || null;
      const cert = socket.getPeerCertificate(false) || null;

      let daysRemaining = null;
      let expired = false;
      if (cert && cert.valid_to) {
        const validToMs = Date.parse(cert.valid_to);
        if (!Number.isNaN(validToMs)) {
          daysRemaining = Math.floor((validToMs - Date.now()) / 86_400_000);
          expired = validToMs <= Date.now();
        }
      }

      socket.end();
      socket.destroy();

      finish({
        isHttps: true,
        protocol,
        authorized,
        authorizationError,
        cert: cert && Object.keys(cert).length > 0 ? cert : null,
        daysRemaining,
        expired,
        error: null,
      });
    });

    socket.once("error", (err) => {
      socket.destroy();
      finish({
        isHttps: true,
        protocol: null,
        authorized: false,
        authorizationError: null,
        cert: null,
        daysRemaining: null,
        expired: false,
        error: err?.message || "TLS connection error",
      });
    });
  });
}

/**
 * Fetch an auxiliary endpoint (e.g. /robots.txt, /sitemap.xml, /.well-known/security.txt).
 * Never throws; returns { ok, status, text, error }.
 */
export async function fetchAuxiliary(origin, path, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const url = `${origin}${path}`;
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        "User-Agent": USER_AGENT,
      },
    });
    const text = res.status === 200 ? await res.text() : "";
    if (res.status !== 200) {
      try {
        await res.body?.cancel?.();
      } catch {
        // Ignore
      }
    }
    return {
      ok: res.status === 200,
      status: res.status,
      text,
      error: null,
    };
  } catch (err) {
    const code = getErrorCode(err);
    if (url.startsWith("https://") && TLS_CERT_ERROR_CODES.has(code)) {
      try {
        const fallback = await requestSingleInsecure(url, timeoutMs);
        return {
          ok: fallback.status === 200,
          status: fallback.status,
          text: fallback.status === 200 ? fallback.html : "",
          error: null,
        };
      } catch (fallbackErr) {
        return {
          ok: false,
          status: 0,
          text: "",
          error: fallbackErr?.message || "Request failed",
        };
      }
    }
    return {
      ok: false,
      status: 0,
      text: "",
      error: err?.cause?.message || err?.message || "Request failed",
    };
  }
}
