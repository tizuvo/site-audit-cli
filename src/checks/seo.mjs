/**
 * Pillar 3: Technical SEO (6 checks)
 */

/**
 * Strip HTML comments safely to avoid matching commented-out tags.
 */
function stripComments(html) {
  return String(html || "").replace(/<!--[\s\S]*?-->/g, "");
}

/**
 * Decode common HTML entities and collapse whitespace.
 */
function decodeText(str) {
  return String(str || "")
    .replace(/<[^>]*>/g, "")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Parse HTML tag attributes into a lowercase key-value map.
 */
function parseAttributes(tagStr) {
  const attrs = {};
  const attrRe = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  // Skip the tag name itself
  const spaceIdx = tagStr.search(/\s/);
  if (spaceIdx === -1) return attrs;
  const body = tagStr.slice(spaceIdx);

  let match;
  while ((match = attrRe.exec(body)) !== null) {
    const key = match[1].toLowerCase();
    const val = match[2] ?? match[3] ?? match[4] ?? "";
    attrs[key] = val;
  }
  return attrs;
}

/**
 * Find all opening tags matching a tag name (e.g. "meta", "link", "html").
 */
function findTags(html, tagName) {
  const re = new RegExp(`<${tagName}(?:\\s[^>]*)?>`, "gi");
  const results = [];
  let match;
  while ((match = re.exec(html)) !== null) {
    results.push(parseAttributes(match[0]));
  }
  return results;
}

/**
 * Run all 6 Technical SEO checks.
 */
export function runSeoChecks(doc, robotsTxt, sitemapXml) {
  const cleanHtml = stripComments(doc.html || "");
  const metaTags = findTags(cleanHtml, "meta");
  const linkTags = findTags(cleanHtml, "link");
  const htmlTags = findTags(cleanHtml, "html");

  return [
    checkTitle(cleanHtml),
    checkMetaDescription(metaTags),
    checkH1AndLang(cleanHtml, htmlTags, metaTags),
    checkCanonicalIndexable(doc, metaTags, linkTags),
    checkRobotsSitemap(robotsTxt, sitemapXml),
    checkStructuredSocial(cleanHtml, metaTags),
  ];
}

function checkTitle(html) {
  const match = html.match(/<title(?:\s[^>]*)?>([\s\S]*?)<\/title>/i);
  const title = match ? decodeText(match[1]) : "";

  if (!title) {
    return {
      id: "title",
      category: "seo",
      status: "fail",
      label: "Title Tag",
      detail: "Missing or empty <title> tag",
    };
  }

  const len = title.length;
  if (len >= 20 && len <= 65) {
    return {
      id: "title",
      category: "seo",
      status: "pass",
      label: "Title Tag",
      detail: `${len} chars (target 20–65)`,
    };
  }

  const reason = len < 20 ? "too short" : "too long";
  return {
    id: "title",
    category: "seo",
    status: "warn",
    label: "Title Tag",
    detail: `${len} chars (${reason}, target 20–65)`,
  };
}

function checkMetaDescription(metaTags) {
  const descTag = metaTags.find(
    (m) => (m.name || "").toLowerCase().trim() === "description"
  );
  const content = descTag ? decodeText(descTag.content || "") : "";

  if (!content) {
    return {
      id: "meta_description",
      category: "seo",
      status: "fail",
      label: "Meta Description",
      detail: 'Missing <meta name="description">',
    };
  }

  const len = content.length;
  if (len >= 70 && len <= 165) {
    return {
      id: "meta_description",
      category: "seo",
      status: "pass",
      label: "Meta Description",
      detail: `${len} chars (target 70–165)`,
    };
  }

  const reason = len < 70 ? "too short" : "too long";
  return {
    id: "meta_description",
    category: "seo",
    status: "warn",
    label: "Meta Description",
    detail: `${len} chars (${reason}, target 70–165)`,
  };
}

function checkH1AndLang(html, htmlTags, metaTags) {
  const h1Matches = html.match(/<h1(?:\s[^>]*)?>[\s\S]*?<\/h1>/gi) || [];
  const h1Count = h1Matches.length;

  const lang = (htmlTags[0]?.lang || "").trim();
  const hasLang = lang.length > 0;

  const viewportTag = metaTags.find(
    (m) => (m.name || "").toLowerCase().trim() === "viewport"
  );
  const hasViewport = Boolean((viewportTag?.content || "").trim());

  const parts = [
    `${h1Count} H1`,
    hasLang ? `lang="${lang}"` : "missing lang",
    hasViewport ? "viewport set" : "missing viewport",
  ];

  if (h1Count === 0 || !hasViewport) {
    return {
      id: "h1_and_lang",
      category: "seo",
      status: "fail",
      label: "H1, Lang & Viewport",
      detail: parts.join(" · "),
    };
  }

  if (h1Count > 1 || !hasLang) {
    return {
      id: "h1_and_lang",
      category: "seo",
      status: "warn",
      label: "H1, Lang & Viewport",
      detail: parts.join(" · "),
    };
  }

  return {
    id: "h1_and_lang",
    category: "seo",
    status: "pass",
    label: "H1, Lang & Viewport",
    detail: parts.join(" · "),
  };
}

function checkCanonicalIndexable(doc, metaTags, linkTags) {
  const robotsMeta = metaTags
    .filter((m) => (m.name || "").toLowerCase().trim() === "robots")
    .map((m) => (m.content || "").toLowerCase())
    .join(", ");

  const xRobotsHeader = (doc.headers?.get?.("x-robots-tag") || "").toLowerCase();
  const hasNoindex = /\bnoindex\b/.test(robotsMeta) || /\bnoindex\b/.test(xRobotsHeader);

  if (hasNoindex) {
    return {
      id: "canonical_indexable",
      category: "seo",
      status: "fail",
      label: "Canonical & Indexability",
      detail: "Page is marked noindex (blocked from search engines)",
    };
  }

  const canonicalTag = linkTags.find((l) => {
    const rels = (l.rel || "").toLowerCase().split(/\s+/);
    return rels.includes("canonical") && Boolean((l.href || "").trim());
  });

  if (canonicalTag) {
    return {
      id: "canonical_indexable",
      category: "seo",
      status: "pass",
      label: "Canonical & Indexability",
      detail: "Canonical set · indexable",
    };
  }

  return {
    id: "canonical_indexable",
    category: "seo",
    status: "warn",
    label: "Canonical & Indexability",
    detail: "Indexable · missing <link rel=\"canonical\">",
  };
}

function checkRobotsSitemap(robotsTxt, sitemapXml) {
  const hasRobots = Boolean(robotsTxt?.ok);
  const hasSitemap = Boolean(sitemapXml?.ok);

  if (hasRobots && hasSitemap) {
    return {
      id: "robots_sitemap",
      category: "seo",
      status: "pass",
      label: "robots.txt & sitemap.xml",
      detail: "Both reachable (HTTP 200)",
    };
  }

  if (hasRobots || hasSitemap) {
    const found = hasRobots ? "/robots.txt" : "/sitemap.xml";
    const missing = hasRobots ? "/sitemap.xml" : "/robots.txt";
    return {
      id: "robots_sitemap",
      category: "seo",
      status: "warn",
      label: "robots.txt & sitemap.xml",
      detail: `${found} found · ${missing} missing`,
    };
  }

  return {
    id: "robots_sitemap",
    category: "seo",
    status: "fail",
    label: "robots.txt & sitemap.xml",
    detail: "Both /robots.txt and /sitemap.xml missing",
  };
}

function checkStructuredSocial(html, metaTags) {
  const ldJsonRe = /<script\b[^>]*type\s*=\s*(?:"application\/ld\+json"|'application\/ld\+json'|application\/ld\+json)[^>]*>([\s\S]*?)<\/script>/gi;
  let hasJsonLd = false;
  let match;
  while ((match = ldJsonRe.exec(html)) !== null) {
    if ((match[1] || "").trim().length > 0) {
      hasJsonLd = true;
      break;
    }
  }

  const hasOgTitle = metaTags.some(
    (m) =>
      ((m.property || m.name || "").toLowerCase().trim() === "og:title") &&
      Boolean((m.content || "").trim())
  );
  const hasOgDesc = metaTags.some(
    (m) =>
      ((m.property || m.name || "").toLowerCase().trim() === "og:description") &&
      Boolean((m.content || "").trim())
  );
  const hasOpenGraph = hasOgTitle && hasOgDesc;

  if (hasJsonLd && hasOpenGraph) {
    return {
      id: "structured_social",
      category: "seo",
      status: "pass",
      label: "Structured Data & Social",
      detail: "JSON-LD and Open Graph (og:title + og:description) present",
    };
  }

  if (hasJsonLd) {
    return {
      id: "structured_social",
      category: "seo",
      status: "warn",
      label: "Structured Data & Social",
      detail: "JSON-LD present · Open Graph incomplete or missing",
    };
  }

  if (hasOpenGraph) {
    return {
      id: "structured_social",
      category: "seo",
      status: "warn",
      label: "Structured Data & Social",
      detail: "Open Graph present · JSON-LD missing",
    };
  }

  return {
    id: "structured_social",
    category: "seo",
    status: "warn",
    label: "Structured Data & Social",
    detail: "Missing both JSON-LD and Open Graph tags",
  };
}
