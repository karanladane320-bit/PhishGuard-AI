/**
 * PhishGuard AI — Deterministic Analysis Engine
 * ---------------------------------------------
 * Pure, fast, explainable rules engine. Runs BEFORE any AI call.
 * All logic is deterministic: same input => same output, in <5ms.
 * The AI layer (see /api/analyze) receives this structured output
 * as grounding context, which dramatically reduces hallucination.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "safe" | "suspicious" | "high" | "critical";
export type Channel = "email" | "sms" | "text";

export interface Finding {
  id: string;
  category: CategoryKey;
  title: string;
  detail: string;
  severity: Severity;
  points: number;
}

export type CategoryKey =
  | "links"
  | "urgency"
  | "lure"
  | "identity"
  | "obfuscation";

export interface CategoryScore {
  key: CategoryKey;
  label: string;
  description: string;
  score: number;
  max: number;
}

export interface UrlInfo {
  url: string;
  host: string;
  flags: string[];
}

export interface EngineResult {
  channel: Channel;
  riskScore: number; // 0..100
  verdict: Verdict;
  verdictLabel: string;
  categories: CategoryScore[];
  findings: Finding[];
  urls: UrlInfo[];
  indicators: { label: string; value: string }[];
  recommendations: string[];
  meta: { chars: number; words: number; urlCount: number; engineMs: number };
}

const CATEGORY_MAX: Record<CategoryKey, number> = {
  links: 30,
  urgency: 20,
  lure: 20,
  identity: 15,
  obfuscation: 15,
};

const CATEGORY_META: Record<CategoryKey, { label: string; description: string }> = {
  links: {
    label: "Links & URLs",
    description: "Infrastructure signals: spoofed domains, IPs, shorteners, unsafe schemes",
  },
  urgency: {
    label: "Urgency & Pressure",
    description: "Manufactured time pressure and threat language",
  },
  lure: {
    label: "Financial & Credential Lures",
    description: "Money hooks and credential-harvesting requests",
  },
  identity: {
    label: "Sender & Identity",
    description: "Sender spoofing, generic greetings, freemail abuse",
  },
  obfuscation: {
    label: "Obfuscation & Payloads",
    description: "Hidden text, suspicious attachments, encoding tricks",
  },
};

const SEVERITY_POINTS: Record<Severity, number> = {
  critical: 12,
  high: 8,
  medium: 5,
  low: 3,
  info: 0,
};

const SUSPICIOUS_TLDS = new Set([
  "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "cn", "ru",
  "su", "click", "link", "work", "bar", "rest", "cam", "quest", "cfd",
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
  "shorturl.at", "tiny.cc", "rebrand.ly", "ow.ly", "buff.ly", "bit.do",
]);

const BRAND_DOMAINS: Record<string, string> = {
  paypal: "paypal.com", apple: "apple.com", icloud: "icloud.com",
  microsoft: "microsoft.com", office365: "microsoft.com", outlook: "outlook.com",
  amazon: "amazon.com", netflix: "netflix.com", google: "google.com",
  gmail: "gmail.com", facebook: "facebook.com", instagram: "instagram.com",
  whatsapp: "whatsapp.com", dhl: "dhl.com", fedex: "fedex.com",
  ups: "ups.com", usps: "usps.com", chase: "chase.com",
  wellsfargo: "wellsfargo.com", citibank: "citi.com", hsbc: "hsbc.com",
  sbi: "sbi.co.in", hdfc: "hdfcbank.com", icici: "icicibank.com",
};

const URGENCY_PATTERNS: { re: RegExp; title: string; detail: string; severity: Severity }[] = [
  { re: /\burgent(?:ly)?\b/gi, title: "Urgency language", detail: "Uses 'urgent' — a classic pressure tactic.", severity: "medium" },
  { re: /\b(?:act now|act fast|immediately|right away)\b/gi, title: "Immediate-action demand", detail: "Demands action without delay.", severity: "high" },
  { re: /\b(?:within|in)\s+(?:the\s+)?(?:next\s+)?(?:24|48|12|6|2)\s*(?:hours|hrs|h)\b/gi, title: "Artificial deadline", detail: "Threatens consequences within a tight deadline.", severity: "high" },
  { re: /\bwithin\s+(?:the\s+)?(?:next\s+)?(?:an?\s+)?(?:hours?|minutes?|mins?)\b/gi, title: "Artificial deadline", detail: "Threatens consequences within a tight deadline.", severity: "high" },
  { re: /\b(?:discreet(?:ly)?|don'?t\s+discuss|keep\s+this\s+between\s+us|confidential\s+task|off\s+the\s+record)\b/gi, title: "Secrecy request", detail: "Asks the reader to keep the request secret — hallmark of CEO-fraud / BEC scams.", severity: "high" },
  { re: /\baccount\s+(?:will\s+be|has\s+been|is)\s+(?:suspended|locked|blocked|disabled|closed|deactivated)\b/gi, title: "Account-suspension threat", detail: "Threatens account loss to force a click.", severity: "critical" },
  { re: /\b(?:verify|confirm|validate|restore|reactivate|secure)\s+your\s+(?:account|identity|details|information|billing|payment)\b/gi, title: "Verification request", detail: "Asks user to verify/confirm account data — hallmark of credential phishing.", severity: "critical" },
  { re: /\b(?:unusual|suspicious)\s+(?:activity|login|sign[\s-]?in|transaction|attempt)\b/gi, title: "Fake security alert", detail: "Claims suspicious activity to panic the reader.", severity: "critical" },
  { re: /\b(?:final|last)\s+(?:notice|warning|reminder)\b/gi, title: "Final-notice framing", detail: "Escalation framing typical of scam campaigns.", severity: "medium" },
  { re: /\bsecurity\s+(?:alert|warning|breach)\b/gi, title: "Security-alert framing", detail: "Poses as a security notification.", severity: "high" },
  { re: /\b(?:expires?|expire[d]?)\s+(?:today|tomorrow|in\s+\d)/gi, title: "Expiry pressure", detail: "Claims an offer/access expires almost immediately.", severity: "medium" },
];

const LURE_PATTERNS: { re: RegExp; title: string; detail: string; severity: Severity }[] = [
  { re: /(?:\$|₹|€|£)\s?\d[\d,.]*\s?(?:usd|inr|eur|gbp)?/g, title: "Monetary amount", detail: "Mentions a specific money amount — bait or fake transaction.", severity: "medium" },
  { re: /\bgift\s?cards?\b/gi, title: "Gift-card request", detail: "Gift cards are the #1 scam payment method.", severity: "critical" },
  { re: /\b(?:wire\s+transfer|bank\s+transfer|upi|neft|imps)\b/gi, title: "Transfer instruction", detail: "Requests an irreversible money transfer.", severity: "high" },
  { re: /\b(?:bitcoin|btc|usdt|ethereum|crypto\w*)\b/gi, title: "Crypto mention", detail: "Cryptocurrency requests are commonly irreversible scams.", severity: "high" },
  { re: /\b(?:you(?:'ve| have)?\s+won|winner|lottery|prize|inheritance|refund of)\b/gi, title: "Prize/refund bait", detail: "Unearned reward offers are classic scams.", severity: "high" },
  { re: /\b(?:otp|one[\s-]?time\s+(?:password|code)|verification\s+code|security\s+code)\b/gi, title: "OTP/code request", detail: "References OTP codes — legitimate services never ask for them.", severity: "critical" },
  { re: /\b(?:passwords?|credentials?|login\s+(?:details|info)|cvv|card\s+(?:numbers?|details)|net\s?banking|social\s+security\s+numbers?|ssn)\b/gi, title: "Credential request", detail: "References sensitive credentials or card data.", severity: "critical" },
  { re: /\bkyc\b|\bupdate\s+your\s+(?:payment|billing|card)\b/gi, title: "KYC/payment-update hook", detail: "Pushes payment-detail 'updates' — common bank-phishing lure.", severity: "high" },
  { re: /\b(?:delivery\s+fee|customs\s+fee|shipping\s+fee|small\s+fee|release\s+fee|pay\s+now|payment\s+pending)\b/gi, title: "Micro-payment gate", detail: "Tiny 'release/delivery fee' before you get something you expected — classic smishing pattern.", severity: "high" },
];

const IDENTITY_PATTERNS: { re: RegExp; title: string; detail: string; severity: Severity }[] = [
  { re: /\bdear\s+(?:customer|user|account\s?holder|valued\s+customer|sir[\s/]+madam)\b/gi, title: "Generic greeting", detail: "No personalization — mass phishing campaigns use generic salutations.", severity: "medium" },
  { re: /\bvalued\s+customer\b/gi, title: "'Valued customer' phrasing", detail: "Impersonal flattery typical of template phishing.", severity: "low" },
];

const BYPASS_PATTERNS: { re: RegExp; title: string; detail: string; severity: Severity }[] = [
  // NOTE: no /g flag — module-level regexes with /g keep `lastIndex` state
  // between requests in a long-lived server, causing missed detections.
  { re: /\bdo\s+not\s+(?:reply|respond|forward|share|call)\b/i, title: "Bypass-pressure instruction", detail: "Discourages replying/verifying through normal channels.", severity: "medium" },
  { re: /\b(?:only\s+)?via\s+the\s+link\s+(?:below|above|provided)\b/i, title: "Link-only verification", detail: "Forces verification through the provided link only.", severity: "high" },
];

const PAYLOAD_EXT = /\b[\w.-]+\.(zip|rar|7z|exe|scr|js|vbs|bat|iso|img|apk|docm|xlsm|hta|lnk)\b/gi;
const BASE64_LIKE = /[A-Za-z0-9+/]{100,}={0,2}/;
const ZERO_WIDTH = /[\u200B-\u200D\uFEFF]/;
const HTML_DANGER = /<\s*(script|iframe)|onerror\s*=|javascript\s*:/i;
// Only digit/glyph-SUBSTITUTED brand spellings count (e.g. 'paypa1') —
// correctly-spelled brand names (e.g. 'Google Play') must NOT trigger this.
const LOOKALIKE_TEXT = /\b(?:paypa1|paypaI|amaz0n|micr0s0ft|g00gle|faceb00k|app1e|netf1ix|instaqram|1nstagram|gmai1|icIoud)\b/i;
const EXEC_ROLE = /\b(ceo|cfo|cto|coo|director|founder|president|chairman|managing\s+director|partner|executive)\b/i;
const CORPORATE_ROLE = /(?:support|security|billing|admin|no-?reply|service|help|team|payments?|invoice|finance|hr|ceo|cfo|office|recovery|alerts?|verify|account)@/i;

const FREEMAIL = new Set(["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "proton.me", "icloud.com", "mail.com", "yandex.com"]);

const SAFE_RECOMMENDATION = "No strong phishing indicators found. Still verify any unexpected request through a channel you trust.";
const ALWAYS_RECOMMENDATION = "Never share OTPs or passwords — no legitimate service will ever ask for them.";

function extractUrls(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s<>"')\]]+/gi) ?? [];
  const bare = text.match(/\bwww\.[a-z0-9-]+\.[a-z]{2,}[^\s<>"')\]]*/gi) ?? [];
  return Array.from(new Set([...matches, ...bare].map((u) => u.replace(/[.,;:!]+$/, "")))).slice(0, 12);
}

function getHost(url: string): string {
  try {
    const u = new URL(url.startsWith("http") ? url : `http://${url}`);
    return u.hostname.toLowerCase();
  } catch {
    return url.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
  }
}

function registrableDomain(host: string): string {
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const twoLevelTlds = ["co.uk", "com.au", "co.in", "co.jp", "com.br", "co.za", "org.uk", "gov.uk", "ac.uk"];
  const last2 = parts.slice(-2).join(".");
  const last3 = parts.slice(-3).join(".");
  return twoLevelTlds.includes(last2) ? last3 : last2;
}

function analyzeUrl(url: string): { flags: string[]; points: number } {
  const host = getHost(url);
  const flags: string[] = [];
  let points = 0;
  const add = (flag: string, p: number) => { flags.push(flag); points += p; };

  const ipv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
  if (ipv4.test(host)) add("IP-literal host", 8);
  if (url.startsWith("http://") || url.startsWith("www.")) add("Unencrypted (no TLS)", 3);

  const tld = host.split(".").pop() ?? "";
  if (SUSPICIOUS_TLDS.has(tld)) add(`High-abuse TLD ".${tld}"`, 6);
  if (URL_SHORTENERS.has(host)) add("URL shortener hides destination", 6);
  if (host.includes("xn--")) add("Punycode (possible homoglyph) domain", 8);

  const regDomain = registrableDomain(host);
  for (const [brand, official] of Object.entries(BRAND_DOMAINS)) {
    const brandRe = new RegExp(`(?:^|[-.])${brand}(?:[-.]|$)`, "i");
    if (brandRe.test(host) && regDomain !== official && !regDomain.endsWith(`.${official}`)) {
      add(`Brand "${brand}" on non-official domain (${regDomain})`, 10);
      break;
    }
  }

  if (host.split(".").length >= 4) add("Excessive subdomain depth", 4);
  if (url.includes("@")) add("'@' userinfo trick in URL", 6);
  if (/[?&](?:url|redirect|next|goto|target)=/i.test(url)) add("Open-redirect parameter", 5);
  if (url.length > 100) add("Unusually long URL", 3);

  return { flags, points: Math.min(points, 18) };
}

function countMatches(text: string, re: RegExp): number {
  const m = text.match(re);
  return m ? m.length : 0;
}

export function runEngine(rawInput: string): EngineResult {
  const t0 = performance.now();
  // Defense in depth: strip control characters except newline/tab.
  const text = rawInput.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "");
  const lower = text.toLowerCase();
  const findings: Finding[] = [];
  const push = (f: Omit<Finding, "id">) => {
    if (findings.some((x) => x.title === f.title)) return;
    findings.push({ id: `f${findings.length + 1}`, ...f });
  };

  // ---- Channel detection -------------------------------------------------
  const hasHeaders = /\b(from|subject|delivered-to|return-path)\s*:/i.test(text);
  const channel: Channel = hasHeaders ? "email" : text.length <= 320 && /\b(?:sms|http|txt|msg|otp|rs\.|\$)\b/i.test(lower) ? "sms" : "text";

  // ---- 1. Links ----------------------------------------------------------
  const urls = extractUrls(text);
  let linkPoints = 0;
  const urlInfos: UrlInfo[] = urls.map((u) => {
    const { flags, points } = analyzeUrl(u);
    linkPoints += points;
    if (flags.length > 0) {
      push({ category: "links", title: `Risky link: ${getHost(u)}`, detail: flags.join("; "), severity: points >= 10 ? "critical" : points >= 6 ? "high" : "medium", points: Math.min(points, 12) });
    }
    return { url: u, host: getHost(u), flags };
  });
  if (urls.length >= 3) {
    push({ category: "links", title: "Link flooding", detail: `${urls.length} URLs in one message overwhelms scrutiny.`, severity: "medium", points: 5 });
    linkPoints += 5;
  }
  const linkScore = Math.min(linkPoints, CATEGORY_MAX.links);

  // ---- 2. Urgency & pressure ----------------------------------------------
  for (const p of URGENCY_PATTERNS) {
    const n = countMatches(text, p.re);
    if (n > 0) push({ category: "urgency", title: p.title, detail: `${p.detail}${n > 1 ? ` (${n} occurrences)` : ""}`, severity: p.severity, points: SEVERITY_POINTS[p.severity] });
  }
  for (const p of BYPASS_PATTERNS) {
    if (p.re.test(text)) push({ category: "urgency", title: p.title, detail: p.detail, severity: p.severity, points: SEVERITY_POINTS[p.severity] });
  }
  const urgencyScore = Math.min(findings.filter((f) => f.category === "urgency").reduce((s, f) => s + f.points, 0), CATEGORY_MAX.urgency);

  // ---- 3. Financial & credential lures ------------------------------------
  for (const p of LURE_PATTERNS) {
    const n = countMatches(text, p.re);
    if (n > 0) push({ category: "lure", title: p.title, detail: `${p.detail}${n > 1 ? ` (${n} occurrences)` : ""}`, severity: p.severity, points: SEVERITY_POINTS[p.severity] });
  }
  const lureScore = Math.min(findings.filter((f) => f.category === "lure").reduce((s, f) => s + f.points, 0), CATEGORY_MAX.lure);

  // ---- 4. Sender & identity ------------------------------------------------
  let identityScore = 0;
  const fromMatch = text.match(/\bfrom\s*:\s*("?)([^"<\n]+)\1\s*<\s*([\w.+-]+@[\w.-]+)\s*>/i)
    ?? text.match(/\bfrom\s*:\s*([\w.+-]+@[\w.-]+)/i);
  const fromEmail = fromMatch?.[3] ?? fromMatch?.[1];
  if (fromEmail) {
    const fromHost = fromEmail.split("@")[1].toLowerCase();
    const fromReg = registrableDomain(fromHost);
    const displayName = (fromMatch?.[2] ?? "").toLowerCase();
    const claimedBrand = Object.keys(BRAND_DOMAINS).find((b) => displayName.includes(b));
    if (claimedBrand && fromReg !== BRAND_DOMAINS[claimedBrand] && !fromReg.endsWith(`.${BRAND_DOMAINS[claimedBrand]}`)) {
      push({ category: "identity", title: "Display-name spoofing", detail: `Claims to be "${claimedBrand}" but sends from ${fromReg}.`, severity: "critical", points: 12 });
      identityScore += 12;
    }
    if (FREEMAIL.has(fromHost) && EXEC_ROLE.test((fromMatch?.[2] ?? ""))) {
      push({ category: "identity", title: "Executive impersonation via freemail", detail: `Claims to be an executive but sends from ${fromHost} — the core CEO-fraud (BEC) pattern.`, severity: "critical", points: 12 });
      identityScore += 12;
    } else if (FREEMAIL.has(fromHost) && CORPORATE_ROLE.test(fromEmail)) {
      push({ category: "identity", title: "Freemail used for corporate role", detail: `${fromHost} address posing as an official role — banks and brands never do this.`, severity: "high", points: 8 });
      identityScore += 8;
    }
  }
  const replyTo = text.match(/\breply-to\s*:\s*([\w.+-]+@[\w.-]+)/i)?.[1];
  if (replyTo && fromEmail && registrableDomain(replyTo.split("@")[1]) !== registrableDomain(fromEmail.split("@")[1])) {
    push({ category: "identity", title: "Reply-To mismatch", detail: `Replies would go to ${registrableDomain(replyTo.split("@")[1])}, not the sender's domain.`, severity: "high", points: 8 });
    identityScore += 8;
  }
  for (const p of IDENTITY_PATTERNS) {
    if (p.re.test(text)) { push({ category: "identity", title: p.title, detail: p.detail, severity: p.severity, points: SEVERITY_POINTS[p.severity] }); identityScore += SEVERITY_POINTS[p.severity]; }
  }
  const identityScoreCapped = Math.min(identityScore, CATEGORY_MAX.identity);

  // ---- 5. Obfuscation & payloads -------------------------------------------
  let obfScore = 0;
  const att = text.match(PAYLOAD_EXT);
  if (att) {
    push({ category: "obfuscation", title: "Suspicious attachment", detail: `Attachment type "${att[0]}" is a common malware vector.`, severity: "critical", points: 12 });
    obfScore += 12;
  }
  if (BASE64_LIKE.test(text)) { push({ category: "obfuscation", title: "Base64-like blob", detail: "Long encoded payload used to hide content from filters.", severity: "high", points: 8 }); obfScore += 8; }
  if (ZERO_WIDTH.test(text)) { push({ category: "obfuscation", title: "Zero-width characters", detail: "Invisible characters used to defeat keyword filters.", severity: "high", points: 8 }); obfScore += 8; }
  if (HTML_DANGER.test(text)) { push({ category: "obfuscation", title: "Dangerous HTML construct", detail: "Embedded script/iframe or JS-URL — treated as untrusted.", severity: "critical", points: 10 }); obfScore += 10; }
  if (LOOKALIKE_TEXT.test(lower)) { push({ category: "obfuscation", title: "Lookalike brand spelling", detail: "Digit-substituted brand name (e.g. 'paypa1') to evade filters.", severity: "high", points: 8 }); obfScore += 8; }

  const letters = text.replace(/[^a-zA-Z]/g, "");
  const upperRatio = letters.length > 40 ? letters.replace(/[^A-Z]/g, "").length / letters.length : 0;
  if (upperRatio > 0.5) { push({ category: "obfuscation", title: "Shouting (ALL CAPS)", detail: `${Math.round(upperRatio * 100)}% of letters are uppercase — agitation tactic.`, severity: "low", points: 3 }); obfScore += 3; }
  const bangs = countMatches(text, /!/g);
  if (bangs >= 3) { push({ category: "obfuscation", title: "Excessive exclamation", detail: `${bangs} '!' marks — emotional manipulation signal.`, severity: "low", points: 2 }); obfScore += 2; }
  const obfScoreCapped = Math.min(obfScore, CATEGORY_MAX.obfuscation);

  // ---- Aggregate -----------------------------------------------------------
  const categories: CategoryScore[] = [
    { key: "links", score: linkScore, ...CATEGORY_META.links, max: CATEGORY_MAX.links },
    { key: "urgency", score: urgencyScore, ...CATEGORY_META.urgency, max: CATEGORY_MAX.urgency },
    { key: "lure", score: lureScore, ...CATEGORY_META.lure, max: CATEGORY_MAX.lure },
    { key: "identity", score: identityScoreCapped, ...CATEGORY_META.identity, max: CATEGORY_MAX.identity },
    { key: "obfuscation", score: obfScoreCapped, ...CATEGORY_META.obfuscation, max: CATEGORY_MAX.obfuscation },
  ];
  const rawRisk = Math.min(100, categories.reduce((s, c) => s + c.score, 0));
  let verdict: Verdict = rawRisk >= 75 ? "critical" : rawRisk >= 50 ? "high" : rawRisk >= 25 ? "suspicious" : "safe";

  // ---- Hard-signal verdict floor -------------------------------------------
  // Structural high-risk URL signals are never "safe" regardless of wording:
  // an IP-literal host, punycode domain, brand-impersonated host, '@' userinfo
  // trick or open-redirect parameter clamps the verdict to at least suspicious.
  const HARD_URL_FLAGS = [
    "IP-literal host",
    "Punycode (possible homoglyph) domain",
    "'@' userinfo trick in URL",
    "Open-redirect parameter",
  ];
  const hasHardUrlSignal = urlInfos.some((u) =>
    u.flags.some((f) => HARD_URL_FLAGS.includes(f) || f.startsWith('Brand "'))
  );
  const riskScore = verdict === "safe" && hasHardUrlSignal ? Math.max(rawRisk, 25) : rawRisk;
  if (riskScore !== rawRisk) verdict = "suspicious";

  const verdictLabel = { safe: "Likely Safe", suspicious: "Suspicious", high: "High Risk — Likely Phishing", critical: "Critical — Confident Phishing" }[verdict];

  // ---- Recommendations (whitelist — never AI-generated) ---------------------
  const rec: string[] = [];
  const has = (k: CategoryKey) => categories.find((c) => c.key === k)!.score > 0;
  if (has("lure")) rec.push("Never enter credentials or card details from a link in this message — navigate to the official site manually.");
  if (has("links")) rec.push("Do not click any links. Hover (or long-press) to reveal the true destination first.");
  if (text.match(PAYLOAD_EXT)) rec.push("Do not open the attachment; scan it with updated antivirus and report it.");
  if (has("urgency")) rec.push("Slow down — manufactured urgency is the #1 phishing tactic. Verify through an official channel.");
  if (has("identity")) rec.push("Contact the organisation via its official website or app, never by replying to this message.");
  if (verdict === "high" || verdict === "critical") rec.push("Report to your IT / security team (or the platform's report-abuse flow) and then delete.");
  if (rec.length === 0) rec.push(SAFE_RECOMMENDATION);
  rec.push(ALWAYS_RECOMMENDATION);

  const engineMs = Math.max(1, Math.round(performance.now() - t0));
  const words = text.split(/\s+/).filter(Boolean).length;

  return {
    channel,
    riskScore,
    verdict,
    verdictLabel,
    categories,
    findings,
    urls: urlInfos,
    indicators: [
      { label: "Channel", value: channel.toUpperCase() },
      { label: "Words", value: String(words) },
      { label: "Links found", value: String(urls.length) },
      { label: "Flags raised", value: String(findings.length) },
    ],
    recommendations: rec,
    meta: { chars: text.length, words, urlCount: urls.length, engineMs },
  };
}
