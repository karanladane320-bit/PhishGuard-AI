<div align="center">

# 🛡️ PhishGuard AI

**Phishing detection workbench — deterministic security engine first, grounded AI reasoning second, honest verification always.**

*Built for the hackathon theme: "Build Beyond AI — Secure, Intelligent, Autonomous Applications."*

</div>

---

## The problem

Phishing and smishing are the #1 entry vector for breaches — and generic "paste it into a chatbot" answers hallucinate, or worse, get manipulated by the very message they're analyzing. PhishGuard AI answers *"is this message safe?"* in seconds with receipts: a deterministic, explainable engine makes the call, AI adds reasoning, and a verification layer keeps both honest.

## The workflow

```
User Input → Validation → Data Analysis → AI Reasoning → Recommendation → Verification → Results
```

| Stage | What happens | Speed |
|---|---|---|
| **Validation** | Zod schema (10–10k chars), control-char stripping, per-IP rate limit (12 req/min) | ~0 ms |
| **Data analysis** | Deterministic engine: URL forensics, urgency/lure/identity/obfuscation rules (~30 patterns), scored 0–100 across 5 categories | **1–5 ms** |
| **AI reasoning** | Exactly **one** LLM call, grounded on engine JSON, injection-hardened, 20 s timeout, JSON-schema validated | ~1.2–1.7 s |
| **Recommendation** | AI actions filtered through a **fixed allow-list** — arbitrary AI output can never render | — |
| **Verification** | Engine ↔ AI verdict cross-check, confidence bounds, output sanitization; disagreements shown honestly | — |
| **Results** | Risk dashboard with **measured** timings; identical input → cache hit, **0 extra AI calls** | ~5 ms |

## Features

- 🚦 **Traffic-light verdicts** — 0–24 likely safe · 25–49 suspicious · 50–100 dangerous, each with a plain-language "what this means" line
- 🔗 **URL forensics** — IP-literal hosts, punycode homoglyphs, brand-in-host impersonation, open redirects, shorteners, high-abuse TLDs, `@` userinfo tricks
- 🎯 **Hard-signal floor** — structural signals (IP host, punycode, brand impersonation) can never yield a "safe" verdict regardless of wording
- 🧪 **4 one-click sample scenarios** — bank phishing, smishing, BEC gift-card scam, and a legitimate email
- 🛡️ **Prompt-injection hardened** — attack attempts are detected and ignored (verified live: "ignore all instructions" messages still scored as phishing)
- 📊 **Live stats strip** — measured engine time, AI coverage, cache-hit rate (clearly labeled estimates vs. measurements)
- 🕐 **History** — reopen past verdicts; full messages are never stored

## Tech stack

- **Next.js 16** (App Router) + **TypeScript 5**
- **Tailwind CSS 4** + shadcn/ui (New York) + Lucide icons
- **Prisma ORM + SQLite** (local, zero-config)
- **Server-side AI SDK** (never exposed to the client) — swappable with the Gemini API by adding one server-side key
- **Zod** validation, in-memory sliding-window rate limiting, SHA-256 content dedup cache (24 h)

## Security by design

- Secrets live **only** server-side; the client never sees keys or raw AI output
- AI output is schema-validated, sanitized, and restricted to a fixed action catalog
- **Privacy:** full message never persisted — only SHA-256 hash + 160-char preview; no accounts, no PII
- All user input treated as untrusted: validated, sanitized, rendered as plain text (never HTML)
- Graceful failure everywhere: AI timeout → honest fallback to engine-only results, clearly labeled

## Getting started

```bash
# 1. Install dependencies (bun recommended; npm/pnpm work too)
bun install

# 2. Create the database from the Prisma schema
bun run db:push

# 3. Start the dev server
bun run dev        # → http://localhost:3000
```

No API keys are required to run the app — the deterministic engine works fully offline, and the AI layer degrades honestly if unreachable.

## Tests performed

| Test | Result |
|---|---|
| 4 sample scenarios end-to-end | ✅ high/73 · suspicious/29 · suspicious/49 · safe/0 |
| Prompt-injection attack payload | ✅ resisted — AI still returned "phishing", engine flagged findings |
| Empty / short / 60k-char / malformed JSON input | ✅ clean 400s with actionable messages |
| Browser golden path (sample → analyze → dashboard) | ✅ zero console errors |
| Mobile 390 px layout + sticky footer | ✅ stacks correctly, footer flush |
| Cache hit on identical input | ✅ ~5 ms, 0 AI calls |

## Known limitations

- Heuristic URL analysis only — no live DNS / reputation lookups
- Pattern rules are English-centric
- AI reasoning requires network access; falls back to engine-only verdicts (clearly labeled)
- Google Gemini / Firebase integration is prepared but not required: swap the server-side AI SDK call for Gemini with a single server-side key

## Honest disclaimer

Decision support, not a guarantee. Always verify sensitive requests through official channels.

---

<div align="center">
<i>Built in a hackathon sprint — Next.js 16 · TypeScript · Prisma/SQLite · grounded AI layer</i>
</div>
