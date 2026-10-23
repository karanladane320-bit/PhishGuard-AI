"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Toaster } from "@/components/ui/sonner";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import {
  ShieldCheck, ShieldAlert, Link2, BrainCircuit, Timer, Zap, Database, Lock,
  CheckCircle2, XCircle, AlertTriangle, RotateCcw, ScanText, History,
  FileInput, Filter, Cpu, Lightbulb, BadgeCheck, Gauge, ArrowRight, Loader2,
} from "lucide-react";
import { SAMPLES } from "@/lib/samples";
import type {
  AnalysisResponse, CategoryScore, Finding, HistoryItem, StatsPayload, Verdict,
} from "@/lib/types";

const MAX_CHARS = 10_000;

const VERDICT_THEME: Record<Verdict, { text: string; chip: string; bar: string; hex: string; ring: string }> = {
  safe:      { text: "text-emerald-400", chip: "bg-emerald-500/10 text-emerald-300 border-emerald-500/30", bar: "bg-emerald-500", hex: "#34d399", ring: "ring-emerald-500/30" },
  suspicious:{ text: "text-amber-400",   chip: "bg-amber-500/10 text-amber-300 border-amber-500/30",     bar: "bg-amber-500",   hex: "#fbbf24", ring: "ring-amber-500/30" },
  high:      { text: "text-orange-400",  chip: "bg-orange-500/10 text-orange-300 border-orange-500/30",  bar: "bg-orange-500",  hex: "#fb923c", ring: "ring-orange-500/30" },
  critical:  { text: "text-rose-400",    chip: "bg-rose-500/10 text-rose-300 border-rose-500/30",        bar: "bg-rose-500",    hex: "#fb7185", ring: "ring-rose-500/30" },
};

const SEVERITY_CHIP: Record<Finding["severity"], string> = {
  critical: "bg-rose-500/15 text-rose-300 border-rose-500/40",
  high: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/15 text-amber-300 border-amber-500/40",
  low: "bg-zinc-500/15 text-zinc-300 border-zinc-500/40",
  info: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const AI_VERDICT_LABEL: Record<string, string> = {
  phishing: "Phishing", suspicious: "Suspicious", legitimate: "Legitimate",
};

/* Plain-language "what this means for you" — one sentence per verdict. */
const VERDICT_PLAIN: Record<Verdict, string> = {
  safe: "No warning signs found. Stay alert anyway — unexpected requests always deserve a second look.",
  suspicious: "We found some warning signs. Don't click any links — check with the sender using their official app or website.",
  high: "This message shows classic phishing signs. Don't click, don't reply — report it to your IT or security team.",
  critical: "Almost certainly a scam. Don't click anything. Report it, then delete it after reporting.",
};

// ---------------------------------------------------------------------------
// Small presentational helpers
// ---------------------------------------------------------------------------
function ScoreRing({ score, hex }: { score: number; hex: string }) {
  const R = 52;
  const C = 2 * Math.PI * R;
  const pct = Math.min(100, Math.max(0, score));
  return (
    <svg viewBox="0 0 120 120" className="h-28 w-28 shrink-0 -rotate-90" role="img" aria-label={`Risk score ${pct} out of 100`}>
      <circle cx="60" cy="60" r={R} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="10" />
      <circle
        cx="60" cy="60" r={R} fill="none" stroke={hex} strokeWidth="10" strokeLinecap="round"
        strokeDasharray={C} strokeDashoffset={C - (pct / 100) * C}
        style={{ transition: "stroke-dashoffset 900ms cubic-bezier(0.22,1,0.36,1)" }}
      />
      <text x="60" y="66" textAnchor="middle" transform="rotate(90 60 60)" style={{ transformOrigin: "60px 60px" }} fill={hex} fontSize="28" fontWeight="700">
        {pct}
      </text>
    </svg>
  );
}

function CategoryBar({ cat, hex }: { cat: CategoryScore; hex: string }) {
  const pct = cat.max > 0 ? Math.round((cat.score / cat.max) * 100) : 0;
  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between gap-2">
        <span className="text-sm font-medium text-zinc-200">{cat.label}</span>
        <span className="font-mono text-xs text-zinc-400">{cat.score}/{cat.max}</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label={cat.label}>
        <div className="h-full rounded-full transition-[width] duration-700 ease-out" style={{ width: `${pct}%`, backgroundColor: hex }} />
      </div>
      <p className="mt-1 text-xs leading-relaxed text-zinc-500">{cat.description}</p>
    </div>
  );
}

function FindingRow({ f }: { f: Finding }) {
  return (
    <li className="flex items-start gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
      <Badge variant="outline" className={`mt-0.5 shrink-0 capitalize ${SEVERITY_CHIP[f.severity]}`}>{f.severity}</Badge>
      <div className="min-w-0">
        <p className="text-sm font-medium text-zinc-100">{f.title}</p>
        <p className="mt-0.5 text-xs leading-relaxed text-zinc-400">{f.detail}</p>
      </div>
    </li>
  );
}

function WorkflowStep({ icon: Icon, step, title, desc }: { icon: React.ComponentType<{ className?: string }>; step: number; title: string; desc: string }) {
  return (
    <div className="relative flex min-w-[220px] flex-1 flex-col gap-2 rounded-xl border border-white/[0.07] bg-white/[0.03] p-4">
      <div className="flex items-center gap-2">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-300"><Icon className="h-4 w-4" /></span>
        <span className="font-mono text-[10px] uppercase tracking-widest text-zinc-500">Step {step}</span>
      </div>
      <p className="text-sm font-semibold text-zinc-100">{title}</p>
      <p className="text-xs leading-relaxed text-zinc-500">{desc}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main application
// ---------------------------------------------------------------------------
export default function PhishGuardApp() {
  const [content, setContent] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [loadingId, setLoadingId] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [stats, setStats] = useState<StatsPayload | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);

  const refreshFeed = useCallback(async () => {
    try {
      const res = await fetch("/api/analyses", { cache: "no-store" });
      if (!res.ok) return;
      const data = (await res.json()) as { items: HistoryItem[]; stats: StatsPayload };
      setHistory(data.items);
      setStats(data.stats);
    } catch {
      // Non-critical panel — silent failure is acceptable here.
    }
  }, []);

  useEffect(() => {
    refreshFeed();
  }, [refreshFeed]);

  const scrollToResults = () => {
    window.setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
  };

  const analyze = async (override?: string) => {
    const payload = (override ?? content).trim();
    // Client-side mirror of the server contract for instant feedback.
    if (payload.length < 10) {
      setError("Please paste at least 10 characters of the message you want to analyze.");
      return;
    }
    if (payload.length > MAX_CHARS) {
      setError(`Message is too long (${payload.length.toLocaleString()} characters). Maximum is ${MAX_CHARS.toLocaleString()}.`);
      return;
    }
    setAnalyzing(true);
    setError(null);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: payload }),
      });
      const data = (await res.json()) as AnalysisResponse & { error?: string };
      if (!res.ok) {
        setError(data.error ?? "Analysis failed. Please try again.");
        return;
      }
      setResult(data);
      refreshFeed();
      toast.success(data.cached ? "Served from cache — no extra AI call needed" : "Analysis complete", {
        description: `Risk score ${data.riskScore}/100 · engine ${data.timings.engineMs}ms`,
      });
      scrollToResults();
    } catch {
      setError("Network error — could not reach the analysis service. Please try again.");
    } finally {
      setAnalyzing(false);
    }
  };

  const loadSample = (id: string) => {
    const sample = SAMPLES.find((s) => s.id === id);
    if (!sample) return;
    setContent(sample.content);
    setError(null);
    toast.success(`Loaded sample: ${sample.label}`, { description: `${sample.scenario} · expected: ${sample.expected}` });
  };

  const reset = () => {
    setContent("");
    setResult(null);
    setError(null);
  };

  const openHistoryItem = async (id: string) => {
    setLoadingId(id);
    setError(null);
    try {
      const res = await fetch(`/api/analyses/${id}`, { cache: "no-store" });
      const data = (await res.json()) as AnalysisResponse & { error?: string };
      if (!res.ok) {
        setError(data.error ?? "Could not load this analysis.");
        return;
      }
      setResult(data);
      setContent("");
      toast.info("Loaded from history", { description: "Full message content is never stored — verdict summary only." });
      scrollToResults();
    } catch {
      setError("Network error — could not load this analysis.");
    } finally {
      setLoadingId(null);
    }
  };

  const theme = result ? VERDICT_THEME[result.verdict] : null;
  const charsNearLimit = content.length > MAX_CHARS - 1000;

  return (
    <div className="flex min-h-screen flex-col bg-zinc-950 text-zinc-100 [background-image:radial-gradient(70rem_40rem_at_50%_-10%,rgba(16,185,129,0.10),transparent),radial-gradient(50rem_30rem_at_90%_20%,rgba(245,158,11,0.05),transparent)]">
      <Toaster richColors position="bottom-right" theme="dark" closeButton />

      {/* ------------------------------- NAV ------------------------------- */}
      <header className="sticky top-0 z-40 border-b border-white/[0.06] bg-zinc-950/80 backdrop-blur-md">
        <div className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between px-4 sm:px-6">
          <a href="#top" className="flex items-center gap-2 font-semibold tracking-tight">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30">
              <ShieldCheck className="h-4.5 w-4.5" />
            </span>
            PhishGuard <span className="text-emerald-400">AI</span>
          </a>
          <nav aria-label="Main navigation" className="hidden items-center gap-1 text-sm text-zinc-400 md:flex">
            <a href="#analyzer" className="rounded-md px-3 py-2 transition-colors hover:bg-white/5 hover:text-zinc-100">Analyzer</a>
            <a href="#workflow" className="rounded-md px-3 py-2 transition-colors hover:bg-white/5 hover:text-zinc-100">How it works</a>
            <a href="#history" className="rounded-md px-3 py-2 transition-colors hover:bg-white/5 hover:text-zinc-100">History</a>
            <a href="#security" className="rounded-md px-3 py-2 transition-colors hover:bg-white/5 hover:text-zinc-100">Security</a>
          </nav>
          <Button size="sm" onClick={() => document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" })} className="bg-emerald-500 text-emerald-950 hover:bg-emerald-400">
            <Zap className="h-3.5 w-3.5" /> Analyze now
          </Button>
        </div>
      </header>

      <main id="top" className="mx-auto w-full max-w-6xl flex-1 px-4 sm:px-6">

        {/* ------------------------------ HERO ------------------------------ */}
        <section className="flex flex-col items-center gap-5 py-14 text-center sm:py-20">
          <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-300">
            Hackathon · Build Beyond AI — Secure, Intelligent, Autonomous
          </Badge>
          <h1 className="max-w-3xl text-4xl font-bold leading-tight tracking-tight sm:text-5xl lg:text-6xl">
            Detect phishing <span className="text-emerald-400">before it detects you.</span>
          </h1>
          <p className="max-w-2xl text-base leading-relaxed text-zinc-400 sm:text-lg">
            Paste any suspicious email or SMS. A deterministic security engine inspects links,
            lures and pressure tactics in milliseconds — then a grounded AI layer explains
            <em className="text-zinc-300"> why</em> it is dangerous and what to do next. Every AI claim is cross-checked.
          </p>

          {/* Traffic-light legend — teaches the score scale at a glance */}
          <div className="flex flex-wrap items-stretch justify-center gap-2" aria-label="Risk score color scale">
            {[
              { icon: ShieldCheck, range: "0–24", label: "Likely safe", cls: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" },
              { icon: ShieldAlert, range: "25–49", label: "Suspicious", cls: "border-amber-500/30 bg-amber-500/10 text-amber-300" },
              { icon: AlertTriangle, range: "50–100", label: "Dangerous — likely phishing", cls: "border-rose-500/30 bg-rose-500/10 text-rose-300" },
            ].map((s) => (
              <span key={s.label} className={`inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-xs font-medium ${s.cls}`}>
                <s.icon className="h-3.5 w-3.5" /> <span className="font-mono">{s.range}</span> · {s.label}
              </span>
            ))}
          </div>

          <div className="flex flex-wrap items-center justify-center gap-2 text-xs">
            {["Deterministic engine · measured < 5 ms", "1 grounded AI call per analysis", "Prompt-injection hardened", "Full message never stored"].map((t) => (
              <span key={t} className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-zinc-300">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /> {t}
              </span>
            ))}
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
            <Button size="lg" onClick={() => document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" })} className="h-11 bg-emerald-500 px-6 text-emerald-950 hover:bg-emerald-400">
              <ScanText className="h-4 w-4" /> Run an analysis
            </Button>
            <Button size="lg" variant="outline" onClick={() => { loadSample("phish-email"); document.getElementById("analyzer")?.scrollIntoView({ behavior: "smooth" }); }} className="h-11 border-white/15 bg-transparent px-6 text-zinc-200 hover:bg-white/5 hover:text-white">
              <FileInput className="h-4 w-4" /> Try a live sample
            </Button>
          </div>
        </section>

        {/* --------------------------- STATS STRIP --------------------------- */}
        {stats && stats.total > 0 && (
          <section aria-label="Live platform statistics" className="mb-10 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
            {[
              { label: "Total analyses", value: stats.total.toLocaleString(), sub: "this instance" },
              { label: "Avg risk score", value: `${stats.avgRisk}/100`, sub: "engine measured" },
              { label: "Avg engine time", value: `${stats.avgEngineMs} ms`, sub: "deterministic rules" },
              { label: "AI coverage", value: `${stats.aiUsageRate}%`, sub: "of analyses AI-grounded" },
              { label: "Cache hit rate", value: `${stats.cacheHitRate}%`, sub: `≈${Math.round(stats.cacheSavingsMs / 1000)}s AI time saved (est.)` },
            ].map((s) => (
              <div key={s.label} className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4">
                <p className="font-mono text-2xl font-bold text-emerald-300">{s.value}</p>
                <p className="mt-1 text-sm font-medium text-zinc-200">{s.label}</p>
                <p className="text-xs text-zinc-500">{s.sub}</p>
              </div>
            ))}
          </section>
        )}

        {/* ---------------------------- ANALYZER ----------------------------- */}
        <section id="analyzer" className="scroll-mt-20 pb-6">
          <div className="mb-4 flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-300"><ScanText className="h-4.5 w-4.5" /></span>
            <div>
              <h2 className="text-xl font-semibold tracking-tight">Threat analyzer</h2>
              <p className="text-sm text-zinc-500"><span className="text-zinc-300">1.</span> Paste the message &nbsp;→&nbsp; <span className="text-zinc-300">2.</span> Press Analyze &nbsp;→&nbsp; <span className="text-zinc-300">3.</span> Follow the checklist.</p>
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-5">
            {/* Input column */}
            <div className="flex flex-col gap-4 lg:col-span-2">
              <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4">
                <div className="mb-2 flex items-center justify-between">
                  <label htmlFor="message" className="text-sm font-medium text-zinc-200">Message to analyze</label>
                  <span className={`font-mono text-xs ${charsNearLimit ? "text-amber-400" : "text-zinc-500"}`}>
                    {content.length.toLocaleString()} / {MAX_CHARS.toLocaleString()}
                  </span>
                </div>
                <textarea
                  id="message"
                  value={content}
                  onChange={(e) => setContent(e.target.value.slice(0, MAX_CHARS + 1))}
                  placeholder={"From: security@your-bank.example\nSubject: Verify your account...\n\nPaste the suspicious message here — include headers if you have them."}
                  rows={12}
                  className="w-full resize-y rounded-lg border border-white/10 bg-zinc-900/60 p-3 font-mono text-xs leading-relaxed text-zinc-200 placeholder:text-zinc-600 focus:border-emerald-500/50 focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
                  maxLength={MAX_CHARS + 500}
                  aria-describedby="message-hint"
                />
                <p id="message-hint" className="mt-1.5 text-xs text-zinc-500">
                  Input is validated &amp; sanitized server-side. Headers like <code className="font-mono text-zinc-400">From:</code> and <code className="font-mono text-zinc-400">Reply-To:</code> improve sender analysis.
                </p>

                {error && (
                  <div role="alert" className="mt-3 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-200">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>{error}</span>
                  </div>
                )}

                <div className="mt-4 flex flex-wrap gap-2">
                  <Button onClick={() => analyze()} disabled={analyzing} className="h-10 flex-1 bg-emerald-500 text-emerald-950 hover:bg-emerald-400 disabled:opacity-60 sm:flex-none sm:px-6">
                    {analyzing ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                    {analyzing ? "Analyzing…" : "Analyze message"}
                  </Button>
                  <Button variant="outline" onClick={reset} disabled={analyzing} className="h-10 border-white/15 bg-transparent text-zinc-300 hover:bg-white/5 hover:text-white">
                    <RotateCcw className="h-4 w-4" /> Reset
                  </Button>
                </div>
              </div>

              <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4">
                <p className="mb-3 text-sm font-medium text-zinc-200">Sample scenarios <span className="font-normal text-zinc-500">— one click, end-to-end demo</span></p>
                <div className="grid gap-2">
                  {SAMPLES.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => loadSample(s.id)}
                      className="group flex items-center justify-between gap-3 rounded-lg border border-white/[0.07] bg-white/[0.02] p-3 text-left transition-colors hover:border-emerald-500/30 hover:bg-emerald-500/[0.06]"
                    >
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-zinc-200">{s.label}</p>
                        <p className="truncate text-xs text-zinc-500">{s.scenario}</p>
                      </div>
                      <Badge variant="outline" className="shrink-0 border-white/10 bg-white/[0.04] text-[10px] text-zinc-400">{s.expected}</Badge>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Results column */}
            <div ref={resultsRef} className="scroll-mt-20 lg:col-span-3" aria-live="polite">
              {analyzing && (
                <div className="flex h-full min-h-[420px] flex-col items-center justify-center gap-4 rounded-xl border border-emerald-500/20 bg-emerald-500/[0.03] p-8">
                  <div className="relative">
                    <Loader2 className="h-10 w-10 animate-spin text-emerald-400" />
                  </div>
                  <p className="text-sm font-medium text-zinc-200">Running the pipeline…</p>
                  <ol className="grid w-full max-w-sm gap-2 text-xs text-zinc-400">
                    {["Validating & sanitizing input", "Deterministic engine scan", "Grounded AI reasoning", "Cross-verification"].map((step, i) => (
                      <li key={step} className="flex items-center gap-2 rounded-md border border-white/[0.06] bg-white/[0.02] px-3 py-2">
                        <Loader2 className="h-3 w-3 animate-spin text-emerald-400/70" style={{ animationDelay: `${i * 200}ms` }} />
                        {step}
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {!analyzing && !result && (
                <div className="flex h-full min-h-[420px] flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-white/10 bg-white/[0.015] p-8 text-center">
                  <ShieldCheck className="h-12 w-12 text-zinc-700" />
                  <p className="text-sm font-medium text-zinc-400">No analysis yet</p>
                  <p className="max-w-xs text-xs leading-relaxed text-zinc-600">
                    Load a sample scenario or paste your own message, then press <span className="text-zinc-400">Analyze message</span>. Results appear here with a risk dashboard, findings, AI reasoning and verification.
                  </p>
                </div>
              )}

              {!analyzing && result && theme && (
                <div className="flex flex-col gap-4">
                  {/* Verdict banner */}
                  <div className={`rounded-xl border border-white/[0.07] bg-white/[0.03] p-5 ring-1 ${theme.ring}`}>
                    <div className="flex flex-wrap items-center gap-5">
                      <ScoreRing score={result.riskScore} hex={theme.hex} />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <Badge variant="outline" className={`capitalize ${theme.chip}`}>{result.verdict}</Badge>
                          <Badge variant="outline" className="border-white/10 bg-white/[0.04] text-[10px] uppercase tracking-wider text-zinc-400">{result.channel}</Badge>
                          {result.cached && (
                            <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-[10px] text-emerald-300">
                              <Database className="mr-1 h-3 w-3" /> cached · 0 AI calls
                            </Badge>
                          )}
                        </div>
                        <h3 className={`mt-2 text-lg font-bold sm:text-xl ${theme.text}`}>{result.verdictLabel}</h3>
                        <p className="mt-1 text-sm leading-relaxed text-zinc-400">
                          <span className="font-medium text-zinc-300">What this means:</span> {VERDICT_PLAIN[result.verdict]}
                        </p>
                        <p className="mt-1 text-xs text-zinc-500">
                          {result.findings.length} finding{result.findings.length === 1 ? "" : "s"} across {result.categories.filter((c) => c.score > 0).length} signal categories ·
                          engine {result.timings.engineMs} ms · AI {result.cached ? "skipped (dedup)" : `${result.timings.aiMs} ms`}
                        </p>
                      </div>
                    </div>
                    <Separator className="my-4 bg-white/[0.06]" />
                    <div className="flex flex-wrap gap-2">
                      {result.indicators.map((ind) => (
                        <span key={ind.label} className="rounded-md border border-white/[0.07] bg-white/[0.02] px-2.5 py-1 font-mono text-xs text-zinc-400">
                          {ind.label}: <span className="text-zinc-200">{ind.value}</span>
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* AI unavailable notice */}
                  {result.aiError && (
                    <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                      <span>{result.aiError}</span>
                    </div>
                  )}

                  {/* Category breakdown */}
                  <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-5">
                    <h4 className="mb-4 flex items-center gap-2 text-sm font-semibold text-zinc-200"><Gauge className="h-4 w-4 text-emerald-400" /> Risk breakdown by signal category</h4>
                    <div className="grid gap-4 sm:grid-cols-2">
                      {result.categories.map((c) => <CategoryBar key={c.key} cat={c} hex={theme.hex} />)}
                    </div>
                  </div>

                  {/* Findings */}
                  <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-5">
                    <h4 className="mb-4 flex items-center gap-2 text-sm font-semibold text-zinc-200"><Link2 className="h-4 w-4 text-emerald-400" /> Engine findings ({result.findings.length})</h4>
                    {result.findings.length === 0 ? (
                      <p className="flex items-center gap-2 text-sm text-emerald-300"><CheckCircle2 className="h-4 w-4" /> No suspicious patterns detected by the rules engine.</p>
                    ) : (
                      <ul className="max-h-96 space-y-2 overflow-y-auto pr-1 [scrollbar-color:rgba(255,255,255,0.2)_transparent] [scrollbar-width:thin]">
                        {result.findings.map((f) => <FindingRow key={f.id} f={f} />)}
                      </ul>
                    )}
                    {result.urls.length > 0 && (
                      <>
                        <Separator className="my-4 bg-white/[0.06]" />
                        <p className="mb-2 text-xs font-medium uppercase tracking-wider text-zinc-500">URLs inspected ({result.urls.length})</p>
                        <ul className="max-h-48 space-y-1.5 overflow-y-auto pr-1 font-mono text-xs [scrollbar-color:rgba(255,255,255,0.2)_transparent] [scrollbar-width:thin]">
                          {result.urls.map((u, i) => (
                            <li key={`${u.url}-${i}`} className="flex flex-wrap items-center gap-2 rounded-md border border-white/[0.06] bg-white/[0.02] px-2.5 py-2">
                              <span className="break-all text-zinc-300">{u.url.length > 80 ? `${u.url.slice(0, 80)}…` : u.url}</span>
                              {u.flags.length === 0
                                ? <span className="ml-auto shrink-0 text-emerald-400">no flags</span>
                                : u.flags.map((fl) => <span key={fl} className="shrink-0 rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-[10px] text-rose-300">{fl}</span>)}
                            </li>
                          ))}
                        </ul>
                      </>
                    )}
                  </div>

                  {/* AI assessment */}
                  {result.ai && (
                    <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-5">
                      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                        <h4 className="flex items-center gap-2 text-sm font-semibold text-zinc-200"><BrainCircuit className="h-4 w-4 text-emerald-400" /> AI assessment <span className="font-normal text-zinc-500">(grounded on engine evidence)</span></h4>
                        <Badge variant="outline" className={`border-white/10 capitalize ${theme.chip}`}>{AI_VERDICT_LABEL[result.ai.verdict] ?? result.ai.verdict}</Badge>
                      </div>
                      <div className="mb-3">
                        <div className="mb-1 flex justify-between text-xs text-zinc-400">
                          <span>AI confidence</span><span className="font-mono">{Math.round(result.ai.confidence * 100)}%</span>
                        </div>
                        <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
                          <div className="h-full rounded-full bg-emerald-500 transition-[width] duration-700" style={{ width: `${Math.round(result.ai.confidence * 100)}%` }} />
                        </div>
                      </div>
                      <p className="text-sm leading-relaxed text-zinc-300">{result.ai.reasoning}</p>
                      {result.ai.techniques.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1.5">
                          {result.ai.techniques.map((t) => (
                            <span key={t} className="rounded-full border border-white/10 bg-white/[0.04] px-2.5 py-1 text-xs text-zinc-300">{t}</span>
                          ))}
                        </div>
                      )}
                      {result.ai.actions.length > 0 && (
                        <>
                          <Separator className="my-4 bg-white/[0.06]" />
                          <p className="mb-2 text-xs font-medium uppercase tracking-wider text-zinc-500">Recommended actions (allow-listed)</p>
                          <ul className="space-y-1.5">
                            {result.ai.actions.map((a) => (
                              <li key={a.code} className="flex items-start gap-2 text-sm text-zinc-300">
                                <Lightbulb className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" /> {a.label}
                              </li>
                            ))}
                          </ul>
                        </>
                      )}
                    </div>
                  )}

                  {/* Deterministic recommendations */}
                  <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-5">
                    <h4 className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-200"><BadgeCheck className="h-4 w-4 text-emerald-400" /> Safety checklist <span className="font-normal text-zinc-500">(rule-derived, deterministic)</span></h4>
                    <ul className="space-y-1.5">
                      {result.recommendations.map((r) => (
                        <li key={r} className="flex items-start gap-2 text-sm text-zinc-300">
                          <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" /> {r}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Verification */}
                  <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-5">
                    <h4 className="mb-1 flex items-center gap-2 text-sm font-semibold text-zinc-200"><Filter className="h-4 w-4 text-emerald-400" /> Verification stage</h4>
                    <p className="mb-3 text-sm text-zinc-400">{result.verification.summary}</p>
                    <ul className="grid gap-2 sm:grid-cols-2">
                      {result.verification.checks.map((c) => (
                        <li key={c.name} className="flex items-start gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                          {c.pass
                            ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
                            : <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />}
                          <div className="min-w-0">
                            <p className="text-xs font-medium text-zinc-200">{c.name}</p>
                            <p className="mt-0.5 break-words text-xs text-zinc-500">{c.detail}</p>
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Performance */}
                  <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-5">
                    <h4 className="mb-3 flex items-center gap-2 text-sm font-semibold text-zinc-200"><Timer className="h-4 w-4 text-emerald-400" /> Measured performance <span className="font-normal text-zinc-500">(real timings, not estimates)</span></h4>
                    <div className="grid grid-cols-3 gap-3">
                      {[
                        { label: "Engine", value: `${result.timings.engineMs} ms`, note: "deterministic rules" },
                        { label: "AI layer", value: result.cached ? "skipped" : `${result.timings.aiMs} ms`, note: result.cached ? "content deduplicated" : "1 grounded call" },
                        { label: "Total", value: `${result.timings.totalMs} ms`, note: "end-to-end" },
                      ].map((m) => (
                        <div key={m.label} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-center">
                          <p className="font-mono text-lg font-bold text-emerald-300">{m.value}</p>
                          <p className="text-xs font-medium text-zinc-300">{m.label}</p>
                          <p className="text-[10px] text-zinc-500">{m.note}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* --------------------------- WORKFLOW ------------------------------ */}
        <section id="workflow" className="scroll-mt-20 py-12">
          <div className="mb-4 flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-300"><Cpu className="h-4.5 w-4.5" /></span>
            <div>
              <h2 className="text-xl font-semibold tracking-tight">How it works — the intelligence pipeline</h2>
              <p className="text-sm text-zinc-500">Ordinary code does the heavy lifting; AI does only what reasoning genuinely requires.</p>
            </div>
          </div>
          <div className="flex gap-3 overflow-x-auto pb-2 [scrollbar-color:rgba(255,255,255,0.2)_transparent] [scrollbar-width:thin]">
            <WorkflowStep icon={FileInput} step={1} title="User input" desc="Paste untrusted email/SMS text up to 10k chars." />
            <WorkflowStep icon={Filter} step={2} title="Validation" desc="Zod schema, length bounds, control-char stripping, rate limiting (12/min/IP)." />
            <WorkflowStep icon={ScanText} step={3} title="Data analysis" desc="Deterministic engine: URL inspection, lures, urgency, identity, obfuscation — scored 0–100." />
            <WorkflowStep icon={BrainCircuit} step={4} title="AI reasoning" desc="Exactly one LLM call, grounded on engine JSON, injection-hardened, 20s timeout, JSON-schema validated." />
            <WorkflowStep icon={Lightbulb} step={5} title="Recommendation" desc="AI actions filtered through a fixed allow-list catalog — arbitrary AI output can never render." />
            <WorkflowStep icon={BadgeCheck} step={6} title="Verification" desc="Engine vs AI verdict cross-check, confidence bounds, output sanitization." />
            <WorkflowStep icon={Gauge} step={7} title="Results" desc="Risk dashboard with measured timings; identical inputs deduplicated (0 extra AI calls)." />
          </div>
        </section>

        {/* ---------------------------- HISTORY ------------------------------ */}
        <section id="history" className="scroll-mt-20 py-12">
          <div className="mb-4 flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-300"><History className="h-4.5 w-4.5" /></span>
            <div>
              <h2 className="text-xl font-semibold tracking-tight">Recent analyses</h2>
              <p className="text-sm text-zinc-500">Stored as hash + 160-char preview only. Click to reopen a verdict.</p>
            </div>
          </div>
          {history.length === 0 ? (
            <div className="rounded-xl border border-dashed border-white/10 bg-white/[0.015] p-8 text-center text-sm text-zinc-500">
              No analyses yet — run one above and it will appear here.
            </div>
          ) : (
            <ul className="max-h-96 space-y-2 overflow-y-auto pr-1 [scrollbar-color:rgba(255,255,255,0.2)_transparent] [scrollbar-width:thin]">
              {history.map((h) => {
                const t = VERDICT_THEME[h.verdict] ?? VERDICT_THEME.safe;
                return (
                  <li key={h.id}>
                    <button
                      onClick={() => openHistoryItem(h.id)}
                      disabled={loadingId === h.id}
                      className="flex w-full items-center gap-3 rounded-lg border border-white/[0.07] bg-white/[0.02] p-3 text-left transition-colors hover:border-emerald-500/30 hover:bg-emerald-500/[0.05] disabled:opacity-60"
                    >
                      <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg font-mono text-sm font-bold ${t.chip}`}>{h.riskScore}</span>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm text-zinc-300">{h.contentPreview || "(no preview)"}</p>
                        <p className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-zinc-500">
                          <span className="uppercase">{h.channel}</span>·
                          <span>{h.aiUsed ? "AI-grounded" : "engine-only"}</span>·
                          {h.servedFromCache && <><span className="text-emerald-400">cache hit</span>·</>}
                          <span>{new Date(h.createdAt).toLocaleString()}</span>
                        </p>
                      </div>
                      {loadingId === h.id ? <Loader2 className="h-4 w-4 shrink-0 animate-spin text-emerald-400" /> : <ArrowRight className="h-4 w-4 shrink-0 text-zinc-600" />}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        {/* --------------------------- SECURITY ------------------------------ */}
        <section id="security" className="scroll-mt-20 py-12">
          <div className="mb-4 flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-300"><Lock className="h-4.5 w-4.5" /></span>
            <div>
              <h2 className="text-xl font-semibold tracking-tight">Security by design</h2>
              <p className="text-sm text-zinc-500">Concrete safeguards implemented in this build — not aspirational.</p>
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              { icon: Filter, title: "Input hardening", points: ["Zod schema validation (10–10k chars)", "Control-character stripping", "Per-IP rate limit: 12 req/min", "Rendered as plain text — never HTML"] },
              { icon: Lock, title: "Secrets & injection", points: ["AI SDK runs server-side only", "Message framed as untrusted data in prompt", "AI JSON schema-validated + sanitized", "Unknown AI action codes dropped"] },
              { icon: Database, title: "Privacy by design", points: ["Full message never persisted", "SHA-256 hash + 160-char preview only", "No accounts, no PII collected", "Local SQLite — data stays on instance"] },
              { icon: Zap, title: "Reliability & efficiency", points: ["AI timeout 20s + 1 retry, honest fallback", "Deterministic results without AI", "Identical input → cache hit, 0 AI calls", "Graceful errors, no crashes"] },
            ].map((card) => (
              <div key={card.title} className="rounded-xl border border-white/[0.07] bg-white/[0.03] p-4">
                <div className="mb-3 flex items-center gap-2">
                  <card.icon className="h-4 w-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-zinc-100">{card.title}</h3>
                </div>
                <ul className="space-y-1.5">
                  {card.points.map((p) => (
                    <li key={p} className="flex items-start gap-1.5 text-xs leading-relaxed text-zinc-400">
                      <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-500/70" /> {p}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>
      </main>

      {/* ------------------------------ FOOTER ------------------------------ */}
      <footer className="mt-auto border-t border-white/[0.06] bg-zinc-950/90">
        <div
          className="mx-auto flex w-full max-w-6xl flex-col items-center justify-between gap-3 px-4 py-6 text-center sm:flex-row sm:px-6 sm:text-left"
          style={{ paddingBottom: "max(1.5rem, env(safe-area-inset-bottom))" }}
        >
          <div className="flex items-center gap-2 text-sm text-zinc-400">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            <span><span className="font-semibold text-zinc-200">PhishGuard AI</span> — Hackathon build · Next.js 16 · TypeScript · Prisma/SQLite · grounded AI layer</span>
          </div>
          <p className="max-w-md text-xs leading-relaxed text-zinc-600">
            Decision support, not a guarantee. Always verify sensitive requests through official channels.
          </p>
        </div>
      </footer>
    </div>
  );
}
