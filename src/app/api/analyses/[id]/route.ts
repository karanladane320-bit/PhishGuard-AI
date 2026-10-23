import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import type { AnalysisResponse, AiAssessment, CategoryScore, Finding, UrlInfo, Verification, Verdict, Channel } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

interface EnginePayload {
  categories: CategoryScore[];
  findings: Finding[];
  urls: UrlInfo[];
  indicators: { label: string; value: string }[];
  recommendations: string[];
  meta: { chars: number; words: number; urlCount: number; engineMs: number };
}

function verdictLabel(score: number, fallback: string): string {
  if (score >= 75) return "Critical — Confident Phishing";
  if (score >= 50) return "High Risk — Likely Phishing";
  if (score >= 25) return "Suspicious";
  if (score >= 0 && fallback) return fallback || "Likely Safe";
  return "Likely Safe";
}

// GET /api/analyses/[id] — reload a past analysis (from stored summary data only).
export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    if (!/^[a-z0-9]{10,40}$/i.test(id)) {
      return NextResponse.json({ error: "Invalid analysis id." }, { status: 400 });
    }
    const record = await db.analysis.findUnique({ where: { id } });
    if (!record) {
      return NextResponse.json({ error: "Analysis not found." }, { status: 404 });
    }
    const engine = JSON.parse(record.engineFindings) as EnginePayload;
    const response: AnalysisResponse = {
      id: record.id,
      createdAt: record.createdAt.toISOString(),
      channel: record.channel as Channel,
      riskScore: record.riskScore,
      verdict: record.verdict as Verdict,
      verdictLabel: verdictLabel(record.riskScore, record.verdict),
      categories: engine.categories,
      findings: engine.findings,
      urls: engine.urls,
      indicators: engine.indicators,
      recommendations: engine.recommendations,
      meta: engine.meta,
      ai: record.aiAssessment ? (JSON.parse(record.aiAssessment) as AiAssessment) : null,
      aiError: record.aiUsed ? null : "AI reasoning was unavailable for this analysis — deterministic engine results only.",
      verification: JSON.parse(record.verification) as Verification,
      cached: record.servedFromCache,
      timings: { engineMs: record.engineMs, aiMs: record.aiMs, totalMs: record.totalMs },
    };
    return NextResponse.json(response);
  } catch (error) {
    console.error("[analyses/:id] failed:", error);
    return NextResponse.json({ error: "Could not load this analysis." }, { status: 500 });
  }
}
