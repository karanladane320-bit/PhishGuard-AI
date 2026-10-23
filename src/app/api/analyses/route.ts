import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import type { HistoryItem, StatsPayload, Verdict } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const EMPTY_COUNTS: Record<Verdict, number> = { safe: 0, suspicious: 0, high: 0, critical: 0 };

// GET /api/analyses — recent history + aggregate stats for the dashboard.
export async function GET() {
  try {
    const rows = await db.analysis.findMany({
      orderBy: { createdAt: "desc" },
      take: 12,
      select: {
        id: true, contentPreview: true, channel: true, riskScore: true,
        verdict: true, aiUsed: true, servedFromCache: true, createdAt: true,
        engineMs: true, aiMs: true, totalMs: true,
      },
    });

    const [total, avgAgg, cachedCount] = await Promise.all([
      db.analysis.count(),
      db.analysis.aggregate({
        _avg: { riskScore: true, engineMs: true, totalMs: true },
      }),
      db.analysis.count({ where: { servedFromCache: true } }),
    ]);

    const verdictCounts = { ...EMPTY_COUNTS };
    for (const r of rows) {
      if (r.verdict in verdictCounts) verdictCounts[r.verdict as Verdict] += 1;
    }
    // Count verdict distribution across the FULL table, not just the recent page.
    const verdictGroup = await db.analysis.groupBy({
      by: ["verdict"],
      _count: { _all: true },
    });
    for (const g of verdictGroup) {
      if (g.verdict in verdictCounts) verdictCounts[g.verdict as Verdict] = g._count._all;
    }

    const aiUsedCount = await db.analysis.count({ where: { aiUsed: true } });

    const stats: StatsPayload = {
      total,
      avgRisk: Math.round(avgAgg._avg.riskScore ?? 0),
      verdictCounts,
      aiUsageRate: total > 0 ? Math.round((aiUsedCount / total) * 100) : 0,
      cacheHitRate: total > 0 ? Math.round((cachedCount / total) * 100) : 0,
      avgEngineMs: Math.round(avgAgg._avg.engineMs ?? 0),
      avgTotalMs: Math.round(avgAgg._avg.totalMs ?? 0),
      cacheSavingsMs: cachedCount * 20_000, // each cache hit avoids ~1 full AI call (est.)
    };

    const items: HistoryItem[] = rows.map((r) => ({
      id: r.id,
      contentPreview: r.contentPreview,
      channel: r.channel,
      riskScore: r.riskScore,
      verdict: r.verdict as Verdict,
      aiUsed: r.aiUsed,
      servedFromCache: r.servedFromCache,
      createdAt: r.createdAt.toISOString(),
    }));

    return NextResponse.json({ items, stats });
  } catch (error) {
    console.error("[analyses] failed to load history:", error);
    return NextResponse.json({ error: "Could not load analysis history." }, { status: 500 });
  }
}
