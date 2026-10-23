import type { EngineResult, Finding, CategoryScore, UrlInfo, Verdict, Channel } from "./phishing-engine";

export type { EngineResult, Finding, CategoryScore, UrlInfo, Verdict, Channel };

/** Fixed action catalog. AI may only pick from these codes —
 *  unknown codes are dropped server-side so we never render arbitrary AI output. */
export const ACTION_CATALOG: Record<string, string> = {
  report_to_security: "Report to your IT / security team",
  delete_message: "Delete the message after reporting",
  block_sender: "Block the sender / number",
  do_not_click_links: "Do not click any links in the message",
  do_not_open_attachment: "Do not open attachments",
  verify_via_official_channel: "Verify via the official website or app — not by replying",
  never_share_otp: "Never share OTPs or passwords",
  reset_affected_password: "Change the affected password immediately",
  monitor_accounts: "Monitor bank/card statements for suspicious activity",
  warn_recipients: "Warn colleagues / recipients about this campaign",
};

export interface AiAssessment {
  verdict: "phishing" | "suspicious" | "legitimate";
  confidence: number; // 0..1
  reasoning: string;
  techniques: string[];
  actions: { code: string; label: string }[];
}

export interface VerificationCheck {
  name: string;
  pass: boolean;
  detail: string;
}

export interface Verification {
  agreement: "agree" | "partial" | "mismatch" | "ai_unavailable";
  summary: string;
  checks: VerificationCheck[];
}

export interface AnalysisResponse {
  id: string;
  createdAt: string;
  channel: Channel;
  riskScore: number;
  verdict: Verdict;
  verdictLabel: string;
  categories: CategoryScore[];
  findings: Finding[];
  urls: UrlInfo[];
  indicators: { label: string; value: string }[];
  recommendations: string[];
  meta: EngineResult["meta"];
  ai: AiAssessment | null;
  aiError: string | null;
  verification: Verification;
  cached: boolean;
  timings: { engineMs: number; aiMs: number; totalMs: number };
}

export interface HistoryItem {
  id: string;
  contentPreview: string;
  channel: string;
  riskScore: number;
  verdict: Verdict;
  aiUsed: boolean;
  servedFromCache: boolean;
  createdAt: string;
}

export interface StatsPayload {
  total: number;
  avgRisk: number;
  verdictCounts: Record<Verdict, number>;
  aiUsageRate: number;
  cacheHitRate: number;
  avgEngineMs: number;
  avgTotalMs: number;
  cacheSavingsMs: number;
}
