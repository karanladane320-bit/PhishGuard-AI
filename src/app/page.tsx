import type { Metadata } from "next";
import PhishGuardApp from "@/components/phishguard-app";

export const metadata: Metadata = {
  title: "PhishGuard AI — Phishing Detection Workbench",
  description:
    "Detect phishing emails and smishing SMS with a deterministic security engine grounded by AI reasoning. Input → Validation → Analysis → AI Reasoning → Verification → Results.",
  keywords: ["phishing", "security", "AI", "fraud detection", "email security", "smishing"],
};

export default function Home() {
  return <PhishGuardApp />;
}
