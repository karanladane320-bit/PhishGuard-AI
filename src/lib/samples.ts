/**
 * Built-in sample scenarios so judges can test the full workflow in one click.
 * URLs use RFC 5737 documentation IPs / example domains — safe & inert.
 */

export interface Sample {
  id: string;
  label: string;
  scenario: string;
  expected: string;
  content: string;
}

export const SAMPLES: Sample[] = [
  {
    id: "phish-email",
    label: "Phishing email",
    scenario: "Bank credential-harvesting campaign",
    expected: "High risk · 73",
    content: `From: SBI Security Team <security.alerts@sbi-secure-verify.tk>
Reply-To: account.recovery@mailsvc-secure.tk
Subject: URGENT: Your account will be SUSPENDED within 24 hours!!

Dear Valued Customer,

We detected unusual activity in your account. Your online banking access will be
suspended permanently within 24 hours unless you verify your account immediately.

Verify your account now: http://203.0.113.7/secure/login?redirect=onlinesbi.sbi.co.in&session=aGdkNjM3ZGhkc2Q=

IMPORTANT: Do not reply to this email. Update your KYC and net banking credentials
via the link below only. Enter your username, password, OTP and card details to
restore access.

SBI Security Department
Security Alert ID: SB-4471-QA
ZW5jcnlwdGVkLXBheWxvYWQtc3RyaW5nLXhpZmZlci1vYnNjdXJlLWhpZGU=`,
  },
  {
    id: "smish-sms",
    label: "Smishing SMS",
    scenario: "Fake parcel-delivery fee scam",
    expected: "Suspicious · 29",
    content: `FrDHL-EXPRESS: Your package PKG-88213 is ON HOLD. A delivery fee of ₹1.99 is pending. Pay now to reschedule TODAY or your parcel returns to sender: https://cutt.ly/dhl-fee-pay

DHL Logistics - Final notice. Do not reply to this SMS.`,
  },
  {
    id: "legit-email",
    label: "Legitimate email",
    scenario: "Normal internal meeting invite",
    expected: "Safe · 0",
    content: `From: Priya Sharma <priya.sharma@acmecorp.com>
Subject: Design review — Thursday 3pm

Hi Alex,

Quick reminder that we moved the quarterly design review to Thursday at 3:00 PM
in Meeting Room 2 (and on Teams for remote folks).

Agenda:
1. Q3 design-system updates — Priya
2. Mobile onboarding flow feedback — Alex
3. AOB

Could you share the updated onboarding mocks before the meeting? The latest
versions are on our intranet under Projects > Design > Onboarding.

Thanks,
Priya Sharma
Senior Product Designer, Acme Corp`,
  },
  {
    id: "giftcard-scam",
    label: "CEO gift-card scam",
    scenario: "Business Email Compromise (BEC)",
    expected: "Suspicious · 49",
    content: `From: Daniel Reeve - CEO <d.reeve.ceo.office@gmail.com>
Subject: Are you at your desk? Quick task

Hi,

I'm in a meeting but need you to handle something discreetly. I'm counting on you.
Head over to the store and get 5 x $200 Google Play gift cards for our client
appreciation giveaways. Scratch the codes and email me the pictures right away —
I need them within the hour.

Don't discuss this with anyone yet, it's a surprise for the team.

Daniel Reeve
CEO, Reeve & Partners`,
  },
];
