# 🛡️ AI-Assisted HTTP Security Header Analyzer

A small Python tool that scans a website's HTTP response headers, flags
missing or weak security headers (like CSP, HSTS, X-Frame-Options), rates
each finding's severity with reasoning, and uses an AI model to explain
the findings in plain English. Built and tested entirely against an
authorized local lab (OWASP Juice Shop) — no real/unauthorized websites
were ever scanned.

**What it does:** `URL → checks security headers → severity + evidence → AI explanation → Markdown report`

📄 Full report example: [`reports/security_report.md`](./reports/security_report.md)
📋 Known limitations: [`LIMITATIONS.md`](./LIMITATIONS.md)

---
