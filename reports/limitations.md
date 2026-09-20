# Limitations of This Tool

This document honestly describes what this HTTP Security Header Analyzer
CAN and CANNOT reliably detect. Every automated security tool has blind
spots, and documenting them is a core part of responsible security tooling.

## What This Tool CAN Detect

- Whether a set of well-known security headers are present or absent in a
  single HTTP response (Strict-Transport-Security, X-Frame-Options,
  X-Content-Type-Options, Content-Security-Policy, Referrer-Policy,
  Permissions-Policy).
- Whether `X-Powered-By` is present (an information-disclosure issue).
- Whether `X-Content-Type-Options` has the correct value (`nosniff`).
- A basic set of known-weak Content-Security-Policy patterns
  (e.g. wildcard sources, `unsafe-inline`, `unsafe-eval`).

## What This Tool CANNOT Reliably Detect

1. **Whether a missing/weak header is actually exploitable.**
   This tool only checks for the *presence and basic quality* of security
   headers. It does not attempt to prove exploitability (e.g. it does not
   build a working clickjacking page or XSS payload). A finding here means
   "a defensive control appears weak or missing," not "this is confirmed
   exploitable."

2. **Full/advanced Content-Security-Policy correctness.**
   CSP is a small language with many directives (`script-src`, `style-src`,
   `img-src`, `frame-ancestors`, nonces, hashes, report-only mode, etc.).
   This tool only does simple substring matching against a short list of
   known-bad patterns. It cannot fully parse or evaluate a complex CSP,
   and could miss subtler misconfigurations, or in rare cases flag a
   pattern that is actually safe in a specific context.

3. **Headers set dynamically or per-page.**
   This tool sends a single GET request to the root URL of a target. Some
   applications set different headers on different pages, after
   authentication, or via client-side JavaScript rather than server
   response headers. Those cases are outside this tool's current scope.

4. **HTTPS-only issues when testing over plain HTTP.**
   Headers like `Strict-Transport-Security` are only fully meaningful on
   a site actually served over HTTPS. Our local lab targets run over
   plain HTTP, so HSTS findings here describe a "not yet configured for
   when HTTPS is used" state, not an active real-world exposure.

5. **Anything outside HTTP response headers.**
   This tool does not check for SQL injection, broken authentication,
   outdated dependencies, exposed admin panels, or any other OWASP Top 10
   category. It is scoped narrowly to the "Security Misconfiguration —
   HTTP Headers" sub-area only.

6. **False positives from non-standard but safe configurations.**
   A small number of legitimate, secure setups could theoretically use a
   header value that superficially matches one of our "weak" patterns.
   Every automated finding should be reviewed by a human before being
   treated as confirmed.

## Why These Limitations Exist (by design)

This tool deliberately avoids sending exploit payloads or attempting to
prove real-world impact, per its safety scope (defensive detection only,
tested against authorized local lab targets). This keeps the tool safe to
run, but means it produces *indicators*, not *proof of exploitability*.
A human analyst is expected to use these findings as a starting point for
further, careful review — not as a final verdict.