import os
from dotenv import load_dotenv
load_dotenv()

from groq import Groq
import requests

# ─────────────────────────────────────────────
# AI CLIENT SETUP (Groq)
# ─────────────────────────────────────────────
client = Groq()  # automatically reads GROQ_API_KEY from the environment (or .env file)

AI_MODEL = "openai/gpt-oss-20b"  # general-purpose reasoning model available on this account


# ─────────────────────────────────────────────
# RULEBOOK (which headers we check, and how we judge each one)
# ─────────────────────────────────────────────
SECURITY_HEADER_CHECKS = [
    {
        "header": "Strict-Transport-Security",
        "should_be_present": True,
        "description": "Forces browsers to use HTTPS instead of HTTP.",
        "severity_if_missing": "Medium",
        "severity_reasoning": (
            "Missing HSTS allows a possible downgrade from HTTPS to HTTP on first "
            "connection, exposing traffic to interception on untrusted networks. "
            "Rated Medium rather than High because it requires an active "
            "network-position attacker to exploit, not a remote/anonymous one."
        ),
        "remediation": (
            "Add the header 'Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains' once the site is served over HTTPS in production."
        )
    },
    {
        "header": "X-Frame-Options",
        "should_be_present": True,
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "severity_if_missing": "Medium",
        "severity_reasoning": (
            "Missing this header enables clickjacking attacks, where a user could be "
            "tricked into clicking a hidden button. Rated Medium because impact "
            "depends heavily on what sensitive actions the page allows (e.g. "
            "account changes vs. a static info page)."
        ),
        "remediation": (
            "Add the header 'X-Frame-Options: DENY' (or 'SAMEORIGIN' if the app "
            "legitimately needs to be framed by its own pages)."
        )
    },
    {
        "header": "X-Content-Type-Options",
        "should_be_present": True,
        "expected_value": "nosniff",
        "description": "Stops browsers from guessing (MIME-sniffing) file types.",
        "severity_if_missing": "Low",
        "severity_reasoning": (
            "MIME-sniffing issues are a secondary/enabling factor for other attacks "
            "rather than a direct exploit path on their own, so this is rated Low "
            "in isolation."
        ),
        "remediation": "Add the header 'X-Content-Type-Options: nosniff'."
    },
    {
        "header": "Content-Security-Policy",
        "should_be_present": True,
        "description": "Restricts which sources of scripts/content the page can load, mitigating XSS.",
        "severity_if_missing": "High",
        "severity_reasoning": (
            "CSP is one of the strongest available browser-side defenses against "
            "Cross-Site Scripting (XSS), a high-impact, very common vulnerability "
            "class. Its complete absence removes a major layer of defense, so this "
            "is rated High."
        ),
        "remediation": (
            "Add a 'Content-Security-Policy' header, starting with a restrictive "
            "baseline such as \"default-src 'self'\" and expanding only as needed "
            "for legitimate third-party resources."
        )
    },
    {
        "header": "Referrer-Policy",
        "should_be_present": True,
        "description": "Controls how much URL information leaks to other sites via referrer.",
        "severity_if_missing": "Low",
        "severity_reasoning": (
            "Impact is typically limited to partial URL/metadata leakage to "
            "third-party sites when a user clicks an outbound link — rarely a "
            "direct path to full compromise, so rated Low."
        ),
        "remediation": (
            "Add the header 'Referrer-Policy: strict-origin-when-cross-origin' "
            "(or 'no-referrer' for stricter privacy)."
        )
    },
    {
        "header": "Permissions-Policy",
        "should_be_present": True,
        "description": "Restricts access to browser features like camera/microphone/geolocation.",
        "severity_if_missing": "Low",
        "severity_reasoning": (
            "Modern browsers already require separate user consent for camera/mic/"
            "location access, so this header is a defense-in-depth layer rather "
            "than the primary control, warranting a Low rating."
        ),
        "remediation": (
            "Add a 'Permissions-Policy' header disabling features the app does not "
            "need, e.g. 'geolocation=(), camera=(), microphone=()'."
        )
    },
    {
        "header": "X-Powered-By",
        "should_be_present": False,
        "description": "Reveals server/framework details useful for attackers (information disclosure).",
        "severity_if_present": "Low",
        "severity_reasoning": (
            "This is an information disclosure issue, not a direct vulnerability. "
            "It helps an attacker plan (e.g. look up known CVEs for that framework "
            "version) but does not by itself grant any access, so rated Low."
        ),
        "remediation": (
            "Disable this header at the framework level (e.g. in Express: "
            "'app.disable(\"x-powered-by\")') so the technology stack isn't advertised."
        )
    },
]


# ─────────────────────────────────────────────
# SCANNER LOGIC (deterministic — no AI here)
# ─────────────────────────────────────────────
def scan_url(url):
    """Send a GET request and check its headers against our rulebook."""
    response = requests.get(url)
    headers = response.headers

    findings = []

    for check in SECURITY_HEADER_CHECKS:
        header_name = check["header"]
        is_present = header_name in headers

        if check["should_be_present"] and not is_present:
            findings.append({
                "url": url,
                "header": header_name,
                "status": "MISSING",
                "description": check["description"],
                "evidence": f"Header '{header_name}' was not found in the response headers.",
                "severity": check["severity_if_missing"],
                "severity_reasoning": check["severity_reasoning"],
                "remediation": check["remediation"],
            })

        elif not check["should_be_present"] and is_present:
            findings.append({
                "url": url,
                "header": header_name,
                "status": "PRESENT_BUT_SHOULD_BE_ABSENT",
                "description": check["description"],
                "evidence": f"Header found: '{header_name}: {headers[header_name]}'",
                "severity": check["severity_if_present"],
                "severity_reasoning": check["severity_reasoning"],
                "remediation": check["remediation"],
            })

        elif check.get("expected_value") and is_present:
            actual_value = headers[header_name]
            if check["expected_value"] not in actual_value:
                findings.append({
                    "url": url,
                    "header": header_name,
                    "status": "PRESENT_BUT_WEAK_VALUE",
                    "description": check["description"],
                    "evidence": (
                        f"Header found with unexpected value: "
                        f"'{header_name}: {actual_value}' "
                        f"(expected to include '{check['expected_value']}')"
                    ),
                    "severity": "Medium",
                    "severity_reasoning": (
                        "The header is present but its value doesn't match the "
                        "expected secure configuration, so the intended protection "
                        "may not be fully effective."
                    ),
                    "remediation": check["remediation"],
                })

        # ── Special-case check: weak Content-Security-Policy values ──
        # CSP can be "present" but still practically useless if it contains
        # wildcards or unsafe directives. This is a separate, additional
        # check layered on top of the basic presence check above.
        if header_name == "Content-Security-Policy" and is_present:
            csp_value = headers[header_name]
            weak_patterns = ["default-src *", "script-src *", "unsafe-inline", "unsafe-eval"]
            found_weak = [pattern for pattern in weak_patterns if pattern in csp_value]

            if found_weak:
                findings.append({
                    "url": url,
                    "header": header_name,
                    "status": "PRESENT_BUT_WEAK_VALUE",
                    "description": check["description"],
                    "evidence": (
                        f"CSP header found but contains weak directive(s): "
                        f"{', '.join(found_weak)}. Full value: '{csp_value}'"
                    ),
                    "severity": "Medium",
                    "severity_reasoning": (
                        "CSP is present (better than missing entirely), but wildcard "
                        "sources or 'unsafe-inline'/'unsafe-eval' significantly weaken "
                        "its ability to prevent XSS, so this is rated Medium rather "
                        "than High (missing) or no finding (fully absent of the issue)."
                    ),
                    "remediation": (
                        "Remove wildcard (*) sources and 'unsafe-inline'/'unsafe-eval' "
                        "from the CSP. Use specific trusted domains and nonces/hashes "
                        "for inline scripts instead."
                    ),
                })

    return findings


# ─────────────────────────────────────────────
# AI-ASSISTED INTERPRETATION (advisory, non-deterministic)
# This function ONLY explains findings already produced above.
# It never changes status or severity.
# ─────────────────────────────────────────────
def get_ai_interpretation(finding):
    """Ask Groq's LLM to explain ONE finding in plain English."""
    prompt = f"""You are assisting a beginner security student in writing a report.
Below is a DETERMINISTIC finding already produced by a Python HTTP header scanner.
Do not change the severity or status — they are already decided.
Your only job is to:
1. Explain this finding in plain, simple English for a non-technical reader.
2. Note if anything about this finding is ambiguous or worth a human double-checking.

Finding:
- Header: {finding['header']}
- Status: {finding['status']}
- Description: {finding['description']}
- Evidence: {finding['evidence']}
- Severity: {finding['severity']}
- Severity Reasoning: {finding['severity_reasoning']}

Respond in 2-4 short sentences. Do not repeat the raw evidence verbatim, explain what it means.
"""

    chat_completion = client.chat.completions.create(
        model=AI_MODEL,
        max_tokens=600,
        reasoning_effort="low",
        messages=[{"role": "user", "content": prompt}]
    )

    return chat_completion.choices[0].message.content


# ─────────────────────────────────────────────
# REPORT GENERATION (Markdown)
# ─────────────────────────────────────────────
def generate_markdown_report(url, findings, output_path="reports/security_report.md"):
    """Build a Markdown report for one URL's findings and append it to the report file."""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    lines = []
    lines.append(f"## Scan Target: {url}\n")
    lines.append(f"**Vulnerability Detected:** {'Y' if findings else 'N'}\n")

    if not findings:
        lines.append("No missing/misconfigured security headers were detected by this scan.\n")
    else:
        for i, finding in enumerate(findings, start=1):
            ai_explanation = get_ai_interpretation(finding)

            lines.append(f"### Finding {i}: {finding['header']} — {finding['status']}\n")
            lines.append(f"- **Description:** {finding['description']}")
            lines.append(f"- **Evidence:** {finding['evidence']}")
            lines.append(f"- **Severity:** {finding['severity']}")
            lines.append(f"- **Severity Reasoning:** {finding['severity_reasoning']}")
            lines.append(f"- **Recommended Remediation:** {finding['remediation']}")
            lines.append("")
            lines.append("**AI-Assisted Interpretation** *(advisory, non-deterministic — generated by an LLM, not the scanner)*:")
            lines.append(f"> {ai_explanation}")
            lines.append("")

    lines.append("---\n")

    with open(output_path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Report section for {url} written to {output_path}")


# ─────────────────────────────────────────────
# MAIN — scan all authorized targets and generate the report
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Authorized local lab targets only.
    # localhost:3000 = OWASP Juice Shop (intentionally vulnerable — expect findings)
    # localhost:5000 = our own safe test server (expect zero or minimal findings)
    authorized_targets = [
        "http://localhost:3000",
        "http://localhost:5000",
    ]

    for target_url in authorized_targets:
        print(f"Scanning: {target_url}")
        try:
            results = scan_url(target_url)
            generate_markdown_report(target_url, results)
            print(f"  → {len(results)} finding(s) detected.\n")
        except requests.exceptions.ConnectionError:
            print(f"  → Could not connect to {target_url}. Is it running?\n")