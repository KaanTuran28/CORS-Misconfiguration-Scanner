#!/usr/bin/env python3
"""Scans a live URL for CORS (Cross-Origin Resource Sharing) misconfigurations.

Sends real HTTP requests carrying a handful of crafted `Origin` headers — an
arbitrary unrelated origin, the special `null` origin (reachable from a
sandboxed iframe or a `data:` URI), and two origin-validation-bypass shapes
(a naive suffix check like `str.endswith(target)` is fooled by prefixing the
real host with no separator; a naive substring/prefix check is fooled by
making the real host a *subdomain* of an attacker-controlled one) — then
inspects whether `Access-Control-Allow-Origin` reflects them back, and
whether `Access-Control-Allow-Credentials` is also set.

Same class of vulnerability as countless real bug-bounty reports: a
reflected-origin-plus-credentials CORS policy lets any website read an
authenticated (cookie-bearing) response from the target on a victim's behalf.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def default_fetch(url: str, origin: str, timeout: float = 5.0):
    req = urllib.request.Request(url, headers={"Origin": origin, "User-Agent": "cors-misconfiguration-scanner"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = resp.headers
    except urllib.error.HTTPError as exc:
        headers = exc.headers
    except (urllib.error.URLError, OSError) as exc:
        raise ConnectionError(str(exc)) from exc
    return headers.get("Access-Control-Allow-Origin"), headers.get("Access-Control-Allow-Credentials")


def build_test_origins(target_host: str) -> list:
    return [
        ("arbitrary_origin_reflected", "https://evil-attacker-test.example"),
        ("null_origin_allowed", "null"),
        ("suffix_matching_bypass", f"https://evil{target_host}"),
        ("subdomain_matching_bypass", f"https://{target_host}.evil-attacker-test.example"),
    ]


def finding(severity: str, check: str, origin_sent: str, reason: str, recommendation: str) -> dict:
    return {"severity": severity, "check": check, "origin_sent": origin_sent, "reason": reason, "recommendation": recommendation}


def evaluate_response(check: str, origin_sent: str, acao, acac) -> dict:
    if not acao:
        return None

    credentials_allowed = str(acac).lower() == "true"

    if acao == "*":
        if credentials_allowed:
            return finding(
                "MEDIUM", "wildcard_with_credentials", origin_sent,
                'Access-Control-Allow-Origin: "*" is combined with Access-Control-Allow-Credentials: true. '
                "Browsers reject this exact combination per the Fetch spec, but it signals a "
                "misconfigured/copy-pasted CORS setup that may have other issues nearby.",
                'Send a specific, validated origin instead of "*" whenever credentials are allowed, '
                "or drop credentials entirely for a public, wildcard-CORS API.",
            )
        return None  # "*" with no credentials is a normal, safe public-API pattern

    if acao == "null":
        severity = "HIGH" if credentials_allowed else "MEDIUM"
        return finding(
            severity, "null_origin_allowed", origin_sent,
            f'Server reflects Access-Control-Allow-Origin: "null" (credentials '
            f'{"allowed" if credentials_allowed else "not allowed"}) — reachable via a sandboxed iframe '
            'or a data: URI, both of which send an Origin: null header.',
            'Never allow the literal "null" origin; validate against an explicit allowlist of real origins.',
        )

    if acao == origin_sent:
        severity = "HIGH" if credentials_allowed else "MEDIUM"
        return finding(
            severity, check, origin_sent,
            f'Server reflects the attacker-controlled Origin ("{origin_sent}") back in '
            f'Access-Control-Allow-Origin (credentials {"allowed" if credentials_allowed else "not allowed"}).'
            + (" This lets any website make an authenticated cross-origin request and read the response."
               if credentials_allowed else
               " This lets any website read the (non-credentialed) response."),
            "Validate the Origin header against an explicit allowlist with exact string comparison "
            "(never a substring/suffix check), and only echo back origins that pass it.",
        )

    return None


def scan_url(url: str, timeout: float = 5.0, fetch=None) -> dict:
    fetch = fetch or default_fetch
    target_host = urllib.parse.urlparse(url).netloc

    findings = []
    for check, origin in build_test_origins(target_host):
        acao, acac = fetch(url, origin, timeout)
        result = evaluate_response(check, origin, acao, acac)
        if result is not None:
            findings.append(result)

    return {"url": url, "findings": findings}


def build_report(result: dict) -> str:
    findings = result["findings"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    lines = [
        f"# CORS Misconfiguration Scan — {result['url']}",
        "",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM",
        "",
    ]
    if findings:
        lines += ["| Severity | Check | Origin Sent | Reason |", "|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1}
        for f in sorted(findings, key=lambda f: order[f["severity"]]):
            reason = f["reason"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {f['check']} | `{f['origin_sent']}` | {reason} |")
    else:
        lines.append("No issues found.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(result: dict) -> str:
    findings = result["findings"]
    payload = {
        "url": result["url"],
        "summary": {
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        },
        "findings": findings,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Scan a live URL for CORS misconfigurations.")
    parser.add_argument("--url", required=True, help="Target URL, e.g. https://api.example.com/data")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    try:
        result = scan_url(args.url, timeout=args.timeout)
    except ConnectionError as exc:
        print(f"Error: request to {args.url} failed ({exc})", file=sys.stderr)
        return 2

    report = build_json_report(result) if args.format == "json" else build_report(result)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    high_count = sum(1 for f in result["findings"] if f["severity"] == "HIGH")
    medium_count = sum(1 for f in result["findings"] if f["severity"] == "MEDIUM")
    print(f"Scanned {args.url}: {high_count} HIGH, {medium_count} MEDIUM finding(s).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
