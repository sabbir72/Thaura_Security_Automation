from __future__ import annotations

from typing import Any

from playwright.sync_api import sync_playwright

from common import PAGES, SENSITIVE_PATTERNS, REPORT_DIR, redact, text_like


def scan_text(source: str, source_url: str, source_type: str, page_url: str, findings: list[dict]):
    if not source:
        return

    # Avoid dumping secret values into evidence. Only record a redacted context.
    for label, pattern in SENSITIVE_PATTERNS:
        match = pattern.search(source)
        if match:
            start = max(0, match.start() - 100)
            end = min(len(source), match.end() + 140)
            context = redact(source[start:end])
            findings.append({
                "Page URL": page_url,
                "Source URL": source_url,
                "Source Type": source_type,
                "Pattern": label,
                "Redacted Context": context,
            })


def run(show_browser: bool = False) -> dict[str, Any]:
    findings = []
    page_rows = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not show_browser)
        context = browser.new_context(viewport={"width": 1440, "height": 900})

        for url in PAGES:
            page = context.new_page()
            scanned_resources = 0

            def on_response(response):
                nonlocal scanned_resources
                try:
                    content_type = response.header_value("content-type") or ""
                    if not text_like(content_type):
                        return
                    content_length = response.header_value("content-length") or ""
                    try:
                        declared_size = int(content_length)
                    except (TypeError, ValueError):
                        declared_size = 0
                    if declared_size > 2_000_000:
                        return
                    if response.request.resource_type not in {"document", "script", "xhr", "fetch"}:
                        return

                    body_text = response.text()
                    scanned_resources += 1
                    scan_text(
                        body_text,
                        response.url,
                        response.request.resource_type,
                        url,
                        findings,
                    )
                except Exception:
                    pass

            console_messages = []

            def on_console(message):
                if message.type in {"error", "warning"}:
                    console_messages.append(message.text or "")

            page.on("response", on_response)
            page.on("console", on_console)

            try:
                response = page.goto(url, wait_until="load", timeout=60000)
                page.wait_for_timeout(2000)

                # Scan current DOM/source too.
                try:
                    html = page.content()
                    scan_text(html, page.url, "dom", url, findings)
                except Exception:
                    pass

                # Scan console messages for obvious secret/stack-trace exposure.
                for message in console_messages:
                    scan_text(message, page.url, "console", url, findings)

                page_rows.append({
                    "Page URL": url,
                    "HTTP Status": response.status if response else "N/A",
                    "Text/JSON Resources Scanned": scanned_resources,
                    "Potential Sensitive Findings": sum(
                        1 for item in findings
                        if item["Page URL"] == url
                    ),
                    "Console Error/Warning Messages Scanned": len(console_messages),
                    "Status": "FAIL" if any(item["Page URL"] == url for item in findings) else "PASS",
                })

            except Exception as exc:
                page_rows.append({
                    "Page URL": url,
                    "HTTP Status": "ERROR",
                    "Text/JSON Resources Scanned": scanned_resources,
                    "Potential Sensitive Findings": 0,
                    "Console Error/Warning Messages Scanned": len(console_messages),
                    "Error": str(exc),
                    "Status": "FAIL",
                })
            finally:
                page.close()

        context.close()
        browser.close()

    return {"results": page_rows, "findings": findings}


def main(show_browser: bool = False):
    from excel_utils import export_case
    export_case(
        "TC-SEC-04",
        "Sensitive Information Exposure",
        run(show_browser),
        REPORT_DIR / "TC-SEC-04_Sensitive_Information_Exposure.xlsx",
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-sv", "--show-browser", action="store_true")
    args = parser.parse_args()
    main(args.show_browser)
