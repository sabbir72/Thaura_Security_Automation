from __future__ import annotations

from typing import Any

from playwright.sync_api import sync_playwright

from common import PAGES, REPORT_DIR

REQUIRED_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
]


def run(show_browser: bool = False) -> dict[str, Any]:
    results = []
    findings = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not show_browser)
        context = browser.new_context(viewport={"width": 1440, "height": 900})

        for url in PAGES:
            page = context.new_page()
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=60000)
                page.wait_for_timeout(1000)
                headers = response.all_headers() if response else {}

                row = {
                    "Page URL": url,
                    "HTTP Status": response.status if response else "N/A",
                }

                missing = []
                for header in REQUIRED_HEADERS:
                    value = headers.get(header, "")
                    row[header] = value
                    if not value:
                        missing.append(header)
                        findings.append({
                            "Page URL": url,
                            "Header": header,
                            "Finding": "Missing",
                        })

                # Basic CSP review; presence alone is not considered enough.
                csp = headers.get("content-security-policy", "")
                weak_csp_terms = []
                for term in ["unsafe-inline", "unsafe-eval", "*"]:
                    if term in csp.lower():
                        weak_csp_terms.append(term)

                row["CSP Review"] = (
                    "Review: " + ", ".join(weak_csp_terms)
                    if weak_csp_terms else "No flagged term"
                )
                row["Missing Headers"] = ", ".join(missing)
                row["Status"] = "PASS" if not missing else "FAIL"
                results.append(row)

            finally:
                page.close()

        context.close()
        browser.close()

    return {"results": results, "findings": findings}


def main(show_browser: bool = False):
    from excel_utils import export_case
    export_case(
        "TC-SEC-02",
        "Security Response Headers",
        run(show_browser),
        REPORT_DIR / "TC-SEC-02_Security_Headers.xlsx",
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-sv", "--show-browser", action="store_true")
    args = parser.parse_args()
    main(args.show_browser)
