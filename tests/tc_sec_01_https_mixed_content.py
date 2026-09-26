from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from playwright.sync_api import sync_playwright

from common import PAGES, REPORT_DIR, EVIDENCE_DIR, slug


def http_variant(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit(("http", parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def run(show_browser: bool = False) -> dict[str, Any]:
    results = []
    mixed = []
    console_messages = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not show_browser)
        context = browser.new_context(viewport={"width": 1440, "height": 900})

        for url in PAGES:
            page = context.new_page()
            http_page = context.new_page()
            http_redirect_status = "N/A"
            http_final_url = ""
            http_navigation_error = ""
            page_console = []
            insecure_requests = []

            def on_console(message):
                text = message.text or ""
                if message.type in {"error", "warning"}:
                    record = {
                        "Page URL": url,
                        "Type": message.type,
                        "Message": text,
                    }
                    page_console.append(record)
                    console_messages.append(record)

            def on_request(request):
                if request.url.lower().startswith("http://"):
                    insecure_requests.append({
                        "Page URL": url,
                        "Request URL": request.url,
                        "Resource Type": request.resource_type,
                    })

            page.on("console", on_console)
            page.on("request", on_request)

            try:
                response = page.goto(url, wait_until="load", timeout=60000)
                page.wait_for_timeout(1500)
                final_url = page.url

                # Test HTTP -> HTTPS on a separate page so the deliberate HTTP
                # navigation itself is not misclassified as mixed content.
                try:
                    response_http = http_page.goto(
                        http_variant(url),
                        wait_until="domcontentloaded",
                        timeout=30000,
                    )
                    http_redirect_status = response_http.status if response_http else "N/A"
                    http_final_url = http_page.url
                except Exception as exc:
                    http_navigation_error = str(exc)
                    http_final_url = http_page.url

                screenshot = ""
                if insecure_requests:
                    screenshot = str(EVIDENCE_DIR / f"SEC-01_{slug(url)}.png")
                    page.screenshot(path=screenshot, full_page=True)

                final_is_https = final_url.lower().startswith("https://")
                http_is_enforced = http_final_url.lower().startswith("https://") if http_final_url else False

                status = "PASS" if final_is_https and http_is_enforced and not insecure_requests else "FAIL"

                results.append({
                    "Page URL": url,
                    "HTTPS Final URL": final_url,
                    "HTTPS Navigation Status": response.status if response else "N/A",
                    "HTTP Test URL": http_variant(url),
                    "HTTP Test Status": http_redirect_status,
                    "HTTP Final URL": http_final_url,
                    "HTTP Navigation Error": http_navigation_error,
                    "HTTP->HTTPS Enforced": "Yes" if http_is_enforced else "No",
                    "Insecure HTTP Resources": len(insecure_requests),
                    "Mixed Content Console Messages": sum(
                        1 for item in page_console
                        if "mixed content" in item["Message"].lower()
                    ),
                    "Screenshot": screenshot,
                    "Status": status,
                })
                mixed.extend(insecure_requests)

            finally:
                page.close()
                http_page.close()

        context.close()
        browser.close()

    return {
        "results": results,
        "mixed": mixed,
        "console": console_messages,
    }


def main(show_browser: bool = False):
    from excel_utils import export_case
    export_case(
        "TC-SEC-01",
        "HTTPS Enforcement and Mixed Content",
        run(show_browser),
        REPORT_DIR / "TC-SEC-01_HTTPS_Mixed_Content.xlsx",
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-sv", "--show-browser", action="store_true")
    args = parser.parse_args()
    main(args.show_browser)
