from __future__ import annotations

from typing import Any

from playwright.sync_api import sync_playwright

from common import PAGES, REPORT_DIR

AUTH_COOKIE_TERMS = (
    "session", "sess", "auth", "token", "jwt", "access", "refresh", "sid"
)


def run(show_browser: bool = False) -> dict[str, Any]:
    rows = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not show_browser)
        context = browser.new_context(viewport={"width": 1440, "height": 900})

        for url in PAGES:
            page = context.new_page()
            try:
                page.goto(url, wait_until="load", timeout=60000)
                page.wait_for_timeout(1500)

                cookies = context.cookies([url])

                if not cookies:
                    rows.append({
                        "Page URL": url,
                        "Cookie Name": "N/A",
                        "Domain": "N/A",
                        "Secure": "N/A",
                        "HttpOnly": "N/A",
                        "SameSite": "N/A",
                        "Auth-Looking": "N/A",
                        "Cookie Assessment": "No cookies set",
                        "Status": "PASS",
                    })
                    continue

                for cookie in cookies:
                    name = cookie.get("name", "")
                    auth_looking = any(
                        term in name.lower()
                        for term in AUTH_COOKIE_TERMS
                    )

                    secure = bool(cookie.get("secure"))
                    httponly = bool(cookie.get("httpOnly"))
                    samesite = cookie.get("sameSite") or ""

                    review_reasons = []
                    if not secure:
                        review_reasons.append("Secure=false")
                    if auth_looking and not httponly:
                        review_reasons.append("auth-looking cookie without HttpOnly")
                    if not samesite:
                        review_reasons.append("SameSite not set")
                    elif samesite.lower() == "none" and not secure:
                        review_reasons.append("SameSite=None without Secure")

                    status = "FAIL" if any([
                        not secure,
                        auth_looking and not httponly,
                        samesite.lower() == "none" and not secure,
                    ]) else "PASS"

                    rows.append({
                        "Page URL": url,
                        "Cookie Name": name,
                        "Domain": cookie.get("domain", ""),
                        "Path": cookie.get("path", ""),
                        "Secure": "Yes" if secure else "No",
                        "HttpOnly": "Yes" if httponly else "No",
                        "SameSite": samesite or "Not set",
                        "Auth-Looking": "Yes" if auth_looking else "No",
                        "Cookie Assessment": "; ".join(review_reasons) or "No immediate flag",
                        "Status": status,
                    })
            except Exception as exc:
                rows.append({
                    "Page URL": url,
                    "Cookie Name": "N/A",
                    "Domain": "N/A",
                    "Secure": "N/A",
                    "HttpOnly": "N/A",
                    "SameSite": "N/A",
                    "Auth-Looking": "N/A",
                    "Cookie Assessment": str(exc),
                    "Status": "FAIL",
                })
            finally:
                page.close()

        context.close()
        browser.close()

    return {"results": rows}


def main(show_browser: bool = False):
    from excel_utils import export_case
    export_case(
        "TC-SEC-05",
        "Cookie Security Attributes",
        run(show_browser),
        REPORT_DIR / "TC-SEC-05_Cookie_Security.xlsx",
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-sv", "--show-browser", action="store_true")
    args = parser.parse_args()
    main(args.show_browser)
