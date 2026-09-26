from __future__ import annotations

from typing import Any

from playwright.sync_api import sync_playwright

from common import PAGES, INPUT_PAYLOADS, REPORT_DIR, EVIDENCE_DIR, slug


def run(show_browser: bool = False) -> dict[str, Any]:
    results = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not show_browser)
        context = browser.new_context(viewport={"width": 1440, "height": 900})

        for url in PAGES:
            page = context.new_page()
            page_errors = []
            console_errors = []
            dialogs = []

            def on_page_error(error):
                page_errors.append(str(error))

            def on_console(message):
                if message.type == "error":
                    console_errors.append(message.text or "")

            def on_dialog(dialog):
                dialogs.append({
                    "type": dialog.type,
                    "message": dialog.message,
                })
                dialog.dismiss()

            page.on("pageerror", on_page_error)
            page.on("console", on_console)
            page.on("dialog", on_dialog)

            try:
                page.goto(url, wait_until="load", timeout=60000)
                page.wait_for_timeout(1000)

                fields = page.locator(
                    "input:not([type=hidden]):not([type=submit]):not([type=button]), textarea, [contenteditable='true']"
                )
                field_count = fields.count()

                if field_count == 0:
                    results.append({
                        "Page URL": url,
                        "Field Index": "N/A",
                        "Field Type": "N/A",
                        "Field Name": "N/A",
                        "Payload Type": "N/A",
                        "Payload Length": "N/A",
                        "Value Preserved": "N/A",
                        "Script Dialog Triggered": "No",
                        "Console Errors After Input": 0,
                        "Page Errors After Input": 0,
                        "Submission": "Not performed",
                        "Status": "N/A - No public text input found",
                    })
                    continue

                max_fields = min(field_count, 10)
                for index in range(max_fields):
                    field = fields.nth(index)
                    field_type = field.get_attribute("type") or "textarea/contenteditable"
                    field_name = (
                        field.get_attribute("name")
                        or field.get_attribute("id")
                        or field.get_attribute("placeholder")
                        or f"field_{index}"
                    )

                    for payload_no, payload in enumerate(INPUT_PAYLOADS, start=1):
                        before_dialogs = len(dialogs)
                        before_page_errors = len(page_errors)
                        before_console_errors = len(console_errors)

                        try:
                            field.fill(payload)
                            field.blur()
                            page.wait_for_timeout(250)
                        except Exception as exc:
                            results.append({
                                "Page URL": url,
                                "Field Index": index,
                                "Field Type": field_type,
                                "Field Name": field_name,
                                "Payload Type": f"payload_{payload_no}",
                                "Payload Length": len(payload),
                                "Value Preserved": "No - fill failed",
                                "Script Dialog Triggered": "No",
                                "Console Errors After Input": max(0, len(console_errors) - before_console_errors),
                                "Page Errors After Input": max(0, len(page_errors) - before_page_errors),
                                "Submission": "Not performed",
                                "Error": str(exc),
                                "Status": "FAIL",
                            })
                            continue

                        try:
                            value = field.input_value(timeout=1000)
                        except Exception:
                            value = ""

                        dialog_triggered = len(dialogs) > before_dialogs
                        new_page_errors = max(0, len(page_errors) - before_page_errors)
                        new_console_errors = max(0, len(console_errors) - before_console_errors)

                        try:
                            script_count = page.locator("script").count()
                        except Exception:
                            script_count = "N/A"

                        screenshot = ""
                        if dialog_triggered or new_page_errors or new_console_errors:
                            screenshot = str(
                                EVIDENCE_DIR
                                / f"SEC-03_{slug(url)}_field{index}_payload{payload_no}.png"
                            )
                            page.screenshot(path=screenshot, full_page=True)

                        status = "FAIL" if dialog_triggered or new_page_errors else "PASS"

                        results.append({
                            "Page URL": url,
                            "Field Index": index,
                            "Field Type": field_type,
                            "Field Name": field_name,
                            "Payload Type": f"payload_{payload_no}",
                            "Payload Length": len(payload),
                            "Value Preserved": "Yes" if value == payload else "No/Transformed",
                            "Script Dialog Triggered": "Yes" if dialog_triggered else "No",
                            "Console Errors After Input": new_console_errors,
                            "Page Errors After Input": new_page_errors,
                            "Script Element Count": script_count,
                            "Submission": "Not performed (non-intrusive)",
                            "Evidence Screenshot": screenshot,
                            "Status": status,
                        })

            except Exception as exc:
                results.append({
                    "Page URL": url,
                    "Field Index": "N/A",
                    "Field Type": "N/A",
                    "Field Name": "N/A",
                    "Payload Type": "N/A",
                    "Payload Length": "N/A",
                    "Value Preserved": "N/A",
                    "Script Dialog Triggered": "No",
                    "Console Errors After Input": len(console_errors),
                    "Page Errors After Input": len(page_errors),
                    "Submission": "Not performed",
                    "Error": str(exc),
                    "Status": "FAIL",
                })
            finally:
                page.close()

        context.close()
        browser.close()

    return {"results": results}


def main(show_browser: bool = False):
    from excel_utils import export_case
    export_case(
        "TC-SEC-03",
        "Public Input Validation and Sanitization",
        run(show_browser),
        REPORT_DIR / "TC-SEC-03_Input_Validation.xlsx",
    )


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-sv", "--show-browser", action="store_true")
    args = parser.parse_args()
    main(args.show_browser)
