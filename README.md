# Thaura Security Testing Automation

This folder automates the five basic, non-intrusive security checks for the 15 supplied public Thaura pages.

## Scope

1. TC-SEC-01 — HTTPS Enforcement and Mixed Content
2. TC-SEC-02 — Security Response Headers
3. TC-SEC-03 — Public Input Validation and Sanitization
4. TC-SEC-04 — Sensitive Information Exposure
5. TC-SEC-05 — Cookie Security Attributes

## Setup

From the project virtual environment:

```bash
pip install -r requirements.txt
playwright install chromium
```

## Run all security tests

Headless:

```bash
python run_security_tests.py
```

Visible browser:

```bash
python run_security_tests.py -sv
```

## Run one test

```bash
python tests/tc_sec_01_https_mixed_content.py -sv
python tests/tc_sec_02_security_headers.py -sv
python tests/tc_sec_03_input_validation.py -sv
python tests/tc_sec_04_sensitive_exposure.py -sv
python tests/tc_sec_05_cookie_security.py -sv
```

## Output

Reports are written to:

```text
reports/
```

The combined report is:

```text
reports/Thaura_Security_Testing_Combined_Report.xlsx
```

Screenshots/findings evidence go to:

```text
evidence/
```

## Important non-intrusive limitation

TC-SEC-03 fills public text inputs but deliberately does **not** submit forms. This avoids sending test payloads to a live service. Use the generated field list to perform a separate controlled manual submission on the Contact form when the assignment specifically requires server-side validation after submission.

TC-SEC-04 records only redacted context for potential sensitive-data matches. It does not intentionally expose or print secrets in the report.

TC-SEC-05 reports cookie attributes available in the browser context. Authentication cookies should be reviewed separately after a controlled login if the public pages do not establish an authenticated session.
