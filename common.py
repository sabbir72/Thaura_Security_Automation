from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
EVIDENCE_DIR = BASE_DIR / "evidence"
REPORT_DIR.mkdir(exist_ok=True)
EVIDENCE_DIR.mkdir(exist_ok=True)

PAGES = [
    "https://thaura.ai/home",
    "https://thaura.ai/story",
    "https://thaura.ai/constitution",
    "https://thaura.ai/pricing",
    "https://thaura.ai/community",
    "https://thaura.ai/contact",
    "https://thaura.ai/careers",
    "https://thaura.ai/faq",
    "https://thaura.ai/api-platform",
    "https://thaura.ai/donate",
    "https://thaura.ai/download",
    "https://thaura.ai/terms-of-service",
    "https://thaura.ai/privacy-policy",
    "https://thaura.ai/data-processing-addendum",
    "https://thaura.ai/imprint",
]

INPUT_PAYLOADS = [
    "A" * 1024,
    "<script>alert('SEC_TEST')</script>",
    "<img src=x onerror=alert('SEC_TEST')>",
    "' \" < > & / \\ | = + %",
    "বাংলা পরীক্ষা مرحبا שלום 👋",
]

SENSITIVE_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I)),
    ("api_key", re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]", re.I)),
    ("secret", re.compile(r"(?:secret|client_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I)),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}", re.I)),
    ("jwt_like", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("openai_like_key", re.compile(r"sk-[A-Za-z0-9_-]{20,}", re.I)),
    ("internal_localhost", re.compile(r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?", re.I)),
    ("stack_trace", re.compile(r"(?:Traceback \(most recent call last\)|at [A-Za-z0-9_$<>.]+\([^)]*\)|Exception in thread)", re.I)),
]


def slug(url: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", "_", url.rstrip("/").split("//", 1)[-1])
    return value.strip("_")[:100] or "page"


def redact(value: str, max_len: int = 260) -> str:
    if not value:
        return ""
    value = re.sub(r"(Authorization\s*:\s*Bearer\s+)[^\s,]+", r"\1[REDACTED]", value, flags=re.I)
    value = re.sub(r"(api[_-]?key\s*[:=]\s*)['\"]?[^,'\"\s]+", r"\1[REDACTED]", value, flags=re.I)
    value = re.sub(r"(secret\s*[:=]\s*)['\"]?[^,'\"\s]+", r"\1[REDACTED]", value, flags=re.I)
    return value[:max_len]


def text_like(content_type: str) -> bool:
    value = (content_type or "").lower()
    return any(token in value for token in (
        "text/", "application/json", "application/javascript", "text/javascript",
        "application/xml", "application/xhtml+xml", "application/graphql-response+json"
    ))


def contains_any(value: str, terms: Iterable[str]) -> bool:
    lowered = value.lower()
    return any(term.lower() in lowered for term in terms)
