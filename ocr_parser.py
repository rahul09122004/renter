import re
import os
import logging
import requests
import base64
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Amount patterns (STRICT ₹ priority) ───────────────────────────────────────
AMOUNT_PATTERNS_HIGH = [
    r'₹\s*([1-9][0-9]{0,2}(?:,[0-9]{2,3})+(?:\.\d{1,2})?)',
    r'₹\s*([1-9][0-9]{2,7}(?:\.\d{1,2})?)',
]

AMOUNT_PATTERNS_LOW = [
    r'\b([1-9][0-9]{4,6})\b',
]

# ── TXN ID patterns ───────────────────────────────────────────────────────────
TXN_PATTERNS = [
    r'(?:Transaction\s*ID|Txn\s*ID|Txn\s*No|Txn)[\s:\-#]*([A-Z0-9]{10,30})',
    r'(?:UTR|UTR\s*No|UTR\s*Number)[\s:\-]*([0-9]{10,22})',
    r'(?:UPI\s*(?:Ref|Reference|Txn))[\s:\-#]*([A-Z0-9]{8,24})',
    r'(?:Ref(?:erence)?(?:\s*No\.?|ID)?)[\s:\-#]*([A-Z0-9]{8,24})',
    r'\b(T[0-9]{15,24})\b',
    r'\b([0-9]{12})\b',
]

# ── OCR.space ─────────────────────────────────────────────────────────────────
def _extract_with_ocrspace(image_path: str) -> str:
    try:
        api_key = os.getenv("OCRSPACE_API_KEY", "helloworld")

        ext = Path(image_path).suffix.lower()
        mime = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".webp": "image/webp",
        }.get(ext, "image/jpeg")

        with open(image_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("utf-8")

        resp = requests.post(
            "https://api.ocr.space/parse/image",
            data={
                "base64Image": f"data:{mime};base64,{b64}",
                "apikey": api_key,
                "language": "eng",
                "OCREngine": 2,
                "scale": True,
            },
            timeout=30,
        )

        result = resp.json()

        if result.get("IsErroredOnProcessing"):
            logger.warning(f"[OCR.space] Error: {result.get('ErrorMessage')}")
            return ""

        text = (result.get("ParsedResults") or [{}])[0].get("ParsedText", "")
        logger.info(f"[OCR.space] text[:200]: {text[:200]}")
        return text

    except Exception as e:
        logger.warning(f"[OCR.space] Failed: {e}")
        return ""


# ── Extract text ──────────────────────────────────────────────────────────────
def _extract_text(image_path: str):
    text = _extract_with_ocrspace(image_path)
    if text and len(text.strip()) > 5:
        return text, "ocrspace"
    return "", "failed"


# ── Amount extraction ─────────────────────────────────────────────────────────
def _collect(text: str, patterns: list, expected: float) -> list:
    out = []
    for pat in patterns:
        for m in re.findall(pat, text, re.IGNORECASE):
            try:
                v = float(str(m).replace(",", ""))

                if 100 <= v <= 999999:

                    # ❌ Remove year-like values
                    if 2000 <= v <= 2035:
                        continue

                    # ❌ Remove garbage OCR values (like 219300)
                    if expected > 0 and v > expected * 5:
                        continue

                    out.append(v)

            except Exception:
                continue
    return out


def _best_amount(candidates: list, expected: float) -> float | None:
    if not candidates:
        return None

    unique = list(set(candidates))

    return min(
        unique,
        key=lambda v: (abs(v - expected), -v)
    )


# ── TXN extraction ────────────────────────────────────────────────────────────
def _extract_txn(text: str) -> str | None:
    for pat in TXN_PATTERNS:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            val = m.group(1)

            # ❌ Ignore phone numbers
            if re.fullmatch(r'[6-9][0-9]{9}', val):
                continue

            # ❌ Ignore small numbers
            if val.isdigit() and len(val) < 10:
                continue

            return val
    return None


# ── Parser ────────────────────────────────────────────────────────────────────
def _parse(text: str, expected: float, manual_txn: str = "") -> dict:

    cleaned = text.replace("\r\n", "\n")

    # 🔥 FIX WRONG OCR SYMBOLS
    cleaned = cleaned.replace("₴", "₹")
    cleaned = cleaned.replace("?", "₹")
    cleaned = cleaned.replace("Rs.", "₹")
    # NEW FIXES 🔥
    cleaned = cleaned.replace("·", "₹")   # case: ·30,302
    cleaned = re.sub(r'\bR(?=\d)', '₹', cleaned)  # case: R233 → ₹233

    # 🔥 PRIORITY: ₹ matches first
    high = _collect(cleaned, AMOUNT_PATTERNS_HIGH, expected)

    if high:
        amount = _best_amount(high, expected)
    else:
        low = _collect(cleaned, AMOUNT_PATTERNS_LOW, expected)
        amount = _best_amount(low, expected)

    txn = _extract_txn(cleaned) or manual_txn or None

    logger.info(f"[Parser] amount={amount} txn={txn}")

    return {
        "amount": amount,
        "txn_id": txn,
        "raw_text": cleaned[:600]
    }


# ── Public API ────────────────────────────────────────────────────────────────
def parse_payment_screenshot(
    image_path: str, expected_amount: float, manual_txn: str = ""
) -> dict:

    raw_text, method = _extract_text(image_path)

    if raw_text.strip():
        parsed = _parse(raw_text, expected_amount, manual_txn)
    else:
        parsed = {
            "amount": None,
            "txn_id": manual_txn or None,
            "raw_text": ""
        }

    amt = parsed.get("amount")

    return {
        "amount": amt,
        "txn_id": parsed.get("txn_id"),
        "method": method,
        "raw_text": parsed.get("raw_text", ""),
        "matched": bool(amt and amt >= expected_amount * 0.95),
        "partial": bool(amt and 0 < amt < expected_amount * 0.95),
    }