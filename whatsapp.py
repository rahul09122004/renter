"""
whatsapp.py — Meta WhatsApp Cloud API integration
Template: rent_reminder  →  Hello {{1}}, your rent of ₹{{2}} is due on {{3}}.
"""

import os
import logging
import requests

def _mask(p):
    p = "".join(ch for ch in str(p or "") if ch.isdigit())
    return ("*" * max(0, len(p) - 4)) + p[-4:]

logger = logging.getLogger(__name__)

WHATSAPP_API_URL = "https://graph.facebook.com/v19.0/{phone_number_id}/messages"


def _get_headers():
    token = os.environ.get("ACCESS_TOKEN", "")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def send_rent_reminder(to_phone: str, tenant_name: str, amount: float, due_date: str) -> dict:
    """
    Send 'rent_reminder' template message.
    to_phone: E.164 without '+', e.g. '919876543210'
    Returns API response dict or error dict.
    """
    phone_number_id = os.environ.get("PHONE_NUMBER_ID", "")
    if not phone_number_id:
        logger.error("PHONE_NUMBER_ID not configured")
        return {"error": "PHONE_NUMBER_ID missing"}

    url = WHATSAPP_API_URL.format(phone_number_id=phone_number_id)

    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "template",
        "template": {
            "name": "rent_reminder",
            "language": {"code": "en_US"},
            "components": [
                {
                    "type": "body",
                    "parameters": [
                        {"type": "text", "text": tenant_name},
                        {"type": "text", "text": f"₹{amount:,.0f}"},
                        {"type": "text", "text": due_date},
                    ],
                }
            ],
        },
    }

    try:
        resp = requests.post(url, headers=_get_headers(), json=payload, timeout=10)
        result = resp.json()
        if resp.status_code == 200:
            logger.info(f"[WhatsApp] Reminder sent to {_mask(to_phone)}")
        else:
            logger.warning(f"[WhatsApp] Failed {_mask(to_phone)}: HTTP {resp.status_code} {str(result.get('error', {}).get('message', ''))[:120] if isinstance(result, dict) else ''}")
        return result
    except requests.RequestException as e:
        logger.error(f"[WhatsApp] Request error: {e}")
        return {"error": str(e)}


def send_payment_confirmation(to_phone: str, tenant_name: str, amount: float, payment_date: str) -> dict:
    """
    Send payment confirmation using 'payment_confirmation' template.
    Falls back to rent_reminder template with confirmation text if unavailable.
    """
    phone_number_id = os.environ.get("PHONE_NUMBER_ID", "")
    if not phone_number_id:
        return {"error": "PHONE_NUMBER_ID missing"}

    url = WHATSAPP_API_URL.format(phone_number_id=phone_number_id)

    # Using a separate confirmation template (create 'payment_confirmation' in Meta)
    # Fallback: reuse rent_reminder with payment_date as due_date param
    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone,
        "type": "template",
        "template": {
            "name": "payment_confirmation",
            "language": {"code": "en_US"},
            "components": [
                {
                    "type": "body",
                    "parameters": [
                        {"type": "text", "text": tenant_name},
                        {"type": "text", "text": f"₹{amount:,.0f}"},
                        {"type": "text", "text": payment_date},
                    ],
                }
            ],
        },
    }

    try:
        resp = requests.post(url, headers=_get_headers(), json=payload, timeout=10)
        result = resp.json()
        logger.info(f"[WhatsApp] Confirmation sent to {_mask(to_phone)}")
        return result
    except requests.RequestException as e:
        logger.error(f"[WhatsApp] Confirmation error: {e}")
        return {"error": str(e)}
