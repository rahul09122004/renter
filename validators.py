"""
validators.py — strict server-side input validation.

Design rules
------------
* Every value that arrives from a form, query string, URL or spreadsheet is
  untrusted. It is parsed here into a typed, range-checked Python value or the
  request is rejected with a ``ValidationError`` carrying a *user-safe* message.
* We REJECT bad input rather than "fixing" it silently (except for harmless
  normalisation such as trimming whitespace / stripping control characters).
* Validation is defence in depth. The primary XSS control is still output
  encoding (Jinja autoescape / ``|tojson``) and the primary SQL-injection
  control is the ORM's bound parameters — never string-built SQL.
"""
import re
import unicodedata
from datetime import date, datetime


class ValidationError(ValueError):
    """Raised for invalid user input. ``str(exc)`` is safe to show to the user."""


# ── Character-level hygiene ───────────────────────────────────────────────────
# C0 control characters except TAB (\x09), LF (\x0a), CR (\x0d); plus DEL.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Unicode bidirectional override/isolate characters — used for "Trojan Source"
# style spoofing of names/descriptions in tables and exports.
_BIDI_CHARS = re.compile(r"[\u202a-\u202e\u2066-\u2069\u200e\u200f]")
_MARKUP_CHARS = re.compile(r"[<>]")


def clean_text(value, field="Value", max_len=200, required=False,
               multiline=False, allow_markup=False, min_len=0):
    """Return a normalised string or raise ``ValidationError``.

    * Must be ``str`` (or ``None`` → empty string).
    * NFC-normalised, NUL/control/bidi characters removed, trimmed.
    * Single-line fields have tabs/newlines collapsed to a space.
    * ``<`` and ``>`` are rejected in single-line fields (names, units, IDs,
      categories …) where they are never legitimate. Free-text ``multiline``
      notes may contain them; they are always HTML-escaped on output.
    * Length is *rejected*, not truncated, so users notice.
    """
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text.")
    v = unicodedata.normalize("NFC", value)
    v = _CONTROL_CHARS.sub("", v)
    v = _BIDI_CHARS.sub("", v)
    if multiline:
        v = v.replace("\r\n", "\n").replace("\r", "\n")
    else:
        v = re.sub(r"[\t\r\n]+", " ", v)
    v = v.strip()
    if required and not v:
        raise ValidationError(f"{field} is required.")
    if v and len(v) < min_len:
        raise ValidationError(f"{field} must be at least {min_len} characters.")
    if len(v) > max_len:
        raise ValidationError(f"{field} must be at most {max_len} characters.")
    if not multiline and not allow_markup and _MARKUP_CHARS.search(v):
        raise ValidationError(f"{field} must not contain '<' or '>'.")
    return v


# ── Numbers ───────────────────────────────────────────────────────────────────
# Strict ASCII grammar. This deliberately rejects "nan", "inf", "1e300",
# exotic Unicode digits and anything float()/Decimal() would otherwise accept.
_MONEY_RE = re.compile(r"^[0-9]{1,12}(?:\.[0-9]{1,2})?$")
_INT_RE = re.compile(r"^[0-9]{1,12}$")


def parse_money(value, field="Amount", min_value=0.0, max_value=100_000_000.0,
                allow_blank=False, default=None):
    """Parse a rupee amount such as '18,000', '₹ 1,250.50' or '500'."""
    if value is None:
        value = ""
    if not isinstance(value, str):
        value = str(value)
    s = value.replace(",", "").replace("₹", "").strip()
    if s == "":
        if allow_blank:
            return default
        raise ValidationError(f"{field} is required.")
    if not _MONEY_RE.match(s):
        raise ValidationError(f"{field} must be a valid amount (digits, optional decimals).")
    amount = round(float(s), 2)
    if amount < min_value or amount > max_value:
        raise ValidationError(
            f"{field} must be between {min_value:,.0f} and {max_value:,.0f}.")
    return amount


def parse_int(value, field="Number", lo=0, hi=10_000, allow_blank=False, default=None):
    if value is None:
        value = ""
    s = str(value).strip()
    if s == "":
        if allow_blank:
            return default
        raise ValidationError(f"{field} is required.")
    if not _INT_RE.match(s):
        raise ValidationError(f"{field} must be a whole number.")
    n = int(s)
    if n < lo or n > hi:
        raise ValidationError(f"{field} must be between {lo} and {hi}.")
    return n


def parse_month_year(month, year, field="Month/Year"):
    m = parse_int(month, "Month", 1, 12)
    y = parse_int(year, "Year", 2000, 2100)
    return m, y


# ── Dates ─────────────────────────────────────────────────────────────────────
def parse_date(value, field="Date", required=False, min_year=2000, max_year=2100):
    if value is None or str(value).strip() == "":
        if required:
            raise ValidationError(f"{field} is required.")
        return None
    s = str(value).strip()
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", s):
        raise ValidationError(f"{field} must be a date in YYYY-MM-DD format.")
    try:
        d = datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        raise ValidationError(f"{field} is not a real calendar date.")
    if d.year < min_year or d.year > max_year:
        raise ValidationError(f"{field} must be between {min_year} and {max_year}.")
    return d


# ── Enumerations ──────────────────────────────────────────────────────────────
def choice(value, allowed, field="Value", default=None):
    """Value must be one of ``allowed`` (case-insensitive). Blank → ``default``."""
    if value is None or str(value).strip() == "":
        if default is not None:
            return default
        raise ValidationError(f"{field} is required.")
    s = str(value).strip()
    for a in allowed:
        if s.lower() == str(a).lower():
            return a
    raise ValidationError(f"{field} has an invalid value.")


# ── Identity-like fields ──────────────────────────────────────────────────────
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()\-]{5,24}$")
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")


def clean_phone(value, field="Phone", required=True):
    s = clean_text(value, field, max_len=25, required=required)
    if not s:
        return ""
    if not _PHONE_RE.match(s):
        raise ValidationError(f"{field} may only contain digits, spaces, +, - and brackets.")
    digits = re.sub(r"\D", "", s)
    if not 8 <= len(digits) <= 15:
        raise ValidationError(f"{field} must have 8–15 digits (include the country code).")
    return digits


def clean_email(value, field="Email", required=False):
    s = clean_text(value, field, max_len=120, required=required)
    if not s:
        return ""
    if not _EMAIL_RE.match(s):
        raise ValidationError(f"{field} is not a valid email address.")
    return s


def clean_username(value, field="Username"):
    s = clean_text(value, field, max_len=40, required=True).lower()
    if not USERNAME_RE.match(s):
        raise ValidationError(
            f"{field} must be 3–40 characters: lowercase letters, numbers, dot, dash or "
            "underscore, starting with a letter or number.")
    return s


# ── Passwords ─────────────────────────────────────────────────────────────────
PASSWORD_MIN = 10
PASSWORD_MAX = 128          # cap so an attacker can't make us hash megabytes
_COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "123456", "1234567",
    "12345678", "123456789", "1234567890", "0123456789", "qwerty", "qwerty123",
    "qwertyuiop", "abc123", "abcd1234", "iloveyou", "admin", "admin123",
    "administrator", "letmein", "welcome", "welcome1", "monkey", "dragon",
    "football", "baseball", "sunshine", "princess", "master", "login",
    "changeme", "change-me", "secret", "default", "test1234", "rentmanager",
    "rent1234", "india123", "india@123", "pass@123", "pass1234", "p@ssw0rd",
    "admin@123", "admin1234", "root", "toor", "guest", "111111", "000000",
    "1q2w3e4r", "zaq12wsx", "qazwsxedc", "asdfghjkl", "zxcvbnm",
}


def check_password_strength(password, username="", email=""):
    """Return an error string, or ``None`` if the password is acceptable.

    Follows NIST SP 800-63B: length matters more than composition rules; block
    known-bad and context-specific passwords.
    """
    if not isinstance(password, str):
        return "Password is required."
    if len(password) < PASSWORD_MIN:
        return f"Password must be at least {PASSWORD_MIN} characters."
    if len(password) > PASSWORD_MAX:
        return f"Password must be at most {PASSWORD_MAX} characters."
    if "\x00" in password:
        return "Password contains invalid characters."
    low = password.lower()
    if low in _COMMON_PASSWORDS:
        return "That password is too common. Choose something less guessable."
    if len(set(password)) < 5:
        return "Password is too repetitive. Use a longer passphrase."
    if username and (low == username.lower() or username.lower() in low and len(username) >= 5):
        return "Password must not contain your username."
    if email:
        local = email.split("@")[0].lower()
        if len(local) >= 4 and local in low:
            return "Password must not contain your email name."
    return None


# ── Spreadsheet cell helpers ──────────────────────────────────────────────────
_FORMULA_PREFIX = ("=", "+", "-", "@", "\t", "\r", "\n")


def excel_safe(value):
    """Neutralise spreadsheet formula injection (CSV/Excel injection).

    A cell that starts with = + - @ is treated as a formula by Excel/LibreOffice
    when a file is opened. Prefixing an apostrophe makes it plain text.
    Only ``str`` values are touched; numbers/dates pass through unchanged.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIX):
        return "'" + value
    return value


def as_date(v):
    """date/datetime → date (used by the importer)."""
    if isinstance(v, datetime):
        return v.date()
    if isinstance(v, date):
        return v
    return None
