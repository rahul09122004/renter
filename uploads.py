"""
uploads.py — safe file upload handling.

Threats addressed
-----------------
* Malicious content behind a friendly extension (HTML/PHP/EXE renamed .png):
  content is sniffed; images are decoded with Pillow and re-encoded (which also
  strips EXIF/GPS metadata); PDFs must start with %PDF- and are screened for
  embedded JavaScript/launch actions.
* Decompression bombs: pixel-count cap + Pillow's bomb guard.
* Path traversal / overwrite / guessable names: the original filename is NEVER
  used. Files are stored as  <owner_id>/<uuid4hex>.<ext>.
* Public exposure: files live OUTSIDE ``static/`` and are only served through an
  authenticated route that checks the file belongs to the signed-in account.
* Resource abuse: per-file size caps, max files per request.
"""
import io
import logging
import os
import re
import shutil
import uuid

from PIL import Image, ImageOps, UnidentifiedImageError

from validators import ValidationError

logger = logging.getLogger(__name__)

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
DOC_EXTS = IMAGE_EXTS | {".pdf"}
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_PDF_BYTES = 10 * 1024 * 1024
MAX_PIXELS = 40_000_000
MAX_FILES_PER_REQUEST = 5

Image.MAX_IMAGE_PIXELS = MAX_PIXELS          # PIL raises DecompressionBombError above 2x

# Pillow format → canonical extension
_FORMAT_EXT = {"JPEG": ".jpg", "PNG": ".png", "WEBP": ".webp", "GIF": ".gif"}

# Keys we generate:  "<owner>/<32 hex>.<ext>"  or  "sb:<owner>/<32 hex>.<ext>"
KEY_RE = re.compile(r"^(?:sb:)?(\d{1,9})/[0-9a-f]{32}\.(?:jpg|png|webp|gif|pdf)$")
# Pre-hardening flat filenames still referenced by old rows.
LEGACY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")

_PDF_ACTIVE = re.compile(rb"/(?:JavaScript|JS|Launch|RichMedia|XFA)\b")


# ── locations ─────────────────────────────────────────────────────────────────
def upload_root(app):
    root = os.environ.get("UPLOAD_DIR") or os.path.join(app.instance_path, "uploads")
    os.makedirs(root, exist_ok=True)
    return root


def local_path(app, key):
    """Absolute path for a validated local key, or None. Guards traversal."""
    root = os.path.realpath(upload_root(app))
    rel = key.split(":", 1)[-1] if key.startswith("sb:") else key
    path = os.path.realpath(os.path.join(root, rel))
    if not path.startswith(root + os.sep):
        return None
    return path


# ── validation ────────────────────────────────────────────────────────────────
def _sniff_and_normalise(data, ext):
    """Return (clean_bytes, canonical_ext) or raise ValidationError."""
    if ext == ".pdf":
        if not data.startswith(b"%PDF-"):
            raise ValidationError("That file is not a valid PDF.")
        if _PDF_ACTIVE.search(data):
            raise ValidationError("PDFs containing scripts or launch actions are not allowed.")
        return data, ".pdf"

    try:
        probe = Image.open(io.BytesIO(data))
        fmt = probe.format
        probe.verify()                                   # structural check
        img = Image.open(io.BytesIO(data))               # verify() invalidates the handle
        if img.width * img.height > MAX_PIXELS:
            raise ValidationError("Image dimensions are too large.")
        if fmt not in _FORMAT_EXT:
            raise ValidationError("Unsupported image type.")
        canon = _FORMAT_EXT[fmt]
        if fmt == "GIF":                                 # keep animation; nothing to strip
            return data, canon
        img.load()
        img = ImageOps.exif_transpose(img)               # honour rotation before dropping EXIF
        out = io.BytesIO()
        if fmt == "JPEG":
            img.convert("RGB").save(out, "JPEG", quality=90, optimize=True)
        elif fmt == "PNG":
            img.save(out, "PNG", optimize=True)
        else:
            img.save(out, "WEBP", quality=90)
        return out.getvalue(), canon
    except ValidationError:
        raise
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, SyntaxError, ValueError):
        raise ValidationError("That file is not a valid image.")


def read_and_validate(file_storage, kinds="doc"):
    """Return (bytes, ext, content_type) for an uploaded FileStorage."""
    name = (file_storage.filename or "").strip()
    ext = os.path.splitext(name)[1].lower()
    allowed = DOC_EXTS if kinds == "doc" else IMAGE_EXTS
    if ext not in allowed:
        raise ValidationError("Unsupported file type. Allowed: "
                              + ", ".join(sorted(e.lstrip(".") for e in allowed)) + ".")
    cap = MAX_PDF_BYTES if ext == ".pdf" else MAX_IMAGE_BYTES
    data = file_storage.stream.read(cap + 1)
    if not data:
        raise ValidationError("The uploaded file is empty.")
    if len(data) > cap:
        raise ValidationError(f"File is too large (max {cap // (1024 * 1024)} MB).")
    clean, canon = _sniff_and_normalise(data, ext)
    ctype = {".jpg": "image/jpeg", ".png": "image/png", ".webp": "image/webp",
             ".gif": "image/gif", ".pdf": "application/pdf"}[canon]
    return clean, canon, ctype


# ── Supabase (optional, private bucket + signed URLs) ─────────────────────────
def _supabase():
    url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    key = os.environ.get("SUPABASE_KEY", "").strip()
    if not (url and key):
        return None
    from storage3 import create_client        # imported lazily
    headers = {"apiKey": key, "Authorization": f"Bearer {key}"}
    return url, create_client(f"{url}/storage/v1", headers, is_async=False)


def _bucket():
    return os.environ.get("SUPABASE_BUCKET") or "uploads"


def supabase_signed_url(key, expires=60):
    """Short-lived signed URL for an ``sb:`` key, or None."""
    try:
        sb = _supabase()
        if not sb:
            return None
        url, client = sb
        res = client.from_(_bucket()).create_signed_url(key[3:], expires)
        signed = res.get("signedURL") or res.get("signedUrl")
        if not signed:
            return None
        return signed if signed.startswith("http") else f"{url}/storage/v1{signed}"
    except Exception as ex:                                   # noqa: BLE001
        logger.error("Supabase signed URL failed: %s", type(ex).__name__)
        return None


# ── public API ────────────────────────────────────────────────────────────────
def store_upload(app, file_storage, owner_id, kinds="doc", keep_local=False):
    """Validate + persist. Returns (key, local_path_or_None).

    With Supabase configured the object goes to a PRIVATE bucket and the key is
    ``sb:<owner>/<uuid>.<ext>``; if that fails we fall back to local storage.
    """
    data, ext, ctype = read_and_validate(file_storage, kinds)
    rel = f"{int(owner_id)}/{uuid.uuid4().hex}{ext}"

    sb = None
    try:
        sb = _supabase()
    except Exception as ex:                                   # noqa: BLE001
        logger.error("Supabase client init failed: %s", type(ex).__name__)
    if sb:
        try:
            _url, client = sb
            client.from_(_bucket()).upload(rel, data, {"content-type": ctype})
            path = None
            if keep_local:                                    # OCR needs a local copy
                path = _write_local(app, rel, data)
            return f"sb:{rel}", path
        except Exception as ex:                               # noqa: BLE001
            logger.error("Supabase upload failed, using local storage: %s", type(ex).__name__)

    return rel, _write_local(app, rel, data)


def _write_local(app, rel, data):
    path = local_path(app, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)
    return path


def key_owner(key):
    m = KEY_RE.match(key or "")
    return int(m.group(1)) if m else None


def is_valid_key(key):
    return bool(key) and (bool(KEY_RE.match(key)) or bool(LEGACY_RE.match(key)))


def delete_stored(app, key):
    """Best-effort removal of the underlying file (local or Supabase)."""
    if not key or key.startswith("http"):
        return
    try:
        if key.startswith("sb:"):
            sb = _supabase()
            if sb:
                sb[1].from_(_bucket()).remove([key[3:]])
            return
        if is_valid_key(key):
            p = local_path(app, key)
            if p and os.path.isfile(p):
                os.remove(p)
    except Exception as ex:                                   # noqa: BLE001
        logger.warning("Could not delete stored file: %s", type(ex).__name__)


def migrate_legacy_uploads(app):
    """Move old files out of the public ``static/uploads`` folder (once).

    Legacy rows keep their flat filename; the authenticated file route serves
    them after checking a DB reference belongs to the requesting account.
    """
    old = os.path.join(app.root_path, "static", "uploads")
    if not os.path.isdir(old):
        return 0
    dest = upload_root(app)
    moved = 0
    for name in os.listdir(old):
        src = os.path.join(old, name)
        if name.startswith(".") or not os.path.isfile(src) or not LEGACY_RE.match(name):
            continue
        dst = os.path.join(dest, name)
        if not os.path.exists(dst):
            shutil.move(src, dst)
            os.chmod(dst, 0o600)
            moved += 1
    if moved:
        logger.warning("Moved %d legacy upload(s) out of the public static folder.", moved)
    return moved
