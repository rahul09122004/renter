"""File-upload hardening and private file serving."""
import io
import os
import zlib

import pytest
from PIL import Image

from conftest import *  # noqa
from conftest import flask_app
import uploads
from models import Admin, BuildingExpense, RentRecord, Tenant, db, unscoped

UPLOAD_DIR = os.environ["UPLOAD_DIR"]


def png_bytes(size=(20, 20), color="red"):
    b = io.BytesIO()
    Image.new("RGB", size, color).save(b, "PNG")
    return b.getvalue()


def jpeg_with_exif():
    img = Image.new("RGB", (30, 30), "blue")
    exif = Image.Exif()
    exif[0x010F] = "SecretCameraMaker"          # Make
    exif[0x8825] = {1: "N", 2: (12.0, 34.0, 56.0)}   # GPS IFD
    b = io.BytesIO()
    img.save(b, "JPEG", exif=exif)
    return b.getvalue()


def upload_photo(c, name, data, filename="me.png", field="photo", **extra):
    payload = {"name": name, "phone": "919876500001", "amount": "1000", "due_day": "5", "unit": "A",
               field: (io.BytesIO(data), filename)}
    payload.update(extra)
    return post(c, "/renters/add", payload, content_type="multipart/form-data")


def tenant_row(name):
    with flask_app.app_context():
        return unscoped(Tenant.query).filter_by(name=name).first()


def uid_of(username):
    with flask_app.app_context():
        return unscoped(Admin.query).filter_by(username=username).first().id


# ── acceptance / rejection ───────────────────────────────────────────────────
def test_valid_image_is_stored_privately_with_random_name():
    c, u = logged_in_client()
    name = unique("Img")
    assert upload_photo(c, name, png_bytes(), "my holiday photo.png").status_code == 302
    key = tenant_row(name).photo_path
    assert uploads.KEY_RE.match(key) and key.startswith(f"{uid_of(u)}/")
    assert "holiday" not in key                                    # original name never used
    assert os.path.isfile(os.path.join(UPLOAD_DIR, key))
    static_dir = os.path.join(flask_app.root_path, "static", "uploads")
    assert [f for f in os.listdir(static_dir) if f != ".gitkeep"] == []   # nothing under public /static


@pytest.mark.parametrize("filename,data", [
    ("evil.png", b"<html><script>alert(1)</script></html>"),
    ("evil.jpg", b"GIF89a<?php system($_GET[0]); ?>"),
    ("shell.php", png_bytes()), ("page.html", png_bytes()), ("vector.svg", b"<svg onload=alert(1)>"),
    ("run.exe", b"MZ\x90\x00"), ("noext", png_bytes()), ("double.png.php", png_bytes()),
    ("empty.png", b""), ("trunc.png", png_bytes()[:40]),
])
def test_disguised_or_disallowed_files_are_rejected(filename, data):
    c, u = logged_in_client()
    name = unique("Rej")
    r = upload_photo(c, name, data, filename)
    assert r.status_code == 200 and tenant_row(name) is None
    assert not os.path.isdir(os.path.join(UPLOAD_DIR, str(uid_of(u)))) or os.listdir(os.path.join(UPLOAD_DIR, str(uid_of(u)))) == []


def test_oversized_image_rejected():
    c, u = logged_in_client()
    name = unique("Big")
    big = b"\x89PNG\r\n\x1a\n" + b"0" * (uploads.MAX_IMAGE_BYTES + 10)
    r = upload_photo(c, name, big, "big.png")
    assert tenant_row(name) is None and b"too large" in r.data


def test_decompression_bomb_dimensions_rejected():
    c, u = logged_in_client()
    name = unique("Bomb")
    img = Image.new("1", (8000, 8000))                             # 64 MP, tiny on disk
    b = io.BytesIO(); img.save(b, "PNG")
    assert len(b.getvalue()) < uploads.MAX_IMAGE_BYTES
    r = upload_photo(c, name, b.getvalue(), "bomb.png")
    assert tenant_row(name) is None


def test_exif_metadata_including_gps_is_stripped():
    c, u = logged_in_client()
    name = unique("Exif")
    original = jpeg_with_exif()
    assert Image.open(io.BytesIO(original)).getexif().get(0x010F) == "SecretCameraMaker"
    upload_photo(c, name, original, "cam.jpg")
    key = tenant_row(name).photo_path
    stored = Image.open(os.path.join(UPLOAD_DIR, key))
    assert dict(stored.getexif()) == {} and b"SecretCameraMaker" not in open(os.path.join(UPLOAD_DIR, key), "rb").read()


def test_wrong_extension_is_corrected_to_real_format():
    c, u = logged_in_client()
    name = unique("Ext")
    upload_photo(c, name, png_bytes(), "actually_png.jpg")
    assert tenant_row(name).photo_path.endswith(".png")


def test_pdf_agreement_rules():
    c, u = logged_in_client()
    ok = unique("Pdf")
    good = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
    assert upload_photo(c, ok, good, "lease.pdf", field="agreement").status_code == 302
    assert tenant_row(ok).agreement_path.endswith(".pdf")
    for label, data in (("js", b"%PDF-1.4\n<< /S /JavaScript /JS (app.alert(1)) >>"),
                        ("launch", b"%PDF-1.4\n<< /S /Launch /F (cmd.exe) >>"),
                        ("fake", b"<html>not a pdf</html>")):
        n = unique("Pdf" + label)
        upload_photo(c, n, data, "x.pdf", field="agreement")
        assert tenant_row(n) is None, label


def test_photo_field_rejects_pdf_but_agreement_accepts_image():
    c, u = logged_in_client()
    n1, n2 = unique("P"), unique("A")
    upload_photo(c, n1, b"%PDF-1.4 x", "x.pdf", field="photo")
    assert tenant_row(n1) is None
    upload_photo(c, n2, png_bytes(), "x.png", field="agreement")
    assert tenant_row(n2) is not None


def test_too_many_screenshots_rejected():
    c, u = logged_in_client()
    name = unique("Shots")
    add_tenant(c, name=name)
    tid = tenant_row(name).id
    files = [(io.BytesIO(png_bytes()), f"s{i}.png") for i in range(uploads.MAX_FILES_PER_REQUEST + 1)]
    r = post(c, f"/tenant/verify-payment/{tid}", {"method": "screenshot", "screenshot": files},
             content_type="multipart/form-data")
    assert r.status_code == 400


# ── authenticated, ownership-checked downloads ───────────────────────────────
def _uploaded_key(c, prefix="Own"):
    name = unique(prefix)
    upload_photo(c, name, png_bytes(), "p.png")
    return name, tenant_row(name).photo_path


def test_owner_can_download_with_safe_headers():
    c, u = logged_in_client()
    _, key = _uploaded_key(c)
    r = c.get(f"/files/{key}")
    assert r.status_code == 200 and r.mimetype == "image/png"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert "private" in r.headers["Cache-Control"]
    assert r.data.startswith(b"\x89PNG")


def test_anonymous_and_other_accounts_cannot_download():
    c, u = logged_in_client()
    _, key = _uploaded_key(c)
    anon = flask_app.test_client()
    r = anon.get(f"/files/{key}")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    other, _ = logged_in_client()
    assert other.get(f"/files/{key}").status_code == 404           # not 403: existence isn't confirmed


def test_static_uploads_route_no_longer_serves_files():
    c, u = logged_in_client()
    _, key = _uploaded_key(c)
    for path in ("/static/uploads/" + key, "/static/uploads/" + key.split("/")[-1], "/static/uploads/"):
        assert c.get(path).status_code == 404


@pytest.mark.parametrize("key", ["../../etc/passwd", "..%2f..%2fetc%2fpasswd", "1/../../../etc/passwd",
                                 "%2e%2e/%2e%2e/etc/passwd", "/etc/passwd", "1/abc.png", "x.php", ".env",
                                 "1/" + "a" * 32 + ".php", "sb:../x", "....//....//etc/passwd"])
def test_path_traversal_and_bad_keys_are_rejected(key):
    c, _ = logged_in_client()
    assert c.get("/files/" + key, follow_redirects=True).status_code == 404


def test_key_validation_unit():
    assert uploads.is_valid_key("12/" + "a" * 32 + ".png") and uploads.is_valid_key("sb:12/" + "b" * 32 + ".pdf")
    assert uploads.is_valid_key("20260101_photo.jpg")                # legacy flat name
    for bad in ("", "../x", "a/../b", "a b", "x" * 300, "1/" + "g" * 32 + ".png", "\x00.png"):
        assert not uploads.is_valid_key(bad)
    assert uploads.local_path(flask_app, "../../etc/passwd") is None


def test_legacy_flat_files_served_only_to_the_referencing_account():
    c, u = logged_in_client()
    other, _ = logged_in_client()
    legacy = f"{unique('legacy')}_photo.png"
    with open(os.path.join(UPLOAD_DIR, legacy), "wb") as fh:
        fh.write(png_bytes())
    orphan = f"{unique('orphan')}_photo.png"
    with open(os.path.join(UPLOAD_DIR, orphan), "wb") as fh:
        fh.write(png_bytes())
    with flask_app.app_context():
        db.session.add(Tenant(name=unique("Legacy"), phone="919999999997", amount=1, due_day=5,
                              photo_path=legacy, owner_id=uid_of(u), occupancy_status="Active"))
        db.session.commit()
    assert c.get(f"/files/{legacy}").status_code == 200
    assert other.get(f"/files/{legacy}").status_code == 404
    assert c.get(f"/files/{orphan}").status_code == 404              # unreferenced file: nobody gets it


def test_legacy_files_are_moved_out_of_public_static_folder():
    static_dir = os.path.join(flask_app.root_path, "static", "uploads")
    name = f"{unique('old')}_agreement.pdf"
    with open(os.path.join(static_dir, name), "wb") as fh:
        fh.write(b"%PDF-1.4 legacy")
    assert uploads.migrate_legacy_uploads(flask_app) >= 1
    assert not os.path.exists(os.path.join(static_dir, name))
    assert os.path.exists(os.path.join(UPLOAD_DIR, name))


# ── client-supplied file references ──────────────────────────────────────────
def test_forged_screenshot_reference_is_rejected():
    c, u = logged_in_client()
    victim_c, _ = logged_in_client()
    _, victim_key = _uploaded_key(victim_c, "Vic")
    name = unique("Forge")
    add_tenant(c, name=name)
    tid = tenant_row(name).id
    c.get("/rent-tracker")                                          # real flow: creates this month's record
    for forged in (victim_key, "../../etc/passwd", "javascript:alert(1)", "');alert(1);//", "https://evil.example/x.png"):
        r = post(c, f"/tenant/force-paid/{tid}", {"method": "upi_screenshot", "screenshot_fn": forged,
                                                 "manual_amount": "1000", "transaction_id": "T1"})
        assert r.status_code == 302
        t = tenant_row(name)
        assert t.payment_screenshot in (None, ""), forged
        assert t.status != "Paid", forged                           # nothing was committed
        assert "Invalid screenshot reference" in c.get("/rent-tracker").get_data(as_text=True), forged


def test_own_screenshot_reference_accepted_and_ocr_flow_stores_privately():
    c, u = logged_in_client()
    name = unique("Ocr")
    add_tenant(c, name=name)
    tid = tenant_row(name).id
    c.get("/rent-tracker")                                          # real flow: creates this month's record
    r = post(c, f"/tenant/verify-payment/{tid}", {"method": "screenshot", "screenshot": (io.BytesIO(png_bytes()), "pay.png")},
             content_type="multipart/form-data")
    assert r.status_code == 200 and b"OCR Scan Result" in r.data
    import re
    key = re.search(r'name="screenshot_fn" value="([^"]+)"', r.get_data(as_text=True)).group(1)
    assert uploads.key_owner(key) == uid_of(u)
    r = post(c, f"/tenant/force-paid/{tid}", {"method": "upi_screenshot", "screenshot_fn": key,
                                             "manual_amount": "1000", "transaction_id": "UTR123"})
    assert tenant_row(name).payment_screenshot == key and tenant_row(name).status == "Paid"
    assert c.get(f"/files/{key}").status_code == 200
    assert f"/files/{key}" in c.get("/rent-tracker").get_data(as_text=True)


# ── lifecycle ────────────────────────────────────────────────────────────────
def test_deleting_renter_or_file_erases_stored_documents():
    c, u = logged_in_client()
    name, key = _uploaded_key(c, "Del")
    path = os.path.join(UPLOAD_DIR, key)
    tid = tenant_row(name).id
    assert os.path.exists(path)
    post(c, f"/renters/delete-file/{tid}/photo")
    assert not os.path.exists(path) and tenant_row(name).photo_path is None
    name2, key2 = _uploaded_key(c, "Del2")
    path2 = os.path.join(UPLOAD_DIR, key2)
    post(c, f"/renters/delete/{tenant_row(name2).id}")
    assert not os.path.exists(path2)
    assert post(c, f"/renters/delete-file/{tid}/../../x").status_code in (404, 405)
    assert post(c, f"/renters/delete-file/{tid}/other").status_code == 404


def test_replacing_a_file_removes_the_old_one():
    c, u = logged_in_client()
    name, old = _uploaded_key(c, "Rep")
    tid = tenant_row(name).id
    post(c, f"/renters/edit/{tid}", {"_photo_only": "1", "photo": (io.BytesIO(png_bytes(color="green")), "n.png")},
         content_type="multipart/form-data")
    new = tenant_row(name).photo_path
    assert new != old and not os.path.exists(os.path.join(UPLOAD_DIR, old)) and os.path.exists(os.path.join(UPLOAD_DIR, new))


def test_building_expense_receipt_uses_same_pipeline():
    c, u = logged_in_client()
    post(c, "/building-expenses/add", {"description": "Roof", "amount": "100", "date": "2026-01-01", "category": "Repairs",
                                       "receipt": (io.BytesIO(b"<script>x</script>"), "r.png")},
         content_type="multipart/form-data")
    with flask_app.app_context():
        assert unscoped(BuildingExpense.query).filter_by(owner_id=uid_of(u)).count() == 0
    post(c, "/building-expenses/add", {"description": "Roof", "amount": "100", "date": "2026-01-01", "category": "Repairs",
                                       "receipt": (io.BytesIO(png_bytes()), "r.png")},
         content_type="multipart/form-data")
    with flask_app.app_context():
        e = unscoped(BuildingExpense.query).filter_by(owner_id=uid_of(u)).one()
        assert uploads.KEY_RE.match(e.receipt_path)


# ── optional Supabase path (mocked: no live project available) ───────────────
def test_supabase_uploads_go_to_private_bucket_and_are_served_via_signed_url(monkeypatch):
    calls = {}

    class Bucket:
        def upload(self, path, data, opts):
            calls["upload"] = (path, opts)

        def create_signed_url(self, path, expires):
            calls["sign"] = (path, expires)
            return {"signedURL": f"https://proj.supabase.co/storage/v1/object/sign/uploads/{path}?token=abc"}

        def remove(self, paths):
            calls["remove"] = paths

    class Client:
        def from_(self, bucket):
            calls["bucket"] = bucket
            return Bucket()

    monkeypatch.setenv("SUPABASE_URL", "https://proj.supabase.co")
    monkeypatch.setenv("SUPABASE_KEY", "service-key")
    monkeypatch.setattr(uploads, "_supabase", lambda: ("https://proj.supabase.co", Client()))
    c, u = logged_in_client()
    name = unique("Sb")
    upload_photo(c, name, png_bytes(), "p.png")
    key = tenant_row(name).photo_path
    assert key.startswith("sb:") and calls["upload"][1] == {"content-type": "image/png"}
    assert not os.path.exists(os.path.join(UPLOAD_DIR, key[3:]))       # not kept locally
    r = c.get(f"/files/{key}")
    assert r.status_code == 302 and "token=abc" in r.headers["Location"] and calls["sign"][1] <= 120
    other, _ = logged_in_client()
    assert other.get(f"/files/{key}").status_code == 404
    post(c, f"/renters/delete/{tenant_row(name).id}")
    assert calls["remove"] == [key[3:]]
