"""Input validation (SQLi/XSS/type abuse) and output encoding."""
import math
from datetime import date

import pytest

from conftest import *  # noqa
from conftest import flask_app
import app as app_module
from models import (Admin, BuildingExpense, CommonExpense, RentRecord, Tenant, db, unscoped)
from validators import (ValidationError, clean_email, clean_phone, clean_text, clean_username,
                        excel_safe, parse_date, parse_int, parse_money)

TODAY = date.today().isoformat()


def _uid(username):
    with flask_app.app_context():
        return unscoped(Admin.query).filter_by(username=username).first().id


def _expenses(uid):
    with flask_app.app_context():
        return [(e.description, e.amount) for e in unscoped(CommonExpense.query).filter_by(owner_id=uid)]


# ── validator unit tests ─────────────────────────────────────────────────────
@pytest.mark.parametrize("bad", ["nan", "NaN", "inf", "-inf", "Infinity", "-5", "1e300", "1e5", "0x10",
                                 "12.345", "", "abc", "1,2,3x", "١٢٣", "999999999999999", " ", "--1", "5;DROP"])
def test_parse_money_rejects_garbage(bad):
    with pytest.raises(ValidationError):
        parse_money(bad)


@pytest.mark.parametrize("raw,expected", [("18000", 18000.0), ("18,000", 18000.0), ("₹ 1,250.50", 1250.5), ("0", 0.0)])
def test_parse_money_accepts_real_amounts(raw, expected):
    assert parse_money(raw) == expected


def test_parse_int_and_date_bounds():
    assert parse_int("12", lo=1, hi=12) == 12
    for bad in ("13", "0", "1.5", "-1", "x", "1e2"):
        with pytest.raises(ValidationError):
            parse_int(bad, lo=1, hi=12)
    assert parse_date("2026-02-28") == date(2026, 2, 28)
    for bad in ("2026-02-30", "2026-13-01", "0001-01-01", "3000-01-01", "26-1-1", "2026/01/01", "'; --"):
        with pytest.raises(ValidationError):
            parse_date(bad)


def test_clean_text_strips_control_chars_and_rejects_markup_and_length():
    assert clean_text("  Ann\x00e\u202e  ") == "Anne"
    assert clean_text("a\nb\tc") == "a b c"
    assert clean_text("l1\r\nl2", multiline=True) == "l1\nl2"
    with pytest.raises(ValidationError):
        clean_text("<script>alert(1)</script>")
    with pytest.raises(ValidationError):
        clean_text("x" * 201)
    with pytest.raises(ValidationError):
        clean_text("  ", required=True)
    assert clean_text("rent < 5000", multiline=True) == "rent < 5000"     # notes may contain < (escaped on output)
    with pytest.raises(ValidationError):
        clean_text(["not", "text"])


def test_identity_validators():
    assert clean_phone("+91 98765-43210") == "919876543210"
    for bad in ("abc", "12", "1" * 20, "+1; DROP", "12345678901234567890"):
        with pytest.raises(ValidationError):
            clean_phone(bad)
    assert clean_email("A@b.co") == "A@b.co"
    for bad in ("nope", "a@b", "<a>@b.co", "a b@c.co", "a@" + "b" * 300 + ".co"):
        with pytest.raises(ValidationError):
            clean_email(bad)
    assert clean_username("Ramesh.K") == "ramesh.k"
    for bad in ("ab", "x y", "x');--", "-lead", "a" * 41, "ünï"):
        with pytest.raises(ValidationError):
            clean_username(bad)


def test_excel_safe_neutralises_formulas_only_for_strings():
    for f in ("=1+1", "+cmd", "-2+3", "@SUM(A1)", "\t=x"):
        assert excel_safe(f).startswith("'")
    assert excel_safe("Normal") == "Normal" and excel_safe(5) == 5 and excel_safe(None) is None


# ── request-level validation ─────────────────────────────────────────────────
@pytest.mark.parametrize("amount", ["nan", "inf", "-100", "1e300", "99999999999", "abc", "", "12.999"])
def test_expense_rejects_bad_amounts(amount):
    c, u = logged_in_client()
    post(c, "/common-expenses/add", {"description": "bad-amount", "amount": amount, "date": TODAY})
    assert _expenses(_uid(u)) == []


def test_expense_accepts_valid_and_normalises():
    c, u = logged_in_client()
    post(c, "/common-expenses/add", {"description": "Water", "amount": "1,250.50", "date": TODAY, "split_units": "6"})
    assert _expenses(_uid(u)) == [("Water", 1250.5)]


@pytest.mark.parametrize("field,value", [
    ("description", "<script>alert(1)</script>"), ("description", "x" * 500), ("description", ""),
    ("date", "2026-13-45"), ("date", "1900-01-01"), ("date", "yesterday"), ("split_units", "0"),
    ("split_units", "99999"), ("split_units", "-3"), ("split_units", "six"),
])
def test_expense_rejects_bad_fields(field, value):
    c, u = logged_in_client()
    data = {"description": "ok", "amount": "10", "date": TODAY, "split_units": "6"}
    data[field] = value
    post(c, "/common-expenses/add", data)
    assert _expenses(_uid(u)) == []


@pytest.mark.parametrize("extra", [
    {"phone": "not-a-phone"}, {"amount": "-1"}, {"amount": "nan"}, {"due_day": "0"}, {"due_day": "32"},
    {"due_day": "abc"}, {"deposit": "-5"}, {"join_date": "31-31-2020"}, {"name": "<img src=x onerror=alert(1)>"},
    {"email": "not-an-email"}, {"unit": "U" * 50}, {"notes": "n" * 5000},
])
def test_renter_rejects_bad_fields(extra):
    c, u = logged_in_client()
    name = extra.get("name") or unique("Renter")
    extra = {k: v for k, v in extra.items() if k != "name"} | ({"name": name} if "name" in extra else {})
    r = add_tenant(c, **({"name": name} | extra))
    assert r.status_code == 200                                    # re-rendered form, not saved
    with flask_app.app_context():
        assert unscoped(Tenant.query).filter_by(owner_id=_uid(u)).count() == 0


def test_renter_edit_rejects_invalid_enum():
    c, u = logged_in_client()
    name = unique("Enum")
    add_tenant(c, name=name)
    with flask_app.app_context():
        tid = unscoped(Tenant.query).filter_by(name=name).first().id
    data = {"name": name, "phone": "919876500001", "amount": "1000", "due_day": "5",
            "occupancy_status": "Hacked"}
    post(c, f"/renters/edit/{tid}", data, content_type="multipart/form-data")
    with flask_app.app_context():
        assert unscoped(Tenant.query).get(tid).occupancy_status == "Active"


def test_rent_record_rejects_bad_status_month_and_amounts():
    c, u = logged_in_client()
    name = unique("Rec")
    add_tenant(c, name=name)
    with flask_app.app_context():
        tid = unscoped(Tenant.query).filter_by(name=name).first().id
    base = {"tenant_id": str(tid), "month": "3", "year": "2026", "status": "Paid", "rent_amount": "1000",
            "paid_amount": "1000", "payment_method": "cash"}
    for override in ({"status": "Hacked"}, {"month": "13"}, {"year": "1999"}, {"paid_amount": "nan"},
                     {"rent_amount": "-1"}, {"payment_method": "bitcoin"}, {"tenant_id": "abc"},
                     {"payment_date": "not-a-date"}, {"transaction_id": "<b>"}):
        post(c, "/rent-history/add", base | override)
    with flask_app.app_context():
        assert unscoped(RentRecord.query).filter_by(tenant_id=tid, month=3, year=2026).count() == 0
    post(c, "/rent-history/add", base)
    with flask_app.app_context():
        assert unscoped(RentRecord.query).filter_by(tenant_id=tid, month=3, year=2026).count() == 1


def test_query_params_never_cause_500():
    c, _ = logged_in_client()
    for url in ("/rent-history/add?month=99&year=abc&tenant_id=xx", "/rent-history?month=-1&year=99999",
                "/income-expenses?view=%3Cscript%3E&month=13&year=1", "/ca-audit?view=year&year=0&month=abc",
                "/unit-analytics?year=1%20OR%201=1", "/rent-history/add?tenant_id=1'--"):
        assert c.get(url).status_code == 200, url


def test_sql_injection_payloads_are_stored_literally_and_do_no_harm():
    c, u = logged_in_client()
    name = "Robert'); DROP TABLE tenants;--"
    assert add_tenant(c, name=name).status_code == 302
    with flask_app.app_context():
        assert unscoped(Tenant.query).filter_by(name=name).count() == 1     # stored verbatim
        assert unscoped(Tenant.query).count() >= 1                          # table still exists
    anon = flask_app.test_client()
    for payload in ("' OR '1'='1", "admin'--", "\" OR \"\"=\"", "1; DROP TABLE admin"):
        assert login(anon, payload, payload).status_code == 401
    with flask_app.app_context():
        assert unscoped(Admin.query).count() >= 1


def test_errors_do_not_leak_exception_text():
    c, _ = logged_in_client()
    r = add_tenant(c, amount="not-a-number")
    text = r.get_data(as_text=True)
    assert "could not convert" not in text and "Traceback" not in text and "ValueError" not in text
    assert "valid amount" in text


def test_unhandled_exception_returns_generic_500_with_reference(monkeypatch):
    import types
    c, _ = logged_in_client()
    monkeypatch.setattr(app_module, "Tenant", types.SimpleNamespace())      # forces AttributeError in the view
    r = c.get("/renters")
    text = r.get_data(as_text=True)
    assert r.status_code == 500
    assert "SimpleNamespace" not in text and "Traceback" not in text and "AttributeError" not in text
    assert "Reference" in text and r.headers.get("X-Request-ID")


def test_api_errors_are_json_and_do_not_leak():
    anon = flask_app.test_client()
    r = anon.get("/api/dashboard")
    assert r.status_code == 401 and r.is_json and r.json["error"] == "unauthorized"


# ── output encoding (data inserted directly to bypass input validation) ───────
def _seed(uid, *objs):
    with flask_app.app_context():
        for o in objs:
            o.owner_id = uid
            db.session.add(o)
        db.session.commit()


def test_dashboard_chart_json_cannot_break_out_of_script_tag():
    c, u = logged_in_client()
    payload = "</script><script>alert(document.domain)</script>"
    _seed(_uid(u), CommonExpense(description=payload, amount=10, category="x", date=date.today()))
    html = c.get("/").get_data(as_text=True)
    assert "</script><script>alert(document.domain)" not in html
    assert "\\u003c/script\\u003e" in html


def test_rent_tracker_drawer_escapes_tenant_fields():
    c, u = logged_in_client()
    evil = "<img src=x onerror=alert(1)>"
    _seed(_uid(u), Tenant(name=evil, phone="919999999999", amount=1000, due_day=5, unit="<b>x</b>",
                          notes=evil, status="Pending", occupancy_status="Active"))
    html = c.get("/rent-tracker").get_data(as_text=True)
    assert evil not in html                                   # never raw
    assert "\\u003cimg src=x onerror" in html or "&lt;img src=x onerror" in html
    assert "function esc(" in html and "${esc(t.name)}" in html
    assert "${t.name}" not in html.replace("${esc(t.name)}", "")   # no unescaped interpolation left


def test_users_page_username_is_not_interpolated_into_javascript():
    c, u = logged_in_client(role="superadmin")
    evil = "x');alert(1);//"
    _seed(None, Admin(username=evil, password_hash="x", role="owner", is_active=True))
    html = c.get("/users").get_data(as_text=True)
    assert "openReset('" not in html and "openDelete('" not in html
    assert "openReset(this.dataset.uid, this.dataset.username)" in html
    assert 'data-username="x&#39;);alert(1);//"' in html      # inert HTML-escaped attribute


def test_ledger_and_category_data_use_json_encoding():
    c, u = logged_in_client()
    nasty = 'a"b\\</script><script>alert(1)</script>\'x'
    _seed(_uid(u), CommonExpense(description=nasty, amount=5, category=nasty, date=date.today()),
          BuildingExpense(description=nasty, amount=5, category=nasty, date=date.today()))
    for url in ("/ca-audit", "/income-expenses", "/building-expenses", "/common-expenses"):
        html = c.get(url).get_data(as_text=True)
        assert "</script><script>alert(1)" not in html, url
    assert "esc(e.particulars)" in c.get("/ca-audit").get_data(as_text=True)


def test_delete_and_vacate_confirmations_do_not_use_inline_js_interpolation():
    c, u = logged_in_client()
    nasty = "x'); alert(1); ('"
    _seed(_uid(u), CommonExpense(description=nasty, amount=5, category="c", date=date.today()),
          BuildingExpense(description=nasty, amount=5, category="c", date=date.today()))
    for url in ("/common-expenses", "/building-expenses"):
        html = c.get(url).get_data(as_text=True)
        assert "return confirm('Delete" not in html and "data-confirm=" in html
    name = unique("Vac")
    add_tenant(c, name=name)
    with flask_app.app_context():
        tid = unscoped(Tenant.query).filter_by(name=name).first().id
    html = c.get(f"/renters/vacate/{tid}").get_data(as_text=True)
    assert "confirm('Confirm vacate" not in html and "data-confirm-click=" in html


def test_flash_messages_and_text_fields_are_html_escaped():
    c, u = logged_in_client()
    _seed(_uid(u), Tenant(name="A&B <b>bold</b>", phone="919999999998", amount=1, due_day=5,
                          status="Pending", occupancy_status="Active"))
    html = c.get("/renters").get_data(as_text=True)
    assert "<b>bold</b>" not in html and "&lt;b&gt;bold&lt;/b&gt;" in html
