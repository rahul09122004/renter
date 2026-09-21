"""Original account-isolation tests (updated for CSRF) + IDOR checks."""
import unittest  # noqa: F401  (kept for parity with the original file)

from conftest import *  # noqa
from conftest import flask_app, get_token
from models import RentRecord, Tenant, unscoped


def test_login_required_rejects_stale_owner_id(client):
    with client.session_transaction() as sess:
        sess["admin_logged_in"] = True
        sess["owner_id"] = 999999
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/login")
    with client.session_transaction() as sess:
        assert not sess.get("admin_logged_in")
        assert not sess.get("owner_id")


def test_accounts_stay_isolated(client):
    a, b = unique("alice"), unique("bob")
    for name in (a, b):
        r = post(client, "/signup", {
            "username": name, "password": PASSWORD, "confirm_password": PASSWORD,
            "full_name": name.title(), "email": f"{name}@test.com", "property_name": "Homes"})
        assert r.status_code == 302, r.get_data(as_text=True)[:400]
    login(client, a)
    with client.session_transaction() as sess:
        assert sess["admin_username"] == a
    login(client, b)
    with client.session_transaction() as sess:
        assert sess["admin_username"] == b


def test_signup_page_is_rendered_as_standalone_auth_page(client):
    resp = client.get("/signup")
    assert resp.status_code == 200
    assert "Create your account" in resp.get_data(as_text=True)
    assert "Dashboard" not in resp.get_data(as_text=True)


def _tenant_id(name):
    with flask_app.app_context():
        return unscoped(Tenant.query).filter_by(name=name).first().id


def test_idor_other_account_cannot_read_or_modify_renter():
    alice, _ = logged_in_client()
    bob, _ = logged_in_client()
    name = unique("Victim")
    assert add_tenant(alice, name=name).status_code == 302
    tid = _tenant_id(name)
    alice.get(f"/renters/detail/{tid}")                    # creates a rent record
    assert alice.get(f"/renters/detail/{tid}").status_code == 200

    assert bob.get(f"/renters/detail/{tid}").status_code == 404
    assert bob.get(f"/renters/edit/{tid}").status_code == 404
    assert post(bob, f"/renters/delete/{tid}").status_code == 404
    assert post(bob, f"/tenant/remind/{tid}", {"channel": "sms"}).status_code == 404
    assert post(bob, f"/tenant/force-paid/{tid}", {"manual_amount": "1"}).status_code == 404
    assert post(bob, f"/renters/vacate/{tid}", {"repair_charged": "1"}).status_code == 404
    with flask_app.app_context():
        assert unscoped(Tenant.query).filter_by(id=tid).first() is not None
        rid = unscoped(RentRecord.query).filter_by(tenant_id=tid).first().id
    assert bob.get(f"/rent-history/edit/{rid}").status_code == 404
    assert post(bob, f"/rent-history/delete/{rid}").status_code == 404
    assert post(bob, f"/rent-history/mark-paid/{rid}").status_code == 404
    # nor does it leak into listings / exports
    assert name.encode() not in bob.get("/renters").data
    assert name.encode() not in bob.get("/download/excel").data
    assert name not in str(bob.get("/api/dashboard").json)
