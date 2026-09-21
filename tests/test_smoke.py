from conftest import *  # noqa

def test_login_page_and_login(client):
    r = client.get("/login")
    assert r.status_code == 200 and b"csrf-token" in r.data
    c, u = logged_in_client()
    assert c.get("/").status_code == 200

def test_add_tenant_roundtrip():
    c, u = logged_in_client()
    r = add_tenant(c)
    assert r.status_code == 302
    assert b"Test Tenant" in c.get("/renters").data
