"""Run:  pip install -r requirements-dev.txt && pytest -q
Uses mongomock (in-memory MongoDB stand-in) with a small seed, so no database server is needed."""
import mongomock
import pytest
from fastapi.testclient import TestClient

from app import db, seed
from app.main import app
from app.reference import REF


@pytest.fixture(scope="module")
def client():
    db._client = mongomock.MongoClient(tz_aware=True)
    db.init_db()
    seed.seed(max_rows=300)
    db.collection("trusted_domains").update_one({"domain": "github.com"}, {"$set": {"rank": 1}}, upsert=True)
    seed.add_blacklist("url", "http://evil-bank-login.top/verify")
    seed.add_blacklist("email", "scammer@fake-lottery.com")
    REF.invalidate()
    yield TestClient(app)
    db._client = None
    REF.invalidate()


def run(client, **body):
    r = client.post("/analyze", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_phishing_message_with_spoofed_link_is_high(client):
    r = run(client, text="URGENT: Your PayPal account has been suspended. Verify your password immediately at http://paypal-secure-login.xyz/verify")
    assert r["risk_level"] == "HIGH" and r["threat_type"] == "Phishing"
    assert r["signals"]["message"] > .5 and r["signals"]["url"] > .5
    assert any("imitates PayPal" in e["label"] for e in r["evidence"])


def test_normal_message_is_low(client):
    assert run(client, text="Hey, are we still meeting for lunch at 1pm tomorrow? I booked a table.")["risk_level"] == "LOW"
    assert run(client, text="Your OTP for the transaction is 482913. Do not share it with anyone.")["risk_level"] == "LOW"


def test_known_phishing_link_is_matched_in_database(client):
    exact = run(client, url="http://evil-bank-login.top/verify")
    assert exact["risk_level"] == "HIGH" and exact["urls_analyzed"][0]["status"] == "listed"
    assert any("Exact match" in e["label"] for e in exact["evidence"])
    other = run(client, url="https://evil-bank-login.top/another/page")      # same website, different page
    assert other["risk_level"] == "HIGH" and any("listed in" in e["label"] for e in other["evidence"])


def test_trusted_domain_lowers_risk_and_unknown_clean_link_is_low(client):
    r = run(client, url="https://github.com/anthropics")
    assert r["risk_level"] == "LOW" and r["urls_analyzed"][0]["status"] == "trusted"
    assert run(client, url="https://example.org/about")["risk_level"] == "LOW"
    assert run(client, url="http://192.168.44.12/secure/login.php")["risk_level"] == "HIGH"
    assert run(client, url="https://paypa1-account-verify.com/signin")["threat_type"] == "Phishing"


def test_sender_email_checks(client):
    assert run(client, email="scammer@fake-lottery.com")["risk_level"] == "HIGH"
    assert run(client, email="paypal-support@gmail.com")["risk_level"] == "MEDIUM"
    assert run(client, email="x@mailinator.com")["signals"]["email"] == .5
    assert run(client, text="dhl-support@yahoo.com")["signals"]["email"] > 0     # address pasted in the message box


def test_not_enough_information(client):
    for body in ({"text": "9876543210"}, {"text": "hello there"}, {"email": "12345"}):
        r = run(client, **body)
        assert r["risk_level"] == "UNKNOWN" and r["risk_score"] is None
    assert client.post("/analyze", json={}).status_code == 400


def test_history_is_stored_and_manageable(client):
    r = run(client, text="Congratulations! You have won a $1000 gift card. Claim your prize today only.")
    assert r["id"]
    item = client.get(f"/history/{r['id']}").json()
    assert item["risk_level"] == r["risk_level"] and item["evidence"] and item["signals"]["message"] > 0
    assert client.get("/history?level=high").json()["total"] >= 1
    assert client.get("/history?q=gift card").json()["total"] >= 1
    assert client.get("/history/summary").json()["total"] >= 1
    assert "id,created_at" in client.get("/history/export.csv").text
    assert client.delete(f"/history/{r['id']}").status_code == 200
    assert client.get(f"/history/{r['id']}").status_code == 404
    assert client.get("/history/not-an-id").status_code == 404


def test_stats_and_reporting_a_new_scam(client):
    s = client.get("/stats").json()
    assert s["source"] == "database" and s["known_phishing_links"] >= 300
    assert run(client, url="https://brand-new-scam-site.xyz/x")["urls_analyzed"][0]["status"] != "listed"
    assert client.post("/reference/blacklist", json={"kind": "domain", "value": "brand-new-scam-site.xyz"}).status_code == 200
    assert run(client, url="https://brand-new-scam-site.xyz/x")["urls_analyzed"][0]["status"] == "listed"


def test_admin_token_protection(client, monkeypatch):
    import app.main as m
    monkeypatch.setattr(m, "ADMIN_TOKEN", "s3cret")
    assert client.get("/history").status_code == 401
    assert client.get("/history", headers={"X-Admin-Token": "s3cret"}).status_code == 200
    assert client.post("/reference/blacklist", json={"kind": "domain", "value": "x-evil.com"}).status_code == 401
    assert client.post("/analyze", json={"text": "hello there my friend"}).status_code == 200
