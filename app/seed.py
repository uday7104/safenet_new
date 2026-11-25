"""Fills MongoDB with the reference data used by the engine. Safe to run repeatedly (only empty collections are filled).

  python seed_db.py            # fill empty collections
  python seed_db.py --reset    # drop and refill everything
  python seed_db.py --full     # also load data/raw/phish_active.txt (large live phishing feed) if present
"""
import csv
from datetime import datetime, timezone
from pathlib import Path

from pymongo.errors import BulkWriteError

from . import db, reference_data as rd
from .features import parse_url
from .reference import REF, domain_of, url_key

DATA = Path(__file__).resolve().parent.parent / "data"
COLLECTIONS = ["phrases", "brands", "suspicious_tlds", "shorteners", "free_email", "blocked_senders",
               "trusted_domains", "known_urls", "known_messages", "meta"]


def _insert(name, docs):
    if not docs:
        return 0
    try:
        return len(db.collection(name).insert_many(docs, ordered=False).inserted_ids)
    except BulkWriteError as e:  # duplicates are skipped
        return e.details.get("nInserted", 0)


def _empty(name):
    return db.collection(name).count_documents({}) == 0


def url_doc(raw, source):
    host = parse_url(raw)[2]
    return {"key": url_key(raw), "host": host, "domain": domain_of(host), "label": "phishing", "source": source}


def _phishing_urls(full):
    seen = set()
    f = DATA / "urls.csv"
    if f.exists():
        for row in csv.DictReader(open(f, encoding="utf-8", errors="ignore")):
            if row["label"] == "1":
                yield row["url"], "Phishing.Database sample"
    raw = DATA / "raw" / "phish_active.txt"
    if full and raw.exists():
        for i, line in enumerate(open(raw, encoding="utf-8", errors="ignore")):
            if i >= 150000:
                break
            if line.strip() and len(line) < 300 and " " not in line.strip():
                yield line.strip(), "Phishing.Database"


def seed(reset=False, full=False, max_rows=None):
    if reset:
        for n in COLLECTIONS:
            db.collection(n).drop()
    c, counts = db.collection, {}
    c("known_urls").create_index("key", unique=True)
    c("known_urls").create_index("host")
    c("known_urls").create_index("domain")
    c("trusted_domains").create_index("domain", unique=True)
    c("blocked_senders").create_index("value")

    cap = (lambda rows: rows[:max_rows]) if max_rows else (lambda rows: rows)   # max_rows: small seed for tests
    if _empty("phrases"):
        counts["phrases"] = _insert("phrases", [{"pattern": p, "category": k, "weight": w} for p, k, w in rd.PHRASES])
    if _empty("brands"):
        counts["brands"] = _insert("brands", [dict(b) for b in rd.BRANDS])
    if _empty("suspicious_tlds"):
        counts["suspicious_tlds"] = _insert("suspicious_tlds", [{"tld": t, "weight": w} for t, w in rd.SUSPICIOUS_TLDS.items()])
    if _empty("shorteners"):
        counts["shorteners"] = _insert("shorteners", [{"domain": d} for d in rd.SHORTENERS])
    if _empty("free_email"):
        counts["free_email"] = _insert("free_email", [{"domain": d} for d in rd.FREE_EMAIL])
    if _empty("blocked_senders"):
        counts["blocked_senders"] = _insert("blocked_senders", [{"value": d, "kind": "disposable", "source": "built-in"} for d in rd.DISPOSABLE_EMAIL])
    if _empty("trusted_domains") and (DATA / "trusted_domains.txt").exists():
        doms = (DATA / "trusted_domains.txt").read_text().split()
        counts["trusted_domains"] = _insert("trusted_domains", cap([{"domain": d.lower(), "rank": i + 1} for i, d in enumerate(doms)]))
    if _empty("known_urls"):
        docs, seen = [], set()
        for raw, src in _phishing_urls(full):
            d = url_doc(raw, src)
            if d["key"] and d["key"] not in seen:
                seen.add(d["key"])
                docs.append(d)
        counts["known_urls"] = _insert("known_urls", cap(docs))
    if _empty("known_messages"):
        docs = [{"text": t, "label": "scam", "category": k, "source": "curated"} for t, k in rd.KNOWN_SCAM_MESSAGES]
        docs += [{"text": t, "label": "safe", "category": None, "source": "curated"} for t in rd.KNOWN_SAFE_MESSAGES]
        f = DATA / "text.csv"
        if f.exists():
            for row in csv.DictReader(open(f, encoding="utf-8", errors="ignore")):
                if row.get("source", "real") == "real" and row["text"].strip():
                    docs.append({"text": row["text"].strip(), "label": "scam" if row["label"] == "1" else "safe",
                                 "category": "SMS spam" if row["label"] == "1" else None, "source": "SMS Spam Collection"})
        counts["known_messages"] = _insert("known_messages", cap(docs))
    if counts:
        c("meta").update_one({"_id": "seed"}, {"$set": {"seeded_at": datetime.now(timezone.utc), "counts": counts}}, upsert=True)
    REF.invalidate()
    return counts


def seed_if_empty():
    return seed()


def add_blacklist(kind, value, note=None):
    """Report a new scam: kind = url | domain | email. Takes effect immediately."""
    value = value.strip()
    if kind == "url":
        d = url_doc(value, "manual")
        db.collection("known_urls").update_one({"key": d["key"]}, {"$set": {**d, "note": note}}, upsert=True)
    elif kind == "domain":
        host = parse_url(value)[2] or value.lower()
        d = {"key": host, "host": host, "domain": domain_of(host), "label": "phishing", "source": "manual", "note": note}
        db.collection("known_urls").update_one({"key": host}, {"$set": d}, upsert=True)
    elif kind == "email":
        v = value.lower()
        db.collection("blocked_senders").update_one(
            {"value": v}, {"$set": {"value": v, "kind": "address" if "@" in v else "domain", "source": "manual", "note": note}}, upsert=True)
    else:
        raise ValueError("kind must be url, domain or email")
    REF.invalidate()
