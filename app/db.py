"""MongoDB storage for every analysis (pymongo).

Configuration (environment variables):
  MONGODB_URI  connection string, default mongodb://localhost:27017
               (MongoDB Atlas: mongodb+srv://user:password@cluster.xxxxx.mongodb.net/)
  MONGODB_DB   database name, default "safenet"
Collection: analyses
"""
import csv
import io
import os
import re
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import DESCENDING, MongoClient

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb+srv://udaysutar7104_db_user:TKHSFJcpNMZWuP3c@cluster0.2exsx68.mongodb.net/")
MONGODB_DB = os.environ.get("MONGODB_DB", "safenet")
COLLECTION = "analyses"

_client = None  # created lazily; tests may inject a mongomock client here


def _db():
    global _client
    if _client is None:
        # Short timeout so an unreachable database slows a request by seconds, not half a minute.
        _client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=3000, tz_aware=True)
    return _client[MONGODB_DB]


def _coll():
    return _db()[COLLECTION]


def collection(name):
    """Any collection in the SafeNet database (reference data lives in several)."""
    return _db()[name]


def init_db():
    c = _coll()
    c.create_index([("created_at", DESCENDING)])
    c.create_index("risk_level")


def save_analysis(text, url, email, result) -> str:
    """Store one analysis (input + full result). Returns the new document id as a string."""
    doc = {
        "created_at": datetime.now(timezone.utc),
        "input_text": text or None,
        "input_url": url or None,
        "input_email": email or None,
        "risk_score": result["risk_score"],
        "risk_level": result["risk_level"],
        "threat_type": result["threat_type"],
        "signals": result["signals"],
        "recommendation": result["recommendation"],
        "reasons": result["reasons"],
        "evidence": result.get("evidence", []),
        "cues": result["cues"],
        "urls_analyzed": result["urls_analyzed"],
        "emails_analyzed": result.get("emails_analyzed", []),
    }
    return str(_coll().insert_one(doc).inserted_id)


def _iso(ts):
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.isoformat(timespec="seconds")


def _public(doc, full=True):
    d = {
        "id": str(doc["_id"]), "created_at": _iso(doc["created_at"]),
        "input_text": doc.get("input_text"), "input_url": doc.get("input_url"), "input_email": doc.get("input_email"),
        "risk_score": doc["risk_score"], "risk_level": doc["risk_level"], "threat_type": doc["threat_type"],
        "signals": doc.get("signals") or {},
        "recommendation": doc.get("recommendation"),
    }
    if full:
        d.update(reasons=doc.get("reasons", []), cues=doc.get("cues", {}), urls_analyzed=doc.get("urls_analyzed", []),
                 evidence=doc.get("evidence", []), emails_analyzed=doc.get("emails_analyzed", []))
    else:  # list view: keep the payload small
        d["input_text"] = (d["input_text"] or "")[:140]
    return d


def _oid(analysis_id):
    try:
        return ObjectId(analysis_id)
    except (InvalidId, TypeError):
        return None


def list_analyses(limit=50, offset=0, level=None, q=None):
    flt = {}
    if level:
        flt["risk_level"] = level.upper()
    if q:
        rx = {"$regex": re.escape(q), "$options": "i"}
        flt["$or"] = [{"input_text": rx}, {"input_url": rx}, {"input_email": rx}]
    c = _coll()
    total = c.count_documents(flt)
    rows = c.find(flt).sort("_id", DESCENDING).skip(offset).limit(limit)
    return [_public(r, full=False) for r in rows], total


def get_analysis(analysis_id: str):
    oid = _oid(analysis_id)
    doc = _coll().find_one({"_id": oid}) if oid else None
    return _public(doc) if doc else None


def delete_analysis(analysis_id: str) -> bool:
    oid = _oid(analysis_id)
    return bool(oid) and _coll().delete_one({"_id": oid}).deleted_count > 0


def summary():
    c = _coll()
    by_level = {r["_id"]: r["n"] for r in c.aggregate([{"$group": {"_id": "$risk_level", "n": {"$sum": 1}}}])}
    by_threat = {r["_id"]: r["n"] for r in c.aggregate(
        [{"$group": {"_id": "$threat_type", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}])}
    avg = list(c.aggregate([{"$group": {"_id": None, "avg": {"$avg": "$risk_score"}}}]))
    per_day = {r["_id"]: r["n"] for r in c.aggregate([
        {"$group": {"_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$created_at"}}, "n": {"$sum": 1}}},
        {"$sort": {"_id": -1}}, {"$limit": 14}])}
    return {"total": c.count_documents({}), "by_level": by_level, "by_threat": by_threat,
            "avg_risk_score": round(avg[0]["avg"], 1) if avg else None, "per_day": per_day}


def export_csv() -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = ["id", "created_at", "risk_level", "risk_score", "threat_type", "input_text", "input_url", "input_email",
            "recommendation"]
    w.writerow(cols)
    for doc in _coll().find().sort("_id", 1):
        row = _public(doc)
        # prefix risky cells so spreadsheets don't execute them as formulas
        w.writerow([("'" + v if isinstance(v, str) and v[:1] in "=+-@" else v) for v in (row[k] for k in cols)])
    return buf.getvalue()
