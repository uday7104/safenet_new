"""Loads the reference data (MongoDB, with built-in fallback) and answers lookups against it."""
import re
import time

from . import reference_data as rd
from .features import IP_REGEX, normalize_url, parse_url, registered_domain, strip_urls

TTL = 300          # seconds between reloads of the small lists
RETRY = 20         # seconds before retrying after a failed load
URL_LOOKUP_CAP = 10


def url_key(url: str) -> str:
    """Canonical form for exact comparison: no scheme/www/fragment/trailing slash, lowercase."""
    return normalize_url(url).split("#")[0].rstrip("/")


def domain_of(host: str) -> str:
    """Registered domain (paypal.com for login.paypal.com); IP addresses are returned unchanged."""
    return host if IP_REGEX.match(host or "") else registered_domain(host)


def message_tokens(text: str):
    words = re.findall(r"[a-z]+", strip_urls(text).lower())
    return set(words) | set(zip(words, words[1:])), len(words)


def jaccard(a, b) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0


class Reference:
    def __init__(self):
        self.loaded_at = 0.0
        self.db_ok = False
        self._builtin()

    # ----- built-in data (fallback) -----
    def _compile(self, rows):
        return [{"rx": re.compile(p, re.I), "category": c, "weight": w} for p, c, w in rows]

    def _builtin(self):
        self.phrases = self._compile(rd.PHRASES)
        self.brands = [dict(b) for b in rd.BRANDS]
        self.tlds = dict(rd.SUSPICIOUS_TLDS)
        self.shorteners = set(rd.SHORTENERS)
        self.free_email = set(rd.FREE_EMAIL)
        self.disposable = set(rd.DISPOSABLE_EMAIL)
        self.blocked = set()
        self.trusted = set()
        self.messages = [("scam", t, c, *message_tokens(t)) for t, c in rd.KNOWN_SCAM_MESSAGES] + \
                        [("safe", t, None, *message_tokens(t)) for t in rd.KNOWN_SAFE_MESSAGES]

    # ----- database -----
    def invalidate(self):
        self.loaded_at = 0.0

    def ensure(self):
        if time.time() - self.loaded_at < TTL:
            return
        try:
            self._load_db()
            self.db_ok = True
            self.loaded_at = time.time()
        except Exception as e:  # noqa: BLE001
            print("Reference DB unavailable, using built-in lists:", str(e)[:120])
            self.db_ok = False
            self.loaded_at = time.time() - TTL + RETRY

    def _load_db(self):
        from . import db
        rows = lambda name: list(db.collection(name).find({}))  # noqa: E731
        phrases = rows("phrases")
        brands = rows("brands")
        tlds = rows("suspicious_tlds")
        short = rows("shorteners")
        free = rows("free_email")
        blocked = rows("blocked_senders")
        trusted = rows("trusted_domains")
        msgs = rows("known_messages")
        # swap in only after everything loaded successfully
        if phrases:
            self.phrases = self._compile([(r["pattern"], r["category"], r["weight"]) for r in phrases])
        if brands:
            self.brands = brands
        if tlds:
            self.tlds = {r["tld"]: r["weight"] for r in tlds}
        if short:
            self.shorteners = {r["domain"] for r in short}
        if free:
            self.free_email = {r["domain"] for r in free}
        self.blocked = {r["value"] for r in blocked if r.get("kind") != "disposable"}
        self.disposable = {r["value"] for r in blocked if r.get("kind") == "disposable"} or set(rd.DISPOSABLE_EMAIL)
        self.trusted = {r["domain"] for r in trusted}
        if msgs:
            self.messages = [(r["label"], r["text"], r.get("category"), *message_tokens(r["text"])) for r in msgs]

    # ----- lookups against the known phishing links -----
    def url_exact(self, key):
        return self._find({"key": key}, 1) > 0

    def url_host_hits(self, host):
        return self._find({"host": host}, URL_LOOKUP_CAP)

    def url_domain_hits(self, domain):
        return self._find({"domain": domain}, URL_LOOKUP_CAP)

    def _find(self, query, cap):
        if not self.db_ok:
            return 0
        try:
            from . import db
            return len(list(db.collection("known_urls").find(query, {"_id": 1}).limit(cap)))
        except Exception:  # noqa: BLE001
            self.db_ok = False
            self.loaded_at = time.time() - TTL + RETRY
            return 0

    def similar_messages(self, text):
        """Best Jaccard similarity to a known scam and to a known safe message."""
        toks, n = message_tokens(text)
        best = {"scam": (0.0, None, None), "safe": (0.0, None, None)}
        if n < 4:
            return best
        for label, mtext, cat, mtoks, mn in self.messages:
            if mn < 3:
                continue
            s = jaccard(toks, mtoks)
            if s > best[label][0]:
                best[label] = (s, mtext, cat)
        return best

    def stats(self):
        out = {"phrases": len(self.phrases), "brands": len(self.brands), "trusted_domains": len(self.trusted),
               "known_messages": len(self.messages), "blocked_senders": len(self.blocked) + len(self.disposable),
               "known_phishing_links": None, "source": "database" if self.db_ok else "built-in lists only"}
        if self.db_ok:
            try:
                from . import db
                out["known_phishing_links"] = db.collection("known_urls").count_documents({})
            except Exception:  # noqa: BLE001
                pass
        return out


REF = Reference()
