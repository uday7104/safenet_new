"""URL + text feature extraction for SafeNet."""
import math
import re
from urllib.parse import urlparse

URL_REGEX = re.compile(r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)", re.I)
IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SUSPICIOUS_TLDS = {"xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work", "support", "zip", "country",
                   "kim", "loan", "icu", "buzz", "cyou", "rest", "monster", "site", "online", "live", "club"}
URL_KEYWORDS = ["login", "verify", "secure", "account", "update", "bank", "confirm", "signin", "password", "wallet",
                "free", "bonus", "gift", "billing", "suspend", "unlock", "paypal", "invoice", "webscr", "auth", "recover"]
BRANDS = ["paypal", "amazon", "microsoft", "apple", "google", "facebook", "netflix", "instagram", "whatsapp", "hdfc",
          "icici", "sbi", "chase", "wellsfargo", "bankofamerica", "dhl", "fedex", "linkedin", "outlook", "office365"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
MULTI_TLDS = {"co.uk", "com.au", "co.in", "ac.in", "com.br", "co.jp", "com.cn", "co.za", "com.mx", "org.uk", "gov.in", "net.in"}
# Free hosting / user-content platforms: a popular parent domain does NOT make these pages trustworthy.
PLATFORM_DOMAINS = {"blogspot.com", "weebly.com", "wixsite.com", "github.io", "pages.dev", "netlify.app", "herokuapp.com",
                    "firebaseapp.com", "web.app", "000webhostapp.com", "glitch.me", "vercel.app", "workers.dev",
                    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "storage.googleapis.com",
                    "wordpress.com", "pantheonsite.io", "ngrok.io", "repl.co", "godaddysites.com"}

URL_FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len", "num_dots", "hyphens_host", "hyphens_total", "digits_host",
    "digit_ratio", "num_special", "has_at", "has_ip", "num_subdomains", "kw_host", "kw_path", "bad_tld",
    "entropy_host", "entropy_path", "has_punycode", "double_slash_path", "is_shortener", "port_in_url", "path_depth",
    "longest_token", "hex_run", "num_params", "is_root", "brand_spoof",
]


def extract_urls(text: str):
    return [u.rstrip(".,);]") for u in URL_REGEX.findall(text or "")]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def parse_url(url: str):
    u = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", u):
        u = "http://" + u
    p = urlparse(u)
    return u, p, (p.hostname or "").lower()


def normalize_url(url: str) -> str:
    """Scheme/www-free lowercase form. Models must not learn http-vs-https or 'www.' dataset artifacts."""
    u, p, host = parse_url(url)
    rest = u.split("://", 1)[1].lower()
    return rest[4:] if rest.startswith("www.") else rest


def registered_domain(host: str) -> str:
    parts = [x for x in (host or "").split(".") if x]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in MULTI_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def url_features(url: str) -> list:
    # Computed on the scheme-free, www-free form so http/https and 'www.' cannot leak dataset artifacts.
    u = normalize_url(url)
    _, p, host = parse_url(u)
    low = u
    host_l, path_l = host, (p.path or "").lower() + ("?" + p.query.lower() if p.query else "")
    parts = host.split(".") if host else []
    tld = parts[-1] if parts else ""
    reg = registered_domain(host)
    try:
        port = p.port
    except ValueError:
        port = None
    tokens = re.split(r"[^a-z0-9]+", low)
    hex_runs = re.findall(r"[0-9a-f]{16,}", low)
    spoof = int(any(b in host_l and not reg.startswith(b + ".") for b in BRANDS))
    path = "" if p.path == "/" else p.path
    return [
        len(u), len(host), len(path), len(p.query), u.count("."), host.count("-"), u.count("-"),
        sum(c.isdigit() for c in host), sum(c.isdigit() for c in u) / max(len(u), 1),
        sum(not c.isalnum() for c in u), int("@" in u), int(bool(IP_REGEX.match(host))),
        max(len(parts) - 2, 0), sum(k in host_l for k in URL_KEYWORDS), sum(k in path_l for k in URL_KEYWORDS),
        int(tld in SUSPICIOUS_TLDS), _entropy(host), _entropy(path), int("xn--" in host),
        int("//" in p.path), int(host in SHORTENERS), int(port is not None),
        len([s for s in path.split("/") if s]), max((len(t) for t in tokens), default=0),
        max((len(h) for h in hex_runs), default=0), len([q for q in p.query.split("&") if q]),
        int(path == "" and not p.query), spoof,
    ]


def url_red_flags(url: str) -> list:
    """Human-readable reasons, used for explainability."""
    f = dict(zip(URL_FEATURE_NAMES, url_features(url)))
    flags = []
    if f["has_ip"]:
        flags.append("Link uses a raw IP address instead of a domain name")
    if f["has_at"]:
        flags.append("Link contains '@', which can hide the real destination")
    if f["brand_spoof"]:
        flags.append("Domain imitates a well-known brand but is not the brand's real domain")
    if f["num_subdomains"] >= 3:
        flags.append("Link has many subdomains (common in spoofed domains)")
    if f["bad_tld"]:
        flags.append("Domain uses a TLD frequently abused in scams")
    if f["kw_host"] + f["kw_path"] >= 2:
        flags.append("Link contains several sensitive keywords (login/verify/secure...)")
    if f["has_punycode"]:
        flags.append("Domain uses punycode (possible look-alike characters)")
    if f["is_shortener"]:
        flags.append("Link is shortened, so the destination is hidden")
    if (url or "").strip().lower().startswith("http://"):
        flags.append("Link does not use HTTPS")
    if f["hyphens_host"] >= 3:
        flags.append("Domain contains many hyphens")
    if f["hex_run"] >= 16:
        flags.append("Link contains a long random-looking token")
    if f["url_len"] > 90:
        flags.append("Link is unusually long")
    return flags


TEXT_CUES = {
    "Urgency": r"\b(urgent|immediately|within \d+ ?(hours?|hrs?|minutes?)|asap|last chance|expires?|final notice|act now|today only)\b",
    "Credential request": r"\b(password|otp|pin|cvv|verify your (account|identity)|confirm your (account|details)|login|sign in|ssn|card number)\b",
    "Money / reward lure": r"\b(winner|won|prize|lottery|reward|cash ?back|gift card|free|bonus|claim|refund|inheritance|investment|crypto|double your)\b",
    "Threat / fear": r"\b(suspended|blocked|locked|terminated|unauthorized|legal action|arrest|penalty|compromised|deactivated)\b",
    "Authority impersonation": r"\b(bank|paypal|amazon|microsoft|apple|irs|income tax|hr department|it support|customs|courier|delivery)\b",
}


def strip_urls(text: str) -> str:
    return re.sub(r"\s+", " ", URL_REGEX.sub(" ", text or "")).strip()


def text_cues(text: str) -> dict:
    t = (text or "").lower()
    out = {}
    for name, rx in TEXT_CUES.items():
        m = [x.group(0) for x in re.finditer(rx, t)]
        if m:
            out[name] = m
    return out
