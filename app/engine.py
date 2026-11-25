"""Reference-database engine. Compares the sender email, message and links with data in MongoDB
(known phishing links, trusted domains, blocked senders, scam phrases, brand domains, known scam messages)
and scores the risk from the matches. No machine learning: every point of the score has a named reason.

Weights are 0-1 ("how suspicious on its own"). Evidence is combined with a noisy-OR:
    risk = 1 - (1 - w1)(1 - w2)...      so several moderate signs add up, and one strong sign is enough.
"""
import re

from . import fusion
from .features import IP_REGEX, PLATFORM_DOMAINS, extract_urls, parse_url, strip_urls
from .reference import REF, domain_of, url_key

EMAIL_RX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
EMAIL_FULL = re.compile(EMAIL_RX.pattern)
PHONE_ONLY = re.compile(r"^\+?[0-9][0-9\s().-]{6,18}$")
SENSITIVE = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password", "wallet", "bank",
             "billing", "suspend", "unlock", "invoice", "webscr", "auth", "recover"]
LEET = str.maketrans("10354$@7", "loesasat")  # paypa1 -> paypal, micr0soft -> microsoft


def noisy_or(weights):
    p = 1.0
    for w in weights:
        p *= 1 - min(max(w, 0.0), 0.99)
    return 1 - p


def ev(source, kind, label, weight, safe=False, target=None):
    return {"source": source, "kind": kind, "label": label, "weight": round(weight, 2), "safe": safe, "target": target}


def is_platform(host):
    return any(host == d or host.endswith("." + d) for d in PLATFORM_DOMAINS)


def is_official(brand, host):
    return any(host == d or host.endswith("." + d) for d in brand["domains"])


def brand_match(name):
    """Does a website/email name imitate a known brand? Handles look-alikes such as paypa1 or hdfc-secure."""
    tokens = [t for t in re.split(r"[.\-_]+", (name or "").lower()) if t]
    for b in REF.brands:
        for kw in b["keywords"]:
            for t in tokens:
                for cand in (t, t.translate(LEET)):
                    if cand == kw or re.fullmatch(re.escape(kw) + r"\d+", cand) or (len(kw) >= 6 and kw in cand):
                        return b
    return None


def _plural(n, word):
    return f"{n}{'+' if n >= 10 else ''} {word}{'s' if n != 1 else ''}"


# ---------------------------------------------------------------- links
def analyze_url(raw):
    u, p, host = parse_url(raw)
    ip = bool(IP_REGEX.match(host))
    reg = domain_of(host)
    plat, plat_root = is_platform(host), host in PLATFORM_DOMAINS
    trusted = (reg in REF.trusted and host not in REF.shorteners and "@" not in u and not ip and not plat)
    evs, status = [], "unknown"

    # 1) database lookups: known phishing links
    if REF.url_exact(url_key(raw)):
        evs.append(ev("link", "url_exact", "Exact match with a known phishing link", .99))
        status = "listed"
    elif not plat_root and not trusted:
        hh = REF.url_host_hits(host)
        if hh:
            evs.append(ev("link", "url_host", f"This website is listed in {_plural(hh, 'known phishing link')}", .9))
            status = "listed"
        elif not plat and not ip:
            dh = REF.url_domain_hits(reg)
            if dh:
                evs.append(ev("link", "url_domain", f"This domain appears in {_plural(dh, 'known phishing link')}", .8))
                status = "listed"
    if status == "unknown" and trusted:
        status = "trusted"

    # 2) structural warning signs
    path_q = (p.path + "?" + p.query).lower()
    kh = [k for k in SENSITIVE if k in host]
    kp = [k for k in SENSITIVE if k in path_q]
    st = []
    if plat and not trusted:
        st.append(("url_platform", "Hosted on a free page-builder service, which scammers often abuse", .2))
    if ip:
        st.append(("url_ip", "Uses a raw IP address instead of a website name", .6))
    if "@" in u:
        st.append(("url_at", "Contains '@', which can hide the real destination", .5))
    brand = None if ip else brand_match(host)
    if brand and not is_official(brand, host):
        st.append(("url_spoof", f"Website name imitates {brand['name']} but is not its real site", .75))
    tld = host.rsplit(".", 1)[-1]
    if not ip and tld in REF.tlds:
        st.append(("url_tld", f"Ends in .{tld}, an ending common in scams", REF.tlds[tld]))
    if host in REF.shorteners:
        st.append(("url_short", "Shortened link hides the real destination", .3))
    if "xn--" in host:
        st.append(("url_puny", "Uses look-alike (punycode) characters", .5))
    if not ip and len(host.split(".")) - len(reg.split(".")) >= 3:
        st.append(("url_subs", "Has many subdomains", .3))
    if len(kh) + len(kp) >= 2:
        st.append(("url_kw", f"Contains sensitive words ({', '.join((kh + kp)[:3])})", .35))
    elif len(kh) == 1:
        st.append(("url_kw", f"Website name contains a sensitive word ({kh[0]})", .12))
    if host.count("-") >= 3:
        st.append(("url_hyph", "Website name has many hyphens", .25))
    if re.search(r"[0-9a-f]{16,}", url_key(raw)):
        st.append(("url_hex", "Contains a long random-looking code", .2))
    if len(url_key(raw)) > 100:
        st.append(("url_long", "Unusually long link", .1))
    if raw.strip().lower().startswith("http://") and not trusted:
        st.append(("url_http", "Does not use HTTPS", .1))
    scale = .25 if (trusted and status != "listed") else 1.0   # popular sites: warning signs count for much less
    evs += [ev("link", k, l, w * scale) for k, l, w in st]

    if trusted and status != "listed":
        evs.append(ev("link", "url_trusted", "Website is among the 10,000 most popular sites", 0, safe=True))
    elif not any(not e["safe"] for e in evs):
        evs.append(ev("link", "url_clean", "Not in the database and no warning signs found", 0, safe=True))
    for e in evs:
        e["target"] = host
    score = noisy_or([e["weight"] for e in evs if not e["safe"]])
    info = {"url": raw, "host": host, "probability": round(score, 4), "status": status,
            "trusted_domain": status == "trusted", "evidence": [e["label"] for e in evs]}
    return info, evs


# ---------------------------------------------------------------- email addresses
def analyze_email(addr, in_message=False):
    src, a = ("message" if in_message else "sender"), addr.strip().lower()
    pre = "Email address in the message: " if in_message else ""
    evs, status = [], "unknown"
    if not EMAIL_FULL.fullmatch(a):
        evs.append(ev(src, "email_invalid", pre + "Not a valid email address", .3))
    else:
        domain = a.rsplit("@", 1)[1]
        local = a.rsplit("@", 1)[0]
        reg = domain_of(domain)
        trusted, free = reg in REF.trusted, reg in REF.free_email
        if a in REF.blocked or domain in REF.blocked or reg in REF.blocked:
            evs.append(ev(src, "email_blocked", pre + "Address or domain is on the SafeNet blocklist", .95))
            status = "listed"
        if domain in REF.disposable or reg in REF.disposable:
            evs.append(ev(src, "email_disposable", pre + "Temporary (disposable) email service", .5))
        if not trusted and not free and not is_platform(domain):
            dh = REF.url_domain_hits(reg)
            if dh:
                evs.append(ev(src, "email_domain_listed", pre + f"Sender's domain appears in {_plural(dh, 'known phishing link')}", .8))
                status = "listed"
        brand = None if free else brand_match(domain)
        if brand and not is_official(brand, domain):
            evs.append(ev(src, "email_spoof", pre + f"Domain imitates {brand['name']} but is not its real domain", .75))
        if free:
            lb = brand_match(local)
            if lb:
                evs.append(ev(src, "email_brand_free", pre + f"Claims to be {lb['name']} but uses a free email service ({reg})", .6))
        tld = domain.rsplit(".", 1)[-1]
        if tld in REF.tlds:
            evs.append(ev(src, "email_tld", pre + f"Domain ends in .{tld}, an ending common in scams", REF.tlds[tld]))
        if trusted and not any(not e["safe"] for e in evs):
            evs.append(ev(src, "email_trusted", pre + "Well-known domain (sender names can still be forged)", 0, safe=True))
            status = "trusted"
        elif not any(not e["safe"] for e in evs):
            evs.append(ev(src, "email_clean", pre + "Not in the database and no warning signs found", 0, safe=True))
    for e in evs:
        e["target"] = a
    score = noisy_or([e["weight"] for e in evs if not e["safe"]])
    return {"email": a, "score": round(score, 4), "status": status, "evidence": [e["label"] for e in evs]}, evs


# ---------------------------------------------------------------- message text
def analyze_message(text):
    found = {}
    for ph in REF.phrases:
        for m in ph["rx"].finditer(text):
            found.setdefault(ph["category"], []).append((ph["weight"], m.group(0).strip()))
    evs, cues = [], {}
    for cat, hits in found.items():
        hits.sort(reverse=True)
        distinct = {h[1].lower() for h in hits}
        w = min(.9, hits[0][0] + min(.2, .08 * (len(distinct) - 1)))   # more distinct matches in a category: a little stronger
        cues[cat] = sorted(distinct)[:8]
        more = f" and {len(distinct) - 1} more" if len(distinct) > 1 else ""
        evs.append(ev("message", "phrase", f"{cat}: “{hits[0][1]}”{more}", w))

    sim = REF.similar_messages(text)
    (s_scam, t_scam, c_scam), (s_safe, t_safe, _) = sim["scam"], sim["safe"]
    matches = {"scam": None, "safe": None}
    if s_scam >= .45:
        evs.append(ev("message", "similar_scam", f"{round(s_scam * 100)}% similar to a known scam message ({c_scam or 'scam'})",
                      min(.9, .2 + (s_scam - .45) * 1.4)))
        matches["scam"] = {"similarity": round(s_scam, 2), "text": t_scam[:160], "category": c_scam}
    if s_safe >= .6:
        matches["safe"] = {"similarity": round(s_safe, 2), "text": t_safe[:160]}
    return evs, cues, matches, s_scam, s_safe


def brand_link_check(text, infos):
    """Message names a brand, but none of its links go to that brand's real website."""
    if not infos:
        return []
    low = " " + re.sub(r"[^a-z0-9]+", " ", strip_urls(text).lower()) + " "
    out = []
    for b in REF.brands:
        if not any(f" {m} " in low for m in b.get("mentions", [])):
            continue
        if any(is_official(b, i["host"]) for i in infos):
            continue
        weight = .45 if any(i["status"] != "trusted" for i in infos) else .15
        out.append(ev("message", "brand_mismatch", f"Mentions {b['name']} but the link goes to a different website", weight))
    return out


def threat_type(level, evs):
    if level == "LOW":
        return "None detected"
    risk = [e for e in evs if not e["safe"] and e["weight"] >= .3]
    kinds = {e["kind"] for e in risk}
    cats = {e["label"].split(":")[0] for e in risk if e["kind"] == "phrase"}
    if kinds & {"url_spoof", "brand_mismatch", "email_spoof", "email_brand_free"} or cats & {"Credential request", "Threat / fear"}:
        return "Phishing"
    if kinds & {"url_exact", "url_host", "url_domain"}:
        return "Malicious URL"
    if cats & {"Money / reward lure", "Payment request"} or "similar_scam" in kinds:
        return "Scam"
    if any(k.startswith("url_") for k in kinds):
        return "Malicious URL"
    if any(k.startswith("email_") for k in kinds):
        return "Suspicious sender"
    return "Suspicious content"


def insufficient(reason):
    return {"risk_score": None, "risk_level": "UNKNOWN", "threat_type": "Not enough information",
            "recommendation": "Paste the full message, a link or a sender email so SafeNet has something to compare.",
            "signals": {"message": None, "url": None, "email": None}, "evidence": [], "reasons": [reason], "cues": {},
            "urls_analyzed": [], "emails_analyzed": [], "matches": {"scam": None, "safe": None},
            "reference": "database" if REF.db_ok else "built-in lists only"}


# ---------------------------------------------------------------- main entry
def analyze(text="", url="", email=""):
    REF.ensure()
    text, url, email = (text or "").strip(), (url or "").strip(), (email or "").strip()
    if text and not url and not email:
        if EMAIL_FULL.fullmatch(text):                 # an address pasted into the message box is a sender check
            email, text = text, ""
        elif PHONE_ONLY.fullmatch(text):
            return insufficient("A phone number alone is not evidence of a scam.")

    urls = list(dict.fromkeys(([url] if url else []) + extract_urls(text)))
    url_infos, url_evs = [], []
    for u in urls:
        info, evs = analyze_url(u)
        url_infos.append(info)
        url_evs += evs

    emails = ([(email, False)] if email else []) + \
             [(e, True) for e in dict.fromkeys(EMAIL_RX.findall(strip_urls(text))) if e.lower() != email.lower()]
    email_infos, email_evs = [], []
    for e, in_msg in emails:
        info, evs = analyze_email(e, in_msg)
        email_infos.append(info)
        email_evs += evs

    if email and not text and not urls and not EMAIL_FULL.fullmatch(email):
        return insufficient("That is not a valid email address.")

    msg_evs, cues, matches, s_scam, s_safe = ([], {}, {"scam": None, "safe": None}, 0, 0)
    if text:
        msg_evs, cues, matches, s_scam, s_safe = analyze_message(text)
        msg_evs += brand_link_check(text, url_infos)
        if len(text.split()) <= 3 and not msg_evs and not urls and not emails:
            return insufficient("A very short fragment gives too little to compare.")

    msg_sig = noisy_or([e["weight"] for e in msg_evs if not e["safe"]]) if text else None
    if text and s_safe >= .7 and s_scam < .45 and msg_sig is not None:
        msg_sig *= .5
        msg_evs.append(ev("message", "similar_safe", f"{round(s_safe * 100)}% similar to a known normal message", 0, safe=True))
    url_sig = max((i["probability"] for i in url_infos), default=None)
    email_sig = max((i["score"] for i in email_infos), default=None)

    total = noisy_or([s for s in (msg_sig, url_sig, email_sig) if s is not None])
    level = fusion.risk_level(total)
    evidence = sorted(msg_evs + url_evs + email_evs, key=lambda e: (e["safe"], -e["weight"]))
    r = lambda v: None if v is None else round(v, 4)  # noqa: E731
    return {
        "risk_score": round(total * 100, 1), "risk_level": level,
        "threat_type": threat_type(level, evidence), "recommendation": fusion.recommendation(level),
        "signals": {"message": r(msg_sig), "url": r(url_sig), "email": r(email_sig)},
        "evidence": evidence, "reasons": [e["label"] for e in evidence if not e["safe"]], "cues": cues,
        "urls_analyzed": url_infos, "emails_analyzed": email_infos, "matches": matches,
        "reference": "database" if REF.db_ok else "built-in lists only",
    }
