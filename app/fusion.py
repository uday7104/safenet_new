"""Fuses text + URL model probabilities into a risk level, threat type and recommendation."""
LOW_T, HIGH_T = 0.35, 0.65
W_TEXT, W_URL = 0.5, 0.5


def fuse(text_p, url_p):
    """Weighted average of available signals, boosted toward the strongest signal."""
    probs = [p for p in (text_p, url_p) if p is not None]
    if not probs:
        return 0.0
    if len(probs) == 1:
        return float(probs[0])
    avg = W_TEXT * text_p + W_URL * url_p
    return float(min(1.0, 0.7 * avg + 0.3 * max(probs)))


def risk_level(score):
    return "LOW" if score < LOW_T else ("MEDIUM" if score < HIGH_T else "HIGH")


def threat_type(level, text_p, url_p, cues):
    if level == "LOW":
        return "None detected"
    if url_p is not None and url_p >= 0.5 and (text_p is None or text_p < 0.5):
        return "Malicious URL"
    if "Credential request" in cues or "Threat / fear" in cues:
        return "Phishing"
    if "Money / reward lure" in cues:
        return "Scam"
    return "Phishing" if (url_p or 0) >= 0.5 else "Suspicious content"


def recommendation(level):
    return {
        "HIGH": "BLOCK: Do not click links, reply, or share any information. Report the message and delete it.",
        "MEDIUM": "VERIFY: Do not act yet. Contact the sender through an official channel and check the link carefully.",
        "LOW": "Looks safe, but stay cautious: never share passwords or OTPs with anyone.",
    }[level]
