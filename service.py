"""Framework-free analysis service. Used by main.py."""
import time
import url_check
from explain import build_explanation, llm_analyze
from logic import combine_scores, risk_tier
from scam_rules import rule_analysis

BLOCKLIST = url_check.load_blocklist()  # replaced atomically by refresh_blocklist()
MAX_TEXT = 5000
LABEL = {"danger": "High risk", "warning": "Medium risk", "safe": "Low risk"}
LINK_ADVICE = {
    "danger": ["Do not enter passwords, payment details or OTPs.",
               "Open the organisation's site by typing its address yourself.",
               "Report the link and block the sender."],
    "warning": ["Verify the destination before entering any personal details.",
                "Open the official app or website yourself instead."],
    "safe": ["No risky URL patterns found. That does not prove the site is safe, so check the address before signing in."],
}


def refresh_blocklist():
    global BLOCKLIST
    if url_check.update_blocklist() is not None:
        BLOCKLIST = url_check.load_blocklist()  # single reference swap: readers never see a half-empty list
    return len(BLOCKLIST)


def analyze_text(text: str, lang: str = "en") -> dict:
    text = (text or "").strip()[:MAX_TEXT]
    if len(text) < 3:
        raise ValueError("Paste a message to analyze (at least 3 characters).")
    t0 = time.time()
    rules = rule_analysis(text)
    url_score, urls = url_check.scan_text_urls(text, BLOCKLIST)
    ai = llm_analyze(text, lang)
    score = combine_scores(ai["prob"] if ai else None, rules["score"], url_score)
    tier = risk_tier(score)
    exp = build_explanation(ai, rules["tactics"], urls, tier)
    return {"kind": "text", "tier": tier, "label": LABEL[tier], "score": score,
            "signals": ([{"name": "AI judgement", "score": ai["prob"]}] if ai else [])
                       + [{"name": "Manipulation tactics", "score": rules["score"]}]
                       + ([{"name": "Link risk", "score": url_score}] if url_score is not None else []),
            "scam_type": ai["type"] if ai and ai["type"].lower() != "none" else "",
            "tactics": rules["tactics"], "links": [{"host": r["host"], "score": r["score"], "flags": r["flags"]} for r in urls], "reasons": exp["reasons"], "advice": exp["advice"],
            "explained_by": exp["source"], "method": "AI + rules + link checks" if ai else "Rules + link checks", "seconds": round(time.time() - t0, 2)}


def analyze_link(link: str) -> dict:
    link = (link or "").strip()
    host, scheme = url_check.host_of(link)
    if (not link or " " in link or len(link) > 2048 or "." not in host
            or ("://" in link and scheme not in ("http", "https"))):
        raise ValueError("That doesn't look like a valid link. Example: https://example.com/login")
    t0 = time.time()
    res = url_check.check_url(link, BLOCKLIST)
    tier = risk_tier(res["score"])
    return {"kind": "link", "tier": tier, "label": LABEL[tier], "score": res["score"],
            "signals": [{"name": "Link structure", "score": res["score"]}], "tactics": {},
            "reasons": res["flags"] or ["No risky URL patterns detected."], "advice": LINK_ADVICE[tier],
            "explained_by": "rules", "method": "Offline link checks (never opened)",
            "host": res["host"], "seconds": round(time.time() - t0, 3)}
