"""Rule-based scam signal: whole-word regexes grouped into named, weighted manipulation tactics."""
import re

TACTICS = {
    "Urgency / pressure": (20, [r"\burgent(ly)?\b", r"\bact now\b", r"\bimmediately\b", r"\bwithin \d+ (hours?|minutes?)\b",
                           r"\bfinal notice\b", r"\blast (warning|chance)\b", r"\blimited time\b", r"\bexpires? (today|soon)\b"]),
    "Fake authority": (20, [r"\byour bank\b", r"\bbank (officer|manager|official)\b", r"\birs\b", r"\bincome tax (dept|department|office)\b",
                       r"\bcustoms (duty|office|department|parcel)\b", r"\b(police|cyber ?crime) (officer|case|complaint|department)\b",
                       r"\bcustomer (care|support)\b", r"\bkyc\b", r"\bsecurity team\b", r"\bdigital arrest\b", r"\b(cbi|trai|rbi)\b"]),
    "Asks for sensitive info": (35, [r"\botp\b", r"\bone[- ]time password\b", r"\bcvv\b", r"\bcard number\b", r"\bbank details\b",
                                r"\bsocial security\b", r"\baadhaar\b", r"\bupi pin\b",
                                r"\b(share|send|enter|reveal|tell|give|confirm)\b[^.\n]{0,25}\b(pin|password|passcode)\b"]),
    "Threat / fear": (25, [r"account (is |has been |will be )?(blocked|suspended|locked|closed|deactivated)", r"\bunauthori[sz]ed\b",
                      r"\bsuspicious activity\b", r"\blegal action\b", r"\barrest(ed)?\b", r"\bsim (will be )?(blocked|deactivated)\b"]),
    "Too good to be true": (20, [r"\byou (have )?won\b", r"\bclaim your (prize|reward)\b", r"\blottery\b", r"\btax refund\b",
                            r"\bfree gift\b", r"\bwork from home\b[^.\n]{0,30}\bearn\b"]),
    "Unusual payment method": (25, [r"\bgift cards?\b", r"\bwire transfer\b", r"\bcrypto(currency)?\b", r"\bbitcoin\b",
                               r"\b(processing|registration|advance|refundable) fee\b", r"\bpay (the |a )?(customs )?(duty|fine|charges?)\b"]),
    "Pushes you to click": (15, [r"\bclick (here|the link|below)\b", r"\bverify (your )?(account|identity|details)\b",
                            r"\breactivate\b", r"\bpayment failed\b", r"\bupdate your (kyc|details|pan)\b"]),
}
# Hindi / Telugu / Hinglish patterns (no \\b: it is unreliable around Indic combining marks)
_INDIC = {"Urgency / pressure": [r"तुरंत", r"जल्द से जल्द", r"వెంటనే", r"\bturant\b"],
          "Fake authority": [r"केवाईसी", r"కేవైసీ"],
          "Asks for sensitive info": [r"ओटीपी", r"ఓటీపీ", r"पासवर्ड", r"పాస్వర్డ్"],
          "Threat / fear": [r"खाता (बंद|ब्लॉक)", r"ఖాతా (బ్లాక్|నిలిపివేయ)"],
          "Too good to be true": [r"इनाम", r"लॉटरी", r"బహుమతి", r"లాటరీ"]}
for _k, _v in _INDIC.items():
    TACTICS[_k][1].extend(_v)
_COMPILED = {t: (w, [re.compile(p, re.I) for p in pats]) for t, (w, pats) in TACTICS.items()}
URL_HINT = re.compile(r"https?://|www\.", re.I)


def rule_analysis(text: str) -> dict:
    """Returns {"score": 0-100, "tactics": {tactic: [matched phrases]}}."""
    found, score = {}, 0
    for tactic, (weight, pats) in _COMPILED.items():
        hits = sorted({m.group(0).lower() for p in pats for m in p.finditer(text)})
        if hits:
            found[tactic] = hits
            score += weight
    if found and URL_HINT.search(text):
        score += 15
    if "Asks for sensitive info" in found and len(found) >= 2:
        score += 15  # asking for secrets while pressuring or impersonating is the classic pattern
    if "Too good to be true" in found and "Unusual payment method" in found:
        score += 15  # advance-fee pattern: win/earn something, but pay first
    return {"score": min(100, score), "tactics": found}
