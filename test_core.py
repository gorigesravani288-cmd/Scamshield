import service, url_check as u
from scam_rules import rule_analysis
from logic import combine_scores, risk_tier

def tier_of(link): return u.check_url(link)["score"]

def test_legit_domains_not_flagged():
    for l in ["https://www.amazon.co.in/orders", "https://accounts.google.com", "https://thirsty.com", "https://pineapple.com", "https://maple.com"]:
        assert tier_of(l) == 0, l

def test_scam_links_flagged():
    for l in ["http://paypal-secure-login.xyz/verify", "https://google.evil.com", "http://192.168.1.5/login", "https://paypa1.com"]:
        assert tier_of(l) >= 45, l

def test_malformed_url_no_crash():
    assert u.check_url("http://[abc")["score"] > 0

def test_clean_link_does_not_dilute():
    msg = "URGENT: your bank asked you to share the OTP immediately https://example.com"
    assert service.analyze_text(msg)["tier"] == "danger"

def test_otp_scam_is_high():
    assert risk_tier(combine_scores(None, rule_analysis("Urgent! Bank officer here, share your OTP")["score"])) == "danger"

def test_benign_text():
    assert service.analyze_text("Lunch at 1? I'll bring the first draft of the report.")["tier"] == "safe"

def test_blocklist_forces_high():
    assert combine_scores(None, 0, 100) >= 90

def test_ai_blend_and_floor():
    assert combine_scores(90, 0) >= 49 and combine_scores(0, 85) >= 60
    assert risk_tier(combine_scores(5, 0)) == "safe"

def test_llm_output_validated():
    from explain import _clean
    assert _clean("not a list") is None and _clean(["a", {"x": 1}, " "]) == ["a"]
