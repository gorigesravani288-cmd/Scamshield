"""URL scanner: extracts links from text and scores them with offline heuristics
plus an optional phishing blocklist (blocklist.txt, one URL or domain per line)."""
import ipaddress, os, re, urllib.request
from urllib.parse import urlparse

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+", re.I)
BARE_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:xyz|top|tk|click|icu|buzz|zip|support|gq|ml|cf|ga|rest|bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd)\b(?:/[^\s<>\"')]*)?", re.I)
SHORT_RE = re.compile(r"\b(?:bit\.ly|tinyurl\.com|cutt\.ly|rb\.gy|is\.gd|t\.co|ow\.ly|shorturl\.at|goo\.gl)/[^\s<>\"')]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly", "shorturl.at"}
RISKY_TLDS = {"zip", "xyz", "top", "tk", "click", "gq", "ml", "cf", "ga", "icu", "rest", "buzz", "support"}
BRANDS = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "facebook", "instagram", "whatsapp",
          "sbi", "hdfc", "icici", "paytm", "phonepe", "flipkart", "irs", "fedex", "dhl", "usps"]
SLD_PARTS = {"co", "com", "org", "net", "gov", "ac", "edu", "nic", "res"}  # co.in, com.au, gov.uk ...
LOGIN_WORDS = re.compile(r"login|signin|verify|secure|update|kyc|wallet|otp|account", re.I)
LOOKALIKE = str.maketrans("013", "ole")
FREE_FEEDS = {"openphish": "https://openphish.com/feed.txt"}


def extract_urls(text):
    found = [u.rstrip(".,;:!?") for u in URL_RE.findall(text)]
    found += [u.rstrip(".,;:!?") for u in SHORT_RE.findall(text) if not any(u in f for f in found)]
    found += [u.rstrip(".,;:!?") for u in BARE_RE.findall(text) if not any(u in f for f in found)]
    return list(dict.fromkeys(found))[:10]


def parse(url):
    try:
        return urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return None


def host_of(url):
    """(hostname, scheme). scheme is '' when the user gave none. Never raises."""
    p = parse(url)
    if p is None:
        return "", ""
    return (p.hostname or "").lower().rstrip("."), (p.scheme if "://" in url else "")


def split_host(host):
    """-> (subdomain labels, registrable label, tld). Handles co.in / com.au style suffixes."""
    parts = host.split(".")
    k = 3 if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SLD_PARTS else 2
    k = min(k, len(parts))
    return parts[:-k], parts[-k], parts[-1]


def _lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def load_blocklist(path="blocklist.txt"):
    out = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    h, _ = host_of(line)
                    if h:
                        out.add(h)
    return out


def update_blocklist(path="blocklist.txt", feed="openphish"):
    """Download a free phishing feed. Returns number of lines, or None if offline/failed."""
    try:
        with urllib.request.urlopen(FREE_FEEDS[feed], timeout=15) as r:
            data = r.read().decode("utf-8", "ignore")
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        return len(data.splitlines())
    except Exception:
        return None


def check_url(url, blocklist=frozenset()):
    host, scheme = host_of(url)
    flags, score = [], 0

    def add(w, msg):
        nonlocal score
        score += w
        flags.append(msg)

    if not host:
        return {"url": url, "host": "", "score": 30, "flags": ["Link could not be read properly"]}
    parts = host.split(".")
    if any(".".join(parts[i:]) in blocklist for i in range(len(parts) - 1)) or host in blocklist:
        return {"url": url, "host": host, "score": 100, "flags": ["Listed in phishing blocklist"]}
    try:
        ipaddress.ip_address(host)
        add(40, "Uses a raw IP address instead of a domain name")
        return {"url": url, "host": host, "score": min(100, score + (15 if scheme == "http" else 0)), "flags": flags}
    except ValueError:
        pass
    p = parse(url)
    if host in SHORTENERS:
        add(25, "Shortened link hides the real destination")
    if scheme == "http":
        add(15, "Not encrypted (http, not https)")
    if p is not None and p.username is not None:
        add(40, "Contains '@' which can disguise the real site")
    try:
        host.encode("ascii")
        if host.startswith("xn--") or ".xn--" in host:
            raise UnicodeError
    except UnicodeError:
        add(35, "Look-alike (non-standard) characters in the domain")
    sub, sld, tld = split_host(host)
    if len(parts) >= 2 and tld in RISKY_TLDS:
        add(20, f"Domain ending '.{tld}' is common in scams")
    if len(sub) >= 3:
        add(15, "Unusually many subdomains")
    if host.count("-") >= 3:
        add(15, "Many hyphens in the domain name")
    tokens = set(re.split(r"[-_\d]+", sld))
    norm = sld.translate(LOOKALIKE)
    sub_tokens = set(re.split(r"[-_\d.]+", ".".join(sub)))
    for b in BRANDS:
        if sld == b:
            break  # the brand's own name (amazon.co.in, accounts.google.com)
        if b in sub_tokens or (len(b) >= 6 and any(b in label for label in sub)):
            add(45, f"Uses '{b}' as a subdomain of a different site"); break
        if b in tokens or (len(b) >= 6 and b in sld):
            add(45, f"Domain contains '{b}' but is not the real {b} site"); break
        if len(b) >= 5 and (norm == b or (len(b) >= 6 and len(sld) >= 5 and _lev(sld, b) == 1)):
            add(45, f"Domain looks like a misspelling of '{b}'"); break
    path = (p.path + "?" + p.query) if p is not None else ""
    if score and LOGIN_WORDS.search(path + host):
        add(10, "Asks you to log in or verify on an unfamiliar link")
    if len(url) > 120:
        add(10, "Very long link")
    return {"url": url, "host": host, "score": min(100, score), "flags": flags}


def scan_text_urls(text, blocklist=frozenset()):
    """Returns (worst url score or None if no URLs, [per-url results])."""
    results = [check_url(u, blocklist) for u in extract_urls(text)]
    return (max(r["score"] for r in results), results) if results else (None, [])
