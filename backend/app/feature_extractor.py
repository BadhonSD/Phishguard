"""
Extracts the 53-feature vector used by the trained model, matching
feature_columns.joblib exactly. Every feature is derived purely from the URL
string -- no page fetch, no WHOIS/DNS, no external services -- so extraction is
synchronous and takes microseconds.

This is a deliberate v2 architecture change from the original 87-feature model
(Hannousse & Yahiouche schema), which depended on page content, WHOIS/DNS lookups,
and unreproducible external signals (google_index, page_rank) that caused most of
v1's false positives and required a headless browser + several external services
to approximate. See DOCUMENTATION.md for the full history. The model was retrained
on the Kaggle "Phishing Site URLs" dataset (549K raw URL + label rows, no
pre-extracted features) using training/colab_train.py, which contains this exact
same feature-extraction logic -- keep the two in sync if either changes.
"""

import ipaddress
import re
from urllib.parse import urlparse

import tldextract

SHORTENING_SERVICES = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "mcaf.ee", "cutt.ly", "shorte.st", "rebrand.ly",
    "tiny.cc", "clck.ru", "lnkd.in", "rb.gy", "shorturl.at",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "info",
    "loan", "win", "review", "kim", "country", "stream", "gdn", "mom",
    "party", "science", "racing", "click", "download",
}

SUSPICIOUS_EXTENSIONS = {"exe", "scr", "zip", "rar", "js", "jar", "bat", "apk", "msi"}

PHISH_HINT_WORDS = [
    "login", "signin", "verify", "account", "update", "secure", "banking",
    "confirm", "webscr", "ebayisapi", "password", "credential", "wp-admin",
    "admin", "suspend", "unlock", "validation", "security", "billing",
]

BRAND_NAMES = [
    "paypal", "apple", "microsoft", "amazon", "google", "facebook", "netflix",
    "bankofamerica", "wellsfargo", "chase", "instagram", "whatsapp", "linkedin",
    "dropbox", "adobe", "ebay", "yahoo", "outlook", "icloud", "americanexpress",
]


class InvalidURLError(ValueError):
    pass


def safe_urlparse(candidate: str) -> tuple[str, str, int | None]:
    """Returns (hostname, path, port). Real-world (especially phishing) URLs are
    frequently malformed in ways that make stdlib urlparse() raise ValueError instead
    of degrading gracefully -- e.g. a stray unbalanced "[" anywhere in the string trips
    its IPv6-literal heuristic ("Invalid IPv6 URL"), even when the string is otherwise a
    perfectly checkable URL. Falls back to a lightweight manual split rather than
    rejecting input outright, since that would mean this exact class of malformed junk
    -- much of which IS real phishing traffic -- could never be checked."""
    try:
        parsed = urlparse(candidate)
        return parsed.hostname or "", parsed.path or "", parsed.port
    except ValueError:
        pass

    rest = candidate.split("://", 1)[-1]
    cut = len(rest)
    for sep in ("/", "?", "#"):
        idx = rest.find(sep)
        if idx != -1:
            cut = min(cut, idx)
    authority = rest[:cut].rsplit("@", 1)[-1]  # drop userinfo
    path = rest[cut:]

    host, port = authority, None
    if ":" in authority and "[" not in authority:
        host, _, port_str = authority.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            host, port = authority, None
    return host.lower(), path, port


def _words(text: str) -> list[str]:
    return [w for w in re.split(r"[^a-zA-Z0-9]+", text) if w]


def _word_stats(words: list[str]) -> tuple[int, int, float]:
    if not words:
        return 0, 0, 0.0
    lengths = [len(w) for w in words]
    return min(lengths), max(lengths), sum(lengths) / len(lengths)


def _char_repeat(s: str) -> int:
    max_run = run = 1 if s else 0
    for i in range(1, len(s)):
        run = run + 1 if s[i] == s[i - 1] else 1
        max_run = max(max_run, run)
    return max_run


def _looks_random(domain: str) -> int:
    if len(domain) < 6:
        return 0
    vowels = set("aeiou")
    run = max_run = 0
    for ch in domain.lower():
        if ch.isalpha() and ch not in vowels:
            run += 1
            max_run = max(max_run, run)
        else:
            run = 0
    return 1 if max_run >= 5 else 0


def _abnormal_subdomain(subdomain: str) -> int:
    if not subdomain or subdomain == "www":
        return 0
    return 1 if re.search(r"\d", subdomain) or subdomain.count("-") >= 2 else 0


def _path_extension_flag(path: str) -> int:
    last_segment = path.rsplit("/", 1)[-1]
    if "." in last_segment:
        ext = last_segment.rsplit(".", 1)[-1].lower()
        return 1 if ext in SUSPICIOUS_EXTENSIONS else 0
    return 0


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _brand_typosquat(domain: str) -> int:
    """Catches classic typosquatting -- a domain crafted to visually resemble a
    known brand via a small character substitution/insertion/deletion/repetition
    (e.g. "paypaaa" for "paypal") -- that domain_in_brand's exact-substring check
    can never catch by construction. Flags domains within a small edit distance
    of a brand name, but NOT already an exact substring match (that's
    domain_in_brand's job) and not absurdly short (to avoid false positives on
    short generic words that happen to be edit-distance-close to a short brand)."""
    domain = domain.lower()
    if len(domain) < 4:
        return 0
    for brand in BRAND_NAMES:
        if brand in domain:
            continue  # already an exact match, not a typosquat
        threshold = 2 if len(brand) >= 5 else 1
        if abs(len(domain) - len(brand)) <= threshold and _levenshtein(domain, brand) <= threshold:
            return 1
    return 0


def extract_features(url: str) -> dict:
    if not url or not url.strip():
        raise InvalidURLError("url must not be empty")

    candidate = url if "://" in url else f"http://{url}"
    hostname, path, port = safe_urlparse(candidate)
    if not hostname or "." not in hostname and not _is_ip(hostname):
        raise InvalidURLError("url does not look like a valid URL")

    # From here on, all character-count/length features are computed on the
    # scheme-normalized `candidate`, not the raw user input. This matters a lot:
    # the training dataset had a severe artifact where scheme presence/absence was
    # itself (accidentally) a near-perfect class signal (see DOCUMENTATION.md), so
    # every feature must be blind to whether the caller happened to type "https://"
    # -- otherwise the model reads "has a scheme" as "looks like training's rare
    # phishing-with-scheme pattern" and flags nearly everything real users submit.
    url = candidate

    ext = tldextract.extract(candidate)

    raw_words = _words(url)
    host_words = _words(hostname)
    path_words = _words(path)
    shortest_raw, longest_raw, avg_raw = _word_stats(raw_words)
    shortest_host, longest_host, avg_host = _word_stats(host_words)
    shortest_path, longest_path, avg_path = _word_stats(path_words)

    digits_url = sum(c.isdigit() for c in url)
    digits_host = sum(c.isdigit() for c in hostname)

    return {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": 1 if _is_ip(hostname) else 0,
        "nb_dots": url.count("."),
        "nb_hyphens": url.count("-"),
        "nb_at": url.count("@"),
        "nb_qm": url.count("?"),
        "nb_and": url.count("&"),
        "nb_or": url.count("|"),
        "nb_eq": url.count("="),
        "nb_underscore": url.count("_"),
        "nb_tilde": url.count("~"),
        "nb_percent": url.count("%"),
        "nb_slash": url.count("/"),
        "nb_star": url.count("*"),
        "nb_colon": url.count(":"),
        "nb_comma": url.count(","),
        "nb_semicolumn": url.count(";"),
        "nb_dollar": url.count("$"),
        "nb_space": url.count(" ") + url.count("%20"),
        "nb_www": url.lower().count("www"),
        "nb_com": url.lower().count("com"),
        "nb_dslash": url.count("//") - 1,
        "http_in_path": 1 if "http" in path.lower() else 0,
        "https_token": 1 if "https" in ext.domain.lower() or "https" in ext.subdomain.lower() else 0,
        "ratio_digits_url": digits_url / len(url) if url else 0.0,
        "ratio_digits_host": digits_host / len(hostname) if hostname else 0.0,
        "punycode": 1 if "xn--" in hostname.lower() else 0,
        "port": 1 if port else 0,
        "tld_in_path": 1 if ext.suffix and ext.suffix in path.lower() else 0,
        "tld_in_subdomain": 1 if ext.suffix and ext.suffix in ext.subdomain.lower() else 0,
        "abnormal_subdomain": _abnormal_subdomain(ext.subdomain),
        "nb_subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "prefix_suffix": 1 if "-" in ext.domain else 0,
        "random_domain": _looks_random(ext.domain),
        "shortening_service": 1 if hostname.lower() in SHORTENING_SERVICES else 0,
        "path_extension": _path_extension_flag(path),
        "length_words_raw": len(raw_words),
        "char_repeat": _char_repeat(url),
        "shortest_words_raw": shortest_raw,
        "shortest_word_host": shortest_host,
        "shortest_word_path": shortest_path,
        "longest_words_raw": longest_raw,
        "longest_word_host": longest_host,
        "longest_word_path": longest_path,
        "avg_words_raw": avg_raw,
        "avg_word_host": avg_host,
        "avg_word_path": avg_path,
        "phish_hints": sum(url.lower().count(w) for w in PHISH_HINT_WORDS),
        "domain_in_brand": 1 if ext.domain.lower() in BRAND_NAMES else 0,
        "brand_in_subdomain": 1 if any(b in ext.subdomain.lower() for b in BRAND_NAMES) and ext.domain.lower() not in BRAND_NAMES else 0,
        "brand_in_path": 1 if any(b in path.lower() for b in BRAND_NAMES) else 0,
        "suspecious_tld": 1 if ext.suffix.lower() in SUSPICIOUS_TLDS else 0,
        "brand_typosquat": _brand_typosquat(ext.domain),
        "brand_in_domain": 1 if any(
            b in ext.domain.lower() for b in BRAND_NAMES
        ) and ext.domain.lower() not in BRAND_NAMES else 0,
    }


def build_feature_vector(url: str, feature_columns: list[str]) -> tuple[list[float], dict]:
    """Returns (ordered feature vector matching feature_columns, raw feature dict)."""
    features = extract_features(url)
    vector = [float(features.get(col, 0)) for col in feature_columns]
    return vector, features
