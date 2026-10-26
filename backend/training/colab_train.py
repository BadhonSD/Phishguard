# ============================================================
# Phishing URL Detection - Lexical-only Model Training (Google Colab)
# Dataset: phishing_site_urls.csv (Kaggle "Phishing Site URLs", 549k rows,
#          columns: URL, Label ["good"/"bad"])
#
# Feature set: 53 URL-string-only features, ported 1:1 from this project's
# app/feature_extractor.py (the lexical functions that never needed a network
# call). No WHOIS/DNS/PageRank/page-content features -- this dataset doesn't
# have that data, and dropping them is the whole point: it makes inference
# near-instant and removes every external dependency that caused trouble
# (google_index, page_rank, live page rendering, bot walls, etc).
# ============================================================

# --- 1. Setup ---
!pip install -q tldextract xgboost scikit-learn pandas joblib

from google.colab import files
print("Upload phishing_site_urls.csv")
uploaded = files.upload()

# --- 2. Load data ---
import pandas as pd

df = pd.read_csv("phishing_site_urls.csv")
df = df.dropna(subset=["URL", "Label"])
print(df.shape)
print(df["Label"].value_counts())

# --- 2b. Augment "good" with real bare domains (fixes a real representativeness gap) ---
# After normalizing for the scheme artifact (see extract_lexical_features below), a bare
# domain with zero path (nb_slash==2, i.e. just "http://domain.tld" and nothing after) is
# nearly ABSENT from "good" (0.02%, 63/392,924 rows) but shows up meaningfully in "bad"
# (2.84%, 4,439/156,422) -- because this "good" list was built from specific pages/articles
# on popular sites, essentially never their bare homepage. But checking a bare homepage
# (e.g. "google.com") is one of the most common real-world uses of a URL checker, and
# without this fix the model reads "no path at all" as a phishing signal purely because
# legitimate bare homepages were almost never shown to it as "good" during training.
# Fix: add real bare domains from the free, reputable Tranco top-sites list as additional
# "good" examples so bare homepages are properly represented.
#
# IMPORTANT: add the bare form ("google.com"), the www-prefixed form
# ("www.google.com"), AND a rotating set of other common real-world subdomains --
# a first attempt used only bare+www, which taught the model "www SPECIFICALLY is
# safe" rather than "having a subdomain in general is normal": verified via
# per-instance contributions that en.wikipedia.org (nb_subdomains=1, non-www) still
# scored 89% phishing post-fix, while www.wikipedia.org (nb_subdomains=1, www)
# scored under 1% -- same feature value, wildly different treatment, because every
# augmented "good" example with a subdomain was specifically "www". Rotating
# through a handful of other common, real subdomain words (avoiding anything that
# overlaps PHISH_HINT_WORDS, e.g. "secure"/"account"/"admin", since those are
# already meaningful phishing-hint signals elsewhere and mixing them in here would
# muddy that) breaks the "only www counts" pattern without needing a real per-domain
# subdomain list, which isn't available for free at this scale.
import io
import zipfile
import requests as _requests

resp = _requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=60)
with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
    with zf.open("top-1m.csv") as f:
        tranco_domains = [line.decode().strip().split(",", 1)[1] for line in f.readlines()[:100_000]]

COMMON_SUBDOMAINS = ["mail", "blog", "shop", "support", "help", "docs", "app", "m", "en", "news", "api", "status"]
rotating_subdomain_urls = [
    f"{COMMON_SUBDOMAINS[i % len(COMMON_SUBDOMAINS)]}.{d}" for i, d in enumerate(tranco_domains)
]

tranco_urls = tranco_domains + [f"www.{d}" for d in tranco_domains] + rotating_subdomain_urls
tranco_df = pd.DataFrame({"URL": tranco_urls, "Label": "good"})
df = pd.concat([df, tranco_df], ignore_index=True)
print("After augmentation:", df.shape)
print(df["Label"].value_counts())

# --- 3. Feature extraction (ported from app/feature_extractor.py) ---
import re
import ipaddress
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


def _words(text):
    return [w for w in re.split(r"[^a-zA-Z0-9]+", text) if w]


def _word_stats(words):
    if not words:
        return 0, 0, 0.0
    lengths = [len(w) for w in words]
    return min(lengths), max(lengths), sum(lengths) / len(lengths)


def _char_repeat(s):
    max_run = run = 1 if s else 0
    for i in range(1, len(s)):
        run = run + 1 if s[i] == s[i - 1] else 1
        max_run = max(max_run, run)
    return max_run


def _looks_random(domain):
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


def _abnormal_subdomain(subdomain):
    if not subdomain or subdomain == "www":
        return 0
    return 1 if re.search(r"\d", subdomain) or subdomain.count("-") >= 2 else 0


def _path_extension_flag(path):
    last_segment = path.rsplit("/", 1)[-1]
    if "." in last_segment:
        ext = last_segment.rsplit(".", 1)[-1].lower()
        return 1 if ext in SUSPICIOUS_EXTENSIONS else 0
    return 0


def _is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _levenshtein(a, b):
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def _brand_typosquat(domain):
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
            continue
        threshold = 2 if len(brand) >= 5 else 1
        if abs(len(domain) - len(brand)) <= threshold and _levenshtein(domain, brand) <= threshold:
            return 1
    return 0


def extract_lexical_features(raw_url: str) -> dict:
    """Same logic as app/feature_extractor.py's lexical section -- keep these two
    in sync if you ever change one."""
    url = raw_url.strip()
    candidate = url if "://" in url else f"http://{url}"

    from urllib.parse import urlparse
    # Scraped phishing URLs are frequently malformed (unbalanced brackets/quotes,
    # stray control chars, ...) and urlparse raises ValueError on some of those
    # (e.g. "Invalid IPv6 URL") instead of just failing to parse gracefully. Fall
    # back to an empty hostname/path rather than losing the whole row -- the
    # URL-level char-count features below still work fine either way.
    try:
        parsed = urlparse(candidate)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        port = parsed.port
    except ValueError:
        hostname = ""
        path = ""
        port = None

    # CRITICAL: this dataset has a severe artifact where 0/392,924 "good" URLs have
    # a scheme prefix vs 1,081/156,422 "bad" ones do -- i.e. scheme presence is
    # itself (accidentally) a strong class signal. Since every real URL a user
    # submits at inference time naturally has "https://", training on raw `url`
    # would make the model read "has a scheme" as "looks like the rare
    # phishing-with-scheme pattern" and flag nearly everything. Normalizing to the
    # scheme-having `candidate` for ALL character-count/length features below
    # removes that artifact by making scheme presence constant across the board.
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
    }


# --- 2c. Augment "bad" with synthetic brand typosquats ---
# brand_typosquat (added above) barely discriminates on the raw data alone: only
# 115-178 real "bad" rows out of 156,422 actually match it (0.07-0.11%), and
# "good" has an almost identical rate (0.06-0.10%) purely from coincidental
# matches (e.g. "case" vs "chase", "mangosoft"/"netlib" vs "microsoft" sharing a
# common suffix) -- confirmed by sampling actual hits. XGBoost learned near-zero
# weight for the feature as a result: there's a real signal in the rare organic
# examples (payspl, paypol, paiypal, faoebook, facebbook all show up in "bad"),
# but it's diluted by comparably-sized coincidental noise in "good". Same root
# cause as the Bug 2 fix above (not enough real examples for the model to learn
# from) -- same category of fix: generate systematic, clean synthetic examples
# instead of relying on rare organic ones. This directly teaches the deletion/
# transposition/leetspeak-substitution/doubling patterns real typosquatters use.
LEETSPEAK = {"o": "0", "i": "1", "e": "3", "a": "4", "s": "5", "l": "1", "t": "7"}


def _typosquat_variants(brand):
    variants = set()
    for i in range(len(brand)):
        variants.add(brand[:i] + brand[i + 1:])  # deletion
        variants.add(brand[: i + 1] + brand[i] + brand[i + 1:])  # doubling
    for i in range(len(brand) - 1):
        chars = list(brand)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        variants.add("".join(chars))  # adjacent transposition
    for i, ch in enumerate(brand):
        if ch in LEETSPEAK:
            variants.add(brand[:i] + LEETSPEAK[ch] + brand[i + 1:])  # leetspeak substitution
    variants.discard(brand)
    # Drop anything under 5 chars -- short deletion results can land on a generic
    # dictionary word (e.g. "chase" -> "case", "ebay" -> "bay") that's a real risk
    # of being a legitimate short domain in its own right, not just a typosquat.
    return {v for v in variants if len(v) >= 5}


typosquat_urls = [f"{v}.com" for brand in BRAND_NAMES for v in _typosquat_variants(brand)]
typosquat_df = pd.DataFrame({"URL": typosquat_urls, "Label": "bad"})
df = pd.concat([df, typosquat_df], ignore_index=True)
print("After typosquat augmentation:", df.shape, "added", len(typosquat_urls), "synthetic typosquat rows")
print(df["Label"].value_counts())

# Sanity check on a couple of rows before running it over all 549k
print(extract_lexical_features("https://www.google.com"))
print(extract_lexical_features(df["URL"].iloc[0]))

# tqdm gives a progress bar for the ~549k-row apply (a few minutes on Colab's CPU)
from tqdm.auto import tqdm
tqdm.pandas()

feature_dicts = df["URL"].astype(str).progress_apply(extract_lexical_features)
X = pd.DataFrame(list(feature_dicts))
y = df["Label"].map({"bad": 1, "good": 0})  # 1 = phishing, matches app/main.py's convention

print("Feature matrix:", X.shape)
print(X.head())

# --- 4. Train/test split ---
from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# --- 5. Train models -- compare a few ---
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix

models = {
    "LogisticRegression": LogisticRegression(max_iter=1000),
    "RandomForest": RandomForestClassifier(n_estimators=300, max_depth=20, n_jobs=-1, random_state=42),
    "XGBoost": XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                              eval_metric="logloss", random_state=42, n_jobs=-1),
}

results = {}
for name, model in models.items():
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, probs)
    print(f"\n=== {name} (AUC: {auc:.4f}) ===")
    print(classification_report(y_test, preds))
    results[name] = (model, auc)

# --- 6. Pick best model ---
best_name = max(results, key=lambda k: results[k][1])
best_model = results[best_name][0]
print(f"\nBest model: {best_name} with AUC {results[best_name][1]:.4f}")

# --- 7. Feature importance (for explainability in the app) ---
import matplotlib.pyplot as plt

if hasattr(best_model, "feature_importances_"):
    importances = pd.Series(best_model.feature_importances_, index=X.columns)
    importances.sort_values(ascending=False).head(15).plot(kind="barh", figsize=(8, 6))
    plt.title(f"Top 15 Features - {best_name}")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig("feature_importance.png")
    plt.show()

# --- 8. Confusion matrix ---
cm = confusion_matrix(y_test, best_model.predict(X_test))
print("Confusion Matrix:\n", cm)

# --- 9. Save model + feature column order (CRITICAL for FastAPI inference) ---
import joblib

joblib.dump(best_model, "phishing_model.joblib")
joblib.dump(list(X.columns), "feature_columns.joblib")

print("\nSaved: phishing_model.joblib, feature_columns.joblib")

# --- 10. Download to local machine ---
files.download("phishing_model.joblib")
files.download("feature_columns.joblib")
files.download("feature_importance.png")
