# PhishGuard — Phishing URL Detector (PWA + FastAPI)

This document explains how the system works end to end, and records what was built,
tested, and fixed along the way.

**This is the v2 architecture** — a pure lexical (URL-string-only) model with no
network calls at inference time. It replaced an earlier v1 design (87 features,
live page rendering, WHOIS/DNS/PageRank lookups) that turned out to be both slow
(3–12s per request) and structurally hard to make accurate, because it depended on
external signals with no free, reliable live source. That entire v1 story —
useful background on *why* v2 looks the way it does — is preserved in
**Appendix A**.

## 1. What this is

A two-part app:

- **Backend** (`backend/app/`): a FastAPI service that takes a URL, computes a 54-feature
  vector from it — pure string parsing, no network calls — runs a trained XGBoost
  model (`backend/models/phishing_model.joblib`), and returns a phishing probability plus the top
  contributing features. Typical response time: **75–150ms**.
- **Frontend** (`frontend/`): an installable PWA (plain HTML/JS/CSS, no framework)
  with a manual URL-check form, a live QR-code scanner, and a local history view.
  Unchanged from v1 — see §3.

```
┌─────────────────────┐        POST /api/check-url        ┌──────────────────────────────┐
│   PWA (frontend/)    │ ─────────────────────────────────▶│   FastAPI (backend/app/)     │
│  index.html/app.js   │                                    │  main.py                     │
│  - URL form          │◀─────────────────────────────────  │  → feature_extractor.py      │
│  - QR scanner        │        { is_phishing, confidence,  │  → model_loader.py           │
│  - IndexedDB history │          top_features[] }          │  → models/phishing_model     │
└─────────────────────┘                                    └──────────────────────────────┘
```

## 2. Backend

### 2.1 File layout

| File | Responsibility |
|---|---|
| `backend/app/main.py` | FastAPI app, CORS, `/api/health`, `/api/check-url` |
| `backend/app/schemas.py` | Pydantic request/response models + URL validation |
| `backend/app/model_loader.py` | Loads `phishing_model.joblib` + `feature_columns.joblib` once at startup |
| `backend/app/feature_extractor.py` | Turns a raw URL into the 54-feature vector the model expects — pure string parsing, synchronous, no I/O |
| `backend/requirements.txt` | fastapi, uvicorn, pydantic, scikit-learn, xgboost, joblib, tldextract |
| `backend/training/colab_train.py` | The Colab training script — see §2.6 |

Compare to v1's file layout (Appendix A §A.1): `browser_loader.py`, WHOIS/DNS/
Playwright/requests/beautifulsoup4 dependencies, and the Tranco data file are all
gone. There is nothing left in the backend that talks to the network.

### 2.2 Startup and request flow

1. On startup, `model_loader.bundle.load()` reads `phishing_model.joblib` (an
   `XGBClassifier`) and `feature_columns.joblib` (the exact ordered list of 54
   feature names the model was trained on) **once**, not per request.
2. `POST /api/check-url` receives `{"url": "..."}`.
3. `schemas.URLCheckRequest` rejects empty strings, whitespace, overly long input, and
   anything that doesn't parse into a URL with a dotted hostname — with a specific
   `422` message for each case. It uses the same `safe_urlparse` helper as feature
   extraction (see §2.3) so validation and extraction never disagree about what a
   URL's hostname/path even are.
4. `feature_extractor.build_feature_vector(url, feature_columns)` computes all 54
   features and orders them to match `feature_columns` exactly (single source of
   truth — the vector is built by looking each name up in a dict, not by hardcoding
   order twice). This is pure computation — no network calls, no async, done in
   well under a millisecond.
5. `model.predict_proba([vector])[0][1]` gives the probability of the "phishing"
   class. `is_phishing = confidence >= 0.5`.
6. The top 5 features by **per-instance contribution to this specific prediction**
   (XGBoost's `pred_contribs`, a SHAP-equivalent, no extra dependency — falls back
   to `coef_ × value` or `feature_importances_ × value` for non-XGBoost models) are
   returned as `top_features`. This is deliberately *not* global importance — see
   Appendix A §A.6c for why that distinction mattered in practice.

### 2.3 Resilient URL parsing

`safe_urlparse()` in `feature_extractor.py` wraps stdlib `urlparse()`. Real-world
(especially phishing) URLs are frequently malformed in ways that make `urlparse()`
raise `ValueError` instead of degrading gracefully — e.g. a stray unbalanced `[`
anywhere in the string trips its IPv6-literal heuristic ("Invalid IPv6 URL"), even
when the string is otherwise a perfectly checkable URL. `safe_urlparse` falls back
to a lightweight manual split (strip scheme, cut at the first `/`/`?`/`#`, strip
userinfo/port) rather than rejecting the input outright — rejecting it would mean
this exact class of malformed junk, much of which *is* real phishing traffic,
could never be checked. Stress-tested against 17 pathological inputs (unbalanced
brackets, null bytes, empty strings, multiple `@`, extremely long strings, etc.) —
all pass.

### 2.4 `/api/check-url` — response shape

```json
{
  "url": "https://www.google.com",
  "is_phishing": false,
  "confidence": 0.018853314220905304,
  "top_features": [
    { "feature": "nb_slash", "value": 2, "importance": -3.018 },
    { "feature": "domain_in_brand", "value": 1, "importance": -0.972 },
    { "feature": "length_hostname", "value": 14, "importance": 0.910 },
    { "feature": "shortest_word_path", "value": 0, "importance": -0.776 },
    { "feature": "nb_dots", "value": 2, "importance": -0.613 }
  ]
}
```

`confidence` is always the probability of the *phishing* class (0–1), regardless of
which side of 0.5 it landed on — this keeps the frontend's badge thresholds simple.
`importance` here is a **signed per-instance contribution** (log-odds space):
negative pushes toward "safe", positive pushes toward "phishing" — not a 0–1
global-importance percentage.

### 2.5 The 54 features

All computed purely from the URL string — no page fetch, no WHOIS/DNS, no external
services. Categories:

- **Character/structure counts**: `length_url`, `length_hostname`, `ip` (literal IP
  host), `nb_dots`, `nb_hyphens`, `nb_at`, `nb_qm`, `nb_and`, `nb_or`, `nb_eq`,
  `nb_underscore`, `nb_tilde`, `nb_percent`, `nb_slash`, `nb_star`, `nb_colon`,
  `nb_comma`, `nb_semicolumn`, `nb_dollar`, `nb_space`, `nb_www`, `nb_com`,
  `nb_dslash`, `http_in_path`, `https_token`, `ratio_digits_url`,
  `ratio_digits_host`, `punycode`, `port`.
- **Domain/TLD structure** (via `tldextract`): `tld_in_path`, `tld_in_subdomain`,
  `abnormal_subdomain`, `nb_subdomains`, `prefix_suffix`, `random_domain`
  (consonant-run heuristic), `shortening_service` (known shortener hostnames),
  `path_extension` (suspicious file extensions), `suspecious_tld`.
- **Word-tokenization stats**: `length_words_raw`, `char_repeat`,
  `shortest/longest/avg_words_raw`, `shortest/longest/avg_word_host`,
  `shortest/longest/avg_word_path`.
- **Keyword/brand checks**: `phish_hints` (count of login/verify/secure/etc.
  keywords), `domain_in_brand`, `brand_in_subdomain`, `brand_in_path` (exact
  substring matches against a small hardcoded brand list — see `BRAND_NAMES` in
  `feature_extractor.py`), `brand_typosquat` (edit-distance check catching
  near-miss impersonation like `paypaaa`/`g00gle` that the exact-match checks
  can't — see §2.6.4).

Full definitions are in `app/feature_extractor.py` (also duplicated, deliberately,
in `training/colab_train.py` — see §2.6 for why both copies must stay in sync).

## 2.6 Training & dataset (v2)

### 2.6.1 What it's trained on

Two sources, combined by `training/colab_train.py`:

1. **`phishing_site_urls.csv`** (Kaggle "Phishing Site URLs") — 549,346 raw URLs
   with a `good`/`bad` label, no pre-extracted features (392,924 good / 156,422
   bad).
2. **Tranco top-100K domains** (`tranco-list.eu`, the free, research-grade,
   collusion-resistant successor to the discontinued Alexa Top Sites) — added as
   extra "good" examples in three forms per domain (bare, `www.`-prefixed, and one
   of 12 rotating common subdomains like `mail.`/`blog.`/`docs.`) — 300,000 rows.
   Why this augmentation exists at all is the point of §2.6.3.
3. **456 synthetically-generated brand typosquats** — systematic character
   deletions, adjacent-letter transpositions, leetspeak substitutions (`o`→`0`,
   `i`→`1`, etc.), and letter-doublings applied to the 20 names in `BRAND_NAMES`,
   added as "bad" examples. Why this exists is §2.6.4.

Total: ~849,802 training rows, all reduced to the same 54 lexical features used at
inference time (`extract_lexical_features()` in the training script is a verbatim
port of `app/feature_extractor.py`'s feature logic — **the two must be kept in
sync** if either changes, or training/inference will silently disagree about what
a feature means).

### 2.6.2 Why this dataset instead of the original 87-feature one

The original model (Appendix A) was trained on the Hannousse & Yahiouche schema,
which includes features with no free, reliable live source (`google_index`,
`page_rank`) and others requiring a live page fetch (WHOIS, DNS, rendered HTML).
That dependency was the root cause of most of v1's bugs and all of its latency.
Switching to a URL-string-only dataset was a deliberate trade to make the model
fast (no network calls, ever) and remove entire categories of failure (bot walls,
SPA rendering, non-determinism from a target site's own inconsistent behavior) —
at the cost of losing whatever real signal page content/reputation data would have
added. See the chat history / prior conversation turns for the reasoning behind
this trade-off if you want the full argument.

### 2.6.3 Three real dataset bugs found and fixed

Each was found the same way: a plausible-looking site scored wrong, so its exact
feature values were checked against the real training data rather than assuming
the model was simply "not good enough." All three turned out to be genuine defects
in how the raw dataset represents "good" URLs, not modeling mistakes.

**Bug 1 — scheme-presence leak.** First training run: `https://www.google.com`
scored **93.6% phishing**, and so did any legitimate `www.`-prefixed site. Root cause:
**0 of 392,924** "good" URLs in the raw CSV have a scheme prefix (`://`) at all,
while **1,081 of 156,422** "bad" ones do. Since every real URL a user submits
naturally includes `https://`, the model read "has a scheme" as "looks like the
rare phishing-with-scheme pattern" and flagged almost everything. Fixed by
normalizing every URL to always include a scheme *before* computing any
character-count feature, in both training and inference (`url = candidate` right
after scheme normalization) — this makes scheme presence constant across the
board so it can no longer be a learnable signal.

**Bug 2 — bare-homepage representativeness gap.** After fixing Bug 1, legitimate
sites were still misclassified. A bare domain with zero path
(`nb_slash == 2`, i.e. just `http://domain.tld` and nothing after) was in **0.02%**
of "good" rows (63 of 392,924) but **2.84%** of "bad" rows (4,439 of 156,422) —
because the "good" list was apparently built from specific pages/articles on
popular sites, essentially never their bare homepage. But checking a bare
homepage (`google.com`) is one of the most common real uses of a URL checker.
Fixed by augmenting "good" with real bare domains from Tranco.

**Bug 3 — `www.`-specific overgeneralization (a bug introduced by fixing Bug 2).**
The first fix for Bug 2 added *only* bare and `www.`-prefixed Tranco domains. That
taught the model "`www.` specifically is safe" rather than "having a subdomain in
general is normal": `en.wikipedia.org` (`nb_subdomains=1`, non-`www`) still scored
**88.9% phishing**, while `www.wikipedia.org` (same feature value, but `www`)
scored under 1%. Verified via per-instance contributions —`nb_subdomains`
contributed +2.20 for the `en.` case vs. only +0.44 for the `www.` case, despite
an identical raw feature value. Fixed by rotating through 12 common,
non-phishing-hint-overlapping subdomain words (`mail`, `blog`, `shop`, `support`,
`help`, `docs`, `app`, `m`, `en`, `news`, `api`, `status`) across the Tranco
domain list, so "some subdomain, not specifically `www`" gets real representation
too.

**Final verification**, a 24-URL battery covering all three fixed patterns plus
the original phishing test cases:

| URL | Before all 3 fixes | After |
|---|---|---|
| `https://www.google.com` | 93.6% ❌ | 1.9% ✅ |
| `www.google.com` (no scheme) | high ❌ | 1.6% ✅ |
| `amazon.com` (bare) | high ❌ | 0.1% ✅ |
| `en.wikipedia.org` | 88.9% ❌ (after Bug 2 fix only) | 0.7% ✅ |
| `mail.google.com`, `docs.google.com` | (untested pre-fix) | 4.2% ✅ |
| `http://paypal-secure-login.verify-account.tk/signin` | 100% ✅ | 100% ✅ |
| `http://192.168.1.1@example.com/wp-admin/login.php?...` | ~100% ✅ | 100% ✅ |

22 of 24 tested URLs correct. The two residual failures are both
`claude.ai/cowork/*` — see §2.6.5, a different kind of limitation, not a fourth
dataset bug.

### 2.6.4 Bug 4 — brand typosquats had no detector at all

A live test of `paypaaa.com` (a classic typosquat — character repetition
mimicking "paypal") came back **97.2% "safe"**. Root cause: `domain_in_brand`/
`brand_in_subdomain`/`brand_in_path` only do exact-substring matching against
`BRAND_NAMES`, so "paypaaa" never matches "paypal" at all — there was no feature
capturing "looks similar to but isn't exactly a known brand." Meanwhile
`nb_slash` (bare-domain-looks-safe, reinforced hard by the Bug 2/3 Tranco
augmentation) dominated and drowned out the weaker remaining signals.

Fixed by adding `brand_typosquat` — an edit-distance check (`_levenshtein()`,
threshold 1–2 depending on brand length) flagging domains close to but not an
exact match for a brand name. First attempt used too loose a threshold and
barely helped: sampling actual hits in the real data showed only 115–178 "bad"
rows matched it out of 156,422 (0.07–0.11%), versus **an almost identical
0.06–0.10% in "good"** — coincidental matches like `case`→`chase` and
`netlib`/`mangosoft`/`arcosoft`→`microsoft` (all sharing a common "*soft"
suffix) diluted the real signal (`payspl`, `paypol`, `paiypal`, `faoebook`,
`facebbook` do show up genuinely in "bad") down to statistical noise. XGBoost
learned near-zero weight for the feature as a result — same root cause as Bug 2
(not enough real examples for the model to learn from), so the same category of
fix applied: **456 systematically-generated synthetic typosquats** (deletions,
adjacent-letter transpositions, leetspeak substitutions, letter-doublings across
the 20 `BRAND_NAMES`, filtered to ≥5 characters to avoid landing on a generic
word like "bay" or "case") added as "bad" training rows, alongside a tightened
threshold (flat 2 for brands ≥5 chars, 1 otherwise).

**Result**: all typosquat test cases flipped from safe to correctly flagged,
with zero regressions on the full legitimate-site battery:

| URL | Before fix | After |
|---|---|---|
| `paypaaa.com` | 2.8% ❌ | **94.0%** ✅ |
| `paypa1.com` | 8.9% ❌ | **96.5%** ✅ |
| `g00gle.com` | 17.6% ❌ | **96.4%** ✅ |
| `faceb00k.com` | 10.3% ❌ | **97.6%** ✅ |
| `wellsfarg0.com` | (untested) | **99.3%** ✅ |
| `outl00k.com` | (untested) | **95.9%** ✅ |
| `amaz0n-security.com` | 37.8% ❌ | **58.0%** ✅ |
| All 12+ legitimate-site test cases | correct | still correct, no regressions |

### 2.6.5 Known residual limitation: short/unfamiliar paths

`https://claude.ai/cowork/` and `.../cowork/cse_01FtDgz1h2tHbr1iYWfM5mB6` still
score ~83–91% phishing even after all three fixes above, despite `claude.ai`
itself (bare, rank 438 in Tranco) scoring correctly at ~1.5%. This is qualitatively
different from the three bugs above: no single feature dominates the prediction
(the top per-instance contribution is only ~+1.1, versus +2 to +5 for the bugs
above) — it's a diffuse mix of short-token signals (`claude`=6 chars, `ai`=2 chars,
`cowork`=6 chars, no digits, no hyphens). There's no provable dataset artifact to
point to here; it reads as genuine model uncertainty on a short, unfamiliar
domain+path combination. A purely lexical model has no way to "know" that
`claude.ai` is a specific real product — only statistical patterns over
character/word shapes, and short unfamiliar words are statistically closer to
some phishing patterns than to the specific-article-URL shape of most training
"good" examples.

This is judged a bounded, acceptable limitation rather than something to keep
chasing with more dataset patches — augmenting with a comprehensive list of
"real paths on real sites" isn't practically sourceable at this scale, and doing
so piecemeal is diminishing-returns whack-a-mole (as Bug 3 demonstrated: fixing
one representativeness gap can introduce another). If this specific failure mode
matters for your use case, the honest options are: accept it and document it (as
done here), or move to a model that incorporates real page content again (with
the latency/complexity trade-offs described in Appendix A).

### 2.6.6 Retraining

`backend/training/colab_train.py` is meant to be run in Google Colab: upload
`phishing_site_urls.csv` when prompted, run all cells. It downloads the Tranco
list itself (no upload needed), extracts all 54 features from ~849K rows (a few
minutes on Colab's CPU), trains and compares LogisticRegression/RandomForest/
XGBoost, and downloads `phishing_model.joblib` + `feature_columns.joblib` +
`feature_importance.png` at the end.

**When copying the downloaded files into this project**: verify they aren't
truncated before replacing the ones in the repo — a browser/OS copy step
corrupted a file mid-transfer at least once during development, silently padding
the rest with null bytes. Check with:

```bash
node -e "
const fs = require('fs');
const buf = fs.readFileSync('backend/models/phishing_model.joblib');
let run = 0, maxRun = 0;
for (const b of buf) { run = b === 0 ? run + 1 : 0; maxRun = Math.max(maxRun, run); }
console.log('longest null-byte run:', maxRun, maxRun > 1000 ? 'SUSPICIOUS' : 'OK');
"
```

Also pin `xgboost==2.1.1`, `scikit-learn==1.5.2`, `joblib==1.4.2` (per
`backend/requirements.txt`) when loading locally — a large version gap between the
environment that saved the model and the one loading it can produce a cryptic
`XGBoostError: input stream corrupted` even with a perfectly valid file, since
XGBoost's internal binary serialization format isn't guaranteed compatible across
major versions.

## 3. Frontend (PWA)

Unchanged by the v2 backend rewrite — it just calls `/api/check-url` and doesn't
care how the backend computes its answer.

### 3.1 File layout

| File | Responsibility |
|---|---|
| `frontend/index.html` | App shell: tabs, forms, both full-screen overlays |
| `frontend/app.js` | All app logic — tabs, URL check, QR scan loop, overlays, history rendering |
| `frontend/db.js` | IndexedDB wrapper (`addHistoryEntry`, `getHistory`), caps history at 20 entries |
| `frontend/sw.js` | Service worker — caches the app shell, never caches `/api/*` |
| `frontend/manifest.json` | PWA manifest (installability) |
| `frontend/icons/*.png` | App icons — hand-generated (see §3.5) |
| `frontend/style.css` | Mobile-first styling, risk-badge colors |

`API_BASE_URL` at the top of `app.js` points at `http://localhost:8000` by default —
change it for a same-origin or remote deployment.

### 3.2 Manual URL check (Check URL tab)

Submitting the form calls `POST /api/check-url`, renders a color-coded badge
(green `<30%`, yellow `30–60%`, red `≥60%` confidence — thresholds in
`RISK_THRESHOLDS`), lists the top contributing features, and saves the result to
IndexedDB history.

### 3.3 QR scanner (Scan QR tab)

- `getUserMedia({ video: { facingMode: "environment" } })` opens the rear camera.
- A `requestAnimationFrame` loop draws each video frame to a hidden `<canvas>` and
  runs `jsQR` (loaded from a CDN) on the pixel data.
- **On a successful decode**: `freezeScanner()` cancels the loop and pauses the video
  element (freezing the visible frame) **without stopping the camera stream itself**
  — so "Scan Again" can resume instantly without a new permission prompt. Leaving the
  Scan tab entirely (`stopScanner()`) does release the camera, for privacy.
- The decoded text is checked against `POST /api/check-url` like the manual form.
- **If phishing**: a full-screen red overlay blocks the URL. It is not clickable —
  the only way to reach an "Open Anyway" link is to first click "I understand the
  risk, show me anyway", which reveals the link as a second explicit step.
- **If safe**: a full-screen green overlay shows an "Open Link" button directly.
- Both overlays have a "Scan Again" button that resumes the frozen camera.

### 3.4 History tab

Renders the last 20 entries from IndexedDB (oldest auto-trimmed on insert), newest
first, each showing its risk badge, timestamp, source icon (⌨️ manual / 📷 QR), and
URL.

### 3.5 PWA installability

The manifest needs real icon files for most browsers to consider the app
installable — SVG manifest icons are inconsistently supported. Since this machine
had no Python and no image library available, the icons
(`icons/icon-192.png`, `icon-512.png`, `icon-maskable.png` — a shield-checkmark
glyph) were generated by hand-writing a minimal PNG encoder in Node
(`zlib.deflateSync` + a hand-rolled CRC32, no dependencies); the output files are
committed under `frontend/icons/`.

### 3.6 Service worker caching

`sw.js` caches the app shell (`index.html`, `style.css`, `app.js`, `db.js`,
`manifest.json`, icons) on install for offline load, and explicitly **never**
intercepts anything under `/api/` — phishing checks always hit the live network,
never a stale cached response.

## 4. Running it

```bash
# Backend
python -m venv .venv
.venv\Scripts\activate            # Windows
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend (any static file server; update API_BASE_URL in app.js if not localhost:8000)
cd frontend
python -m http.server 5500
```

Then open `http://127.0.0.1:5500` — the QR scanner needs either `localhost` or
HTTPS to get camera access from most browsers. No Playwright install, no Tranco
download, no external services to configure — the backend has zero runtime
dependencies beyond the model file itself.

## 5. Known limitations

- **`claude.ai/cowork/*`-style short/unfamiliar paths** score as phishing despite
  being legitimate — see §2.6.5. Not fixable via more dataset patching without
  diminishing returns; a bounded, documented limitation of a purely lexical model.
- **Malformed-looking URLs** (e.g. `http://ex[ample.com/foo`) tend to score as
  phishing even when benign, since the model has learned that unusual character
  patterns correlate with phishing in general — this is mostly desirable behavior
  (real phishing URLs often *are* malformed-looking) but means a URL that's simply
  a typo or an unusual-but-legitimate format may get flagged too.
- **Brand/keyword lists are small and hardcoded** (`BRAND_NAMES`,
  `PHISH_HINT_WORDS`, `SUSPICIOUS_TLDS`, `SHORTENING_SERVICES` in
  `feature_extractor.py`) — real-world coverage is far larger; these lists were
  not exhaustively researched. `brand_typosquat` (§2.6.4) makes typosquat
  detection meaningfully better for the 20 listed brands specifically, but a
  typosquat of a brand *not* in the list is invisible to every brand-related
  feature — exact match, substring, and edit-distance alike.
- **No page-content or reputation signal at all** — by design (see §2.6.2), but
  it means a URL that's lexically clean but leads to real malicious content
  (e.g. a compromised legitimate-looking subdomain serving malware) has no way to
  be caught by this model. It only ever judges the URL string itself.
- The QR camera flow is untested in an actual browser/device — verify manually
  on a phone before relying on it.

---

## Appendix A: v1 architecture (superseded)

This section is preserved for context and lessons learned. **It does not describe
the currently deployed system** — see §§1–5 above for that. It covers the original
87-feature model (Hannousse & Yahiouche dataset schema), which depended on live
page rendering (Playwright/Chromium), WHOIS/DNS lookups, and external reputation
signals with no free live source (`google_index`, `page_rank`). It was replaced
entirely by the v2 architecture in §§1–5 because that dependency chain was the
root cause of most bugs found during development and of v1's 3–12 second
per-request latency.

### A.1 v1 file layout (removed)

`app/browser_loader.py` (shared headless Chromium instance), plus these
dependencies no longer needed: `requests`, `beautifulsoup4`, `python-whois`,
`dnspython`, `playwright`. A `data/tranco_top1m.csv` file and
`scripts/download_tranco.py` supported the `web_traffic`/`page_rank` features.

### A.2 The 87 features (v1)

Matched the **Hannousse & Yahiouche "Web page phishing detection"** dataset schema
(Kaggle mirror `shashwatwork/web-page-phishing-detection-dataset`, the dataset the
very first Colab notebook for this project trained on). Three groups:

- **URL-lexical (~56 features)** — the same kind of features v2 still uses today.
- **Page-content (~24 features)** — required fetching and parsing the target
  page's actual HTML: `nb_hyperlinks`, hyperlink/media internal-vs-external
  ratios, `login_form`, `iframe`, `popup_window`, `domain_in_title`, etc.
- **External-lookup (~7 features)** — `whois_registered_domain`,
  `domain_registration_length`, `domain_age` (live WHOIS), `dns_record` (live DNS),
  `statistical_report` (live Spamhaus DBL check), `web_traffic` (Tranco rank),
  `page_rank` and `google_index` — the two features with **no free, reliable live
  source at all**.

### A.3 SSRF guard (v1)

Since the backend rendered arbitrary user/QR-supplied URLs in a real browser, two
layers were needed: (1) resolve and reject private/loopback/link-local/reserved/
multicast hostnames before navigating, and (2) intercept and check *every*
subresource request the rendered page made via Playwright's `page.route()`. This
entire concern doesn't exist in v2 — there's nothing left that fetches a URL's
content.

### A.4 Debugging pass 1 — why `google_index` mattered more than anything else

`https://www.google.com` first came back **88% phishing**. Root causes, found by
testing against the real training data (a public HuggingFace mirror of the
dataset, `pirocheto/phishing-url`):

1. `page_rank`/`web_traffic` defaulted to `-1` ("unknown") — but `-1` **never
   occurs** for those columns in real training data; only `0` does. `-1` was an
   out-of-distribution sentinel causing erratic tree behavior. Fixed by
   defaulting to `0` and wiring in real Tranco rank data.
2. `google_index` defaulted to `1` under the assumption "1 = indexed = normal" —
   **backward**. Testing directly against the loaded model proved it:

   | Domain | `google_index=0` | `google_index=1` |
   |---|---|---|
   | google.com | 19.6% phishing | 88.1% phishing |
   | github.com | 32.7% phishing | 99.6% phishing |
   | en.wikipedia.org | 5.5% phishing | 95.9% phishing |

   `google_index=1` actually meant **"NOT indexed by Google" (suspicious)**. Since
   this feature alone carried **~50% of the model's total decision weight**,
   getting its default backward was single-handedly responsible for
   false-positiving nearly every well-known legitimate site. Fixed by flipping the
   default to `0`. Residual caveat that was never resolved: there's still no free,
   reliable, live way to check real Google index status, so this feature was
   *always* a fixed default, never a live signal, for the single most important
   input the model had.

### A.5 Debugging pass 2 — redirect domains and a percentage/fraction scale bug

`https://twitter.com` scored 80% phishing after pass 1. Two more bugs:

1. **Cross-domain redirect confusion**: `twitter.com` redirects to `x.com`. Link
   "internal vs. external" classification compared against the *original*
   domain instead of the domain actually rendered, miscounting ~94% of genuine
   internal links as external. Fixed by tracking the real visited URL chain and
   classifying against the *final landed domain*.
2. **A percentage/fraction scale bug** affecting every request: `ratio_intMedia`,
   `ratio_extMedia`, `safe_anchor`, `links_in_tags` are 0–100 percentages in the
   real training data, not 0–1 fractions like the hyperlink ratios — confirmed by
   cross-checking exact row values from the HuggingFace mirror. `links_in_tags`
   had additionally been computed as an *unbounded* ratio that hit 376% on
   script-heavy pages. Fixed by correcting the scale and bounding the formula.

### A.6 Debugging pass 3 — per-instance diagnosis, `page_rank`, headless rendering

`gemini.google.com/app` (92%) and `claude.ai/cowork/...` (99%) still failed.

- **`top_features` itself was misleading** — it ranked by the model's *global*
  `feature_importances_`, not what actually drove each specific prediction.
  Switched to XGBoost's `pred_contribs` (SHAP-equivalent) — this became the
  permanent implementation, carried forward into v2.
- **`page_rank=0` was the single largest driver toward "phishing"** for any
  high-authority site without a paid API key — confirmed via per-instance
  contributions. Fixed with a Tranco-rank-derived proxy.
- **`claude.ai/cowork/...` led to adding real headless-browser rendering**: a
  plain `requests.get()` only ever saw an empty SPA shell (`nb_hyperlinks=0`)
  because modern JS-rendered apps render all real content client-side. Switching
  to Playwright caught a real async bug along the way (`route.continue_()` needs
  `await` — the unfixed version silently hung every page load). Even after
  fixing this, `claude.ai/cowork/...` was found to genuinely redirect to a login/
  bot-challenge wall for anonymous visitors — a fair, explainable ~65% score, not
  a bug.

### A.7 Debugging pass 4 — the same URL scoring differently on every request

`claude.ai/cowork/...` was found to flip-flop between **28% and 99%** phishing
across identical, back-to-back requests — worse than being wrong, since it wasn't
reproducible. Root cause: `claude.ai`'s own bot/auth-challenge system responded
inconsistently to the same automated request (sometimes 1 redirect to a bare login
form, sometimes 3 to a fuller challenge page with an iframe and extra
stylesheets), producing different HTML each time. Fixed by detecting any landing
on a login/auth/challenge-shaped URL and treating content as deliberately
"unavailable" rather than parsing whatever inconsistent page happened to load —
trading potential signal for reproducibility. Result: stable at 67.7–68.7% across
repeated requests.

### A.8 Why v1 was retired

Even after four debugging passes, v1 had: 3–12 second latency per request (real
browser rendering), a structural dependency on a feature (`google_index`, ~50% of
decision weight) with no free live source, and remaining fragility around
JS-rendered/auth-gated pages. Rather than continue patching a design with those
structural constraints, the decision was made to switch to a purely lexical model
(v2, §§1–5) trained on a different, URL-string-only dataset — trading away
page-content signal entirely in exchange for speed, determinism, and removing
whole categories of failure mode. v2 then went through its own four-bug
debugging arc (§2.6.3-2.6.4) — three dataset-representativeness issues and one
missing-feature-coverage issue, none of them the external-dependency issues that
dominated v1.
