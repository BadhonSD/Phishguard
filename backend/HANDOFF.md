# Handoff Prompt

Paste everything below this line into a new session to bring it up to speed.

---

## CONTEXT: Phishing URL Detector (PWA + FastAPI) — continuing existing work

Project location: `c:\Users\naser.arman\testQue` (Windows machine, no git repo,
no prior git history to check — treat `DOCUMENTATION.md` as the source of truth
for history, not git log).

### WHAT THIS IS

A two-part app: a FastAPI backend that scores a URL's phishing probability, and a
PWA frontend (plain HTML/JS/CSS) with a manual URL-check form, a live QR-code
scanner, and an IndexedDB history view.

### READ THIS FIRST

`c:\Users\naser.arman\testQue\DOCUMENTATION.md` has the full accurate write-up —
current architecture in §§1-5, known limitations in §5, and the entire debugging
history (including a superseded v1 architecture) in Appendix A. Read it before
making changes; it documents several non-obvious bugs that are easy to
reintroduce if you're not aware of them.

### CURRENT ARCHITECTURE (v2 — this is what's deployed now)

- **Backend**: `backend/app/main.py`, `backend/app/feature_extractor.py`, `backend/app/model_loader.py`,
  `backend/app/schemas.py`. Pure lexical model — 54 features computed ONLY from the URL
  string (character counts, tldextract-based domain/TLD structure, word-length
  stats, keyword/brand checks including an edit-distance typosquat detector).
  ZERO network calls at inference time. ~75-150ms per request.
- **Model**: `backend/models/phishing_model.joblib` (XGBClassifier) + `backend/models/feature_columns.joblib`,
  both at `backend/models/`. Trained via `backend/training/colab_train.py` in Google Colab
  (not locally — this machine trains nothing itself).
- **Dataset**: `backend/data/phishing_site_urls.csv` (Kaggle "Phishing Site URLs", 549K raw
  URL+label rows, provided by the user) + three augmentations added by the
  training script itself: (1) Tranco top-100K domains as bare/www/rotating-
  subdomain "good" examples (~300K rows), (2) 456 synthetically-generated brand
  typosquat variants as "bad" examples. Total ~849.8K training rows. All
  augmentations exist to fix real representativeness/coverage gaps found in the
  raw dataset, detailed below.
- **Frontend**: `frontend/` (`index.html`, `app.js`, `db.js`, `sw.js`,
  `manifest.json`, `style.css`, `icons/`). Talks to the backend via
  `API_BASE_URL` in `app.js` (currently `http://localhost:8000`). Untouched by
  any of the backend rewrites.

### IMPORTANT HISTORY — do not re-break these

1. This started as a v1 architecture with 87 features (Hannousse/Yahiouche
   dataset schema), live headless-browser page rendering (Playwright), WHOIS/DNS
   lookups, and two features (`google_index`, `page_rank`) with no free live
   data source. It went through 4 debugging passes fixing real bugs (a backward
   boolean default that was ~50% of the model's decision weight, a
   redirect-domain confusion bug, a 0-1-vs-0-100 percentage scale bug, an async
   Playwright bug that silently broke every page load, and a non-determinism
   bug from a target site's own inconsistent bot-challenge behavior). Despite
   all fixes, v1 still had 3-12s latency and a structural dependency on
   unreplicable external signals, so it was **retired** in favor of v2. Full
   detail: `DOCUMENTATION.md` Appendix A. Don't reintroduce
   Playwright/WHOIS/DNS/page-fetching unless there's a deliberate, explicit
   decision to go back to that trade-off.
2. v2 (current) went through its own 4-bug debugging arc — three dataset
   representativeness gaps and one missing-feature-coverage issue, none of them
   the external-dependency issues that dominated v1:
   - **Bug 1**: 0/392,924 "good" URLs in the raw CSV had a scheme prefix
     (`://`) vs 1,081/156,422 "bad" ones — so any real URL a user submits
     (which naturally has `https://`) looked like the rare phishing pattern.
     Fixed by normalizing every URL to always include a scheme before
     computing character-count features, in BOTH training and inference.
   - **Bug 2**: bare homepages (no path at all) were almost entirely absent
     from "good" (0.02% vs 2.84% in "bad") since the "good" list was built
     from specific article/product pages, not homepages. Fixed by augmenting
     "good" with real bare Tranco domains.
   - **Bug 3** (introduced by fixing Bug 2): the Bug-2 fix used ONLY bare +
     www-prefixed domains, which taught the model "www SPECIFICALLY is safe"
     rather than "having a subdomain in general is normal" — e.g.
     `en.wikipedia.org` still scored 88.9% phishing while `www.wikipedia.org`
     scored under 1%, same feature value. Fixed by rotating through 12 common
     non-phishing-hint subdomain words
     (mail/blog/shop/support/help/docs/app/m/en/news/api/status) across the
     same Tranco domains.
   - **Bug 4**: classic typosquats (`paypaaa.com`, `g00gle.com`,
     `faceb00k.com`) scored as safe (2-18% phishing) because the brand checks
     only did exact-substring matching — "paypaaa" never matches "paypal" at
     all by construction. Added an edit-distance-based `brand_typosquat`
     feature, but the first version barely helped: the raw dataset only had
     ~150 genuine typosquat examples, diluted by an almost-equal rate of
     coincidental matches in "good" (`case`→`chase`, `netlib`/`mangosoft`→
     `microsoft`, sharing a common suffix). Same root cause as Bug 2 (not
     enough real examples), same category of fix: 456 systematically-generated
     synthetic typosquat variants (deletions, transpositions, leetspeak
     substitutions, letter-doublings, filtered to ≥5 chars to avoid generic
     words) added as "bad" training rows. Fixed all typosquat test cases to
     94-99% phishing with zero regressions on legitimate sites.

   Lesson if you find another site scoring oddly: check its exact feature
   values against a fresh sample of the real training data before assuming the
   MODEL is wrong — every bug so far (4 for 4) was a dataset/coverage gap, not
   a modeling error.
3. `backend/app/feature_extractor.py`'s feature-extraction logic and
   `backend/training/colab_train.py`'s `extract_lexical_features()` are two SEPARATE
   COPIES of the same logic (Colab can't import from this local repo). If you
   change one, you MUST change the other identically, or training and
   inference will silently disagree about what a feature means. This has
   already caused confusion more than once.
4. When copying newly-trained model files from Downloads into the project,
   **verify they aren't truncated first** — a browser/OS copy step silently
   corrupted a file mid-transfer at least once, padding the rest with null
   bytes. Check: a long run (>1000) of consecutive `0x00` bytes near the end of
   `backend/models/phishing_model.joblib` means it's corrupted; re-copy from Downloads
   directly rather than through any intermediate copy. Also watch for `(N)`-
   suffixed duplicate downloads in the Downloads folder — always verify by
   timestamp AND by loading the file (check `n_features_in_`/column names)
   that you're wiring in the actually-latest retrain, not a stale one with the
   same-looking filename pattern.
5. Pin exact versions when loading the model locally: `xgboost==2.1.1`,
   `scikit-learn==1.5.2`, `joblib==1.4.2` (see `requirements.txt`). A large
   version gap between Colab's environment and the local one can throw a
   cryptic `XGBoostError: input stream corrupted` even on a perfectly valid
   file, since XGBoost's internal binary format isn't guaranteed compatible
   across major versions.

### CURRENT STATUS / TEST RESULTS

Last full regression battery (28 URLs: 12+ major legitimate sites in both www
and bare form, 7 typosquat variants, 2 known-phishing test URLs, a
malformed-bracket URL, and `claude.ai/cowork/*` variants): all pass except the
known open issue below.

**Known open issue** (not yet fixed, judged as a bounded/acceptable limitation,
not an active bug to chase further right now): `claude.ai/cowork/*` paths still
score ~83-92% phishing even though `claude.ai` bare scores correctly (~1.5%).
Root cause is NOT a dataset artifact like bugs 1-4 — per-instance contribution
analysis shows no single dominant feature, just a diffuse mix of short-token
signals (short domain/path words with no digits/hyphens). This is genuine model
uncertainty on short, unfamiliar domain+path combinations that a purely lexical
model has no way to resolve — see `DOCUMENTATION.md` §2.6.5 for the full
reasoning on why this isn't worth further dataset patching (diminishing
returns / whack-a-mole risk, as Bug 3 proved).

### ENVIRONMENT NOTES

- No Python was originally installed on this machine; it was installed via
  `winget` (Python 3.12). A venv exists at `.venv/` — activate it or call
  `.venv\Scripts\python.exe` directly.
- Backend run: `cd backend`,
  `..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000`
- Frontend run: `cd frontend`, `python -m http.server 5500`, open
  `http://127.0.0.1:5500`
- No git repository exists in this project — changes aren't version-controlled.
- The QR camera scanning flow has **never been tested on an actual
  browser/device** in any session so far (no camera/browser available in the
  dev environment) — treat it as unverified until someone tests it on a real
  phone.

### NEXT STEPS

Nothing urgent is broken; pick based on what's actually asked. Possible
directions if asked "what's next": expand `BRAND_NAMES`/`PHISH_HINT_WORDS`/
`SUSPICIOUS_TLDS` coverage (currently small, hardcoded lists — note
`brand_typosquat` only protects the 20 brands already in `BRAND_NAMES`, so
adding more brands directly improves typosquat coverage too), decide whether
the `claude.ai/cowork`-style limitation matters enough to revisit, get the QR
scanner tested on a real device, or consider setting up git for version
control. Don't assume any of these are wanted — ask or wait for direction like
usual.
