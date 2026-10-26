import asyncio
from contextlib import asynccontextmanager
import os
import urllib.request

import xgboost as xgb
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.feature_extractor import InvalidURLError, build_feature_vector
from app.model_loader import bundle
from app.schemas import FeatureContribution, HealthResponse, URLCheckRequest, URLCheckResponse


async def self_ping_loop():
    # Wait 30 seconds after startup to ensure server is fully ready
    await asyncio.sleep(30)
    
    url = os.getenv("RENDER_EXTERNAL_URL") or os.getenv("SELF_PING_URL")
    if not url:
        print("Self-ping: RENDER_EXTERNAL_URL/SELF_PING_URL not set. Self-pinging disabled.")
        return

    # Normalize url (remove trailing slash if any)
    url = url.rstrip("/")
    print(f"Self-ping: Loop started targeting {url}/api/health")
    
    while True:
        try:
            # Run the HTTP call in a separate thread to not block the main event loop
            status = await asyncio.to_thread(
                lambda: urllib.request.urlopen(f"{url}/api/health", timeout=15).getcode()
            )
            print(f"Self-ping success: status code {status}")
        except Exception as e:
            print(f"Self-ping warning: failed to connect: {e}")
        
        # Sleep for 5 minutes (300 seconds)
        await asyncio.sleep(300)


@asynccontextmanager
async def lifespan(app: FastAPI):
    bundle.load()
    # Start the self-ping loop in the background
    ping_task = asyncio.create_task(self_ping_loop())
    yield
    # Clean up background task on shutdown
    ping_task.cancel()


app = FastAPI(title="Phishing URL Detector", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _top_features(model, vector: list[float], features: dict, feature_columns: list[str], n: int = 5) -> list[FeatureContribution]:
    """Ranks features by their actual per-instance contribution to THIS prediction, not
    by the model's global importance -- the two can disagree a lot. Global importance says
    "this feature matters a lot across the whole model"; per-instance contribution says
    "this feature's specific value is what's pushing THIS URL's score up or down", which is
    what a user asking "why was this flagged" actually wants. Uses XGBoost's built-in
    pred_contribs (SHAP-equivalent, no extra dependency) when available."""
    booster = getattr(model, "get_booster", None)
    if booster is not None:
        dmatrix = xgb.DMatrix([vector], feature_names=feature_columns)
        contribs = booster().predict(dmatrix, pred_contribs=True)[0][:-1]  # drop bias term
    else:
        coefs = getattr(model, "coef_", None)
        if coefs is not None:
            contribs = [c * v for c, v in zip(coefs[0], vector)]
        else:
            importances = getattr(model, "feature_importances_", [0.0] * len(feature_columns))
            contribs = [imp * v for imp, v in zip(importances, vector)]

    ranked = sorted(zip(feature_columns, contribs), key=lambda pair: abs(pair[1]), reverse=True)[:n]
    return [
        FeatureContribution(feature=name, value=float(features.get(name, 0)), importance=float(contribution))
        for name, contribution in ranked
    ]


@app.get("/api/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", model_loaded=bundle.is_loaded)


@app.post("/api/check-url", response_model=URLCheckResponse)
def check_url(payload: URLCheckRequest) -> URLCheckResponse:
    if not bundle.is_loaded:
        raise HTTPException(status_code=503, detail="model is not loaded yet")

    try:
        vector, features = build_feature_vector(payload.url, bundle.feature_columns)
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    proba = bundle.model.predict_proba([vector])[0]
    confidence = float(proba[1])  # probability of the "phishing" class

    return URLCheckResponse(
        url=payload.url,
        is_phishing=confidence >= 0.5,
        confidence=confidence,
        top_features=_top_features(bundle.model, vector, features, bundle.feature_columns),
    )
