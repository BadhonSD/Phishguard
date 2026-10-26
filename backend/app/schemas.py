from pydantic import BaseModel, field_validator

from app.feature_extractor import safe_urlparse


class URLCheckRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        if len(v) > 2048:
            raise ValueError("url is too long")
        if " " in v or "\t" in v or "\n" in v:
            raise ValueError("url must not contain whitespace")
        # must look like a URL: either has a scheme, or has a dot-separated host.
        # safe_urlparse tolerates the malformed-but-real-world junk that plain
        # urlparse() chokes on (e.g. a stray "[" anywhere triggers "Invalid IPv6
        # URL") -- exactly the kind of URL a phishing checker most needs to accept.
        candidate = v if "://" in v else f"http://{v}"
        hostname, _, _ = safe_urlparse(candidate)
        if not hostname or "." not in hostname:
            raise ValueError("url does not look like a valid URL")
        return v


class FeatureContribution(BaseModel):
    feature: str
    value: float
    importance: float


class URLCheckResponse(BaseModel):
    url: str
    is_phishing: bool
    confidence: float
    top_features: list[FeatureContribution]


class HealthResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    status: str
    model_loaded: bool
