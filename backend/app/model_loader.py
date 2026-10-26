from pathlib import Path

import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"
FEATURE_COLUMNS_PATH = BASE_DIR / "models" / "feature_columns.joblib"


class ModelBundle:
    def __init__(self):
        self.model = None
        self.feature_columns: list[str] | None = None

    def load(self) -> None:
        self.model = joblib.load(MODEL_PATH)
        self.feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

    @property
    def is_loaded(self) -> bool:
        return self.model is not None and self.feature_columns is not None


bundle = ModelBundle()
