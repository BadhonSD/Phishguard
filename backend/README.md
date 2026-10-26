# PhishGuard Backend

This directory contains the Python FastAPI backend service and the trained machine learning model for phishing URL detection.

## Structure

- **`app/`**: The FastAPI application source code.
  - `main.py`: Application entry point, endpoints, and CORS middleware.
  - `feature_extractor.py`: Utility functions to parse URLs and extract features.
  - `model_loader.py`: Handles model initialization and loading.
  - `schemas.py`: Request and response models.
- **`models/`**: Stores the XGBoost classifier model (`phishing_model.joblib`) and the feature columns list (`feature_columns.joblib`).
- **`data/`**: Stores the raw training datasets (`phishing_site_urls.csv`, `dataset_phishing.csv`) and test zip archives.
- **`training/`**: Stores the training scripts (`colab_train.py`) and training reports (`feature_importance.png`).

## Getting Started

### Prerequisites

You should have a virtual environment configured. By default, the environment is located at the workspace root directory in `.venv`.

### Running the API Server

To start the backend, navigate to the `backend/` directory and run the application using `uvicorn`:

```bash
# Navigate to the backend directory
cd backend

# Run uvicorn from the root virtual environment
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Once started, the API will be available at `http://127.0.0.1:8000`.
You can access the auto-generated documentation at `http://127.0.0.1:8000/docs`.
