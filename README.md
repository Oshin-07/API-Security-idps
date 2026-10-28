# API Security Scanner — Combined Team Build

This is the integrated project assembled from the uploaded team files. The main runnable implementation is based on the most complete end-to-end scanner package, with the dashboard/PDF reporting module integrated and Apoorva's independent discovery/model examples preserved under `legacy/apoorva/` so they do not conflict with the working backend.

## Quick start (Windows / VS Code)

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python -m core.ai_risk.train_model
```

Terminal 1 — start the safe local vulnerable demo API:
```bat
python test_vulnerable_api\mock_vulnerable_api.py
```

Terminal 2 — run the scanner pipeline:
```bat
python run_scanner_pipeline.py --target http://127.0.0.1:5000 --spec test_vulnerable_api\sample_openapi.json
```

Terminal 3 — start the dashboard:
```bat
streamlit run dashboard.py
```

Optional FastAPI backend:
```bat
python backend\main.py
```

Then open `http://127.0.0.1:8000/docs`.

## What came from where

### Trisha / Member 3 integrated package — PRIMARY BASE
- `core/` — discovery, vulnerability scanner, AI/ML risk engine and adaptive selection
- `data/` — training data, trained model, assessment reports and generated graphs
- `test_vulnerable_api/` — safe local vulnerable API and OpenAPI specification
- `backend/main.py` — unified FastAPI orchestration layer
- `run_scanner_pipeline.py` — end-to-end discovery → scan → AI risk pipeline
- `dashboard.py` — upgraded to use the integrated report and PDF generation
- `requirements.txt`, `start_servers.bat`, `run_dashboard.bat`

### Final Dashboard / Member 4 package — INTEGRATED
- `reports/report_generator.py` — PDF security report generator
- Its original standalone `data/results.json` and duplicate dashboard were not copied because they use a different data schema and would conflict with the integrated scanner data. The report generator was adapted to the integrated assessment format.

### Apoorva package — PRESERVED AS OPTIONAL LEGACY/REFERENCE
- `legacy/apoorva/test_api.py` — Apoorva's demo FastAPI test API
- `legacy/apoorva/models.py` — Apoorva's Pydantic API models
- `legacy/apoorva/api_discovery.py` — Apoorva's standalone discovery implementation
- `legacy/apoorva/api_details.json` — Apoorva's saved discovery output

These are kept separately instead of replacing the integrated backend/core modules, because the Trisha package already contains the more complete discovery + scanner + AI risk pipeline.

## Important

Only scan APIs you own or have explicit permission to test. The included vulnerable API is a local sandbox for demonstration/testing.

## Dashboard architecture (updated)
The dashboard is now a browser-based HTML/CSS/JavaScript frontend served directly by FastAPI. Streamlit is no longer required to run the main dashboard.

Start everything with `start_servers.bat`, or activate the virtual environment and run `python backend\main.py`. Then open `http://127.0.0.1:8000/`.

The old Streamlit dashboard files are preserved under `legacy/` for reference only.
