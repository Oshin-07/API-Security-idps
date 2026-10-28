# Source Map

| Combined location | Source upload | Action |
|---|---|---|
| `core/**` | `api_security_scanner_member3_updated_ui_Trisha` | Used as primary implementation |
| `data/**` | `api_security_scanner_member3_updated_ui_Trisha` | Used as primary runtime/model data |
| `test_vulnerable_api/**` | `api_security_scanner_member3_updated_ui_Trisha` | Used as local test target |
| `backend/main.py` | `api_security_scanner_member3_updated_ui_Trisha` | Used as integrated FastAPI backend |
| `run_scanner_pipeline.py` | `api_security_scanner_member3_updated_ui_Trisha` | Used as main end-to-end runner |
| `dashboard.py` | `api_security_scanner_member3_updated_ui_Trisha` + final dashboard | Integrated/updated to load scanner report and PDF generation |
| `reports/report_generator.py` | `API-Security-Dashboard-Updated_Final.zip` | Integrated and adapted to scanner assessment schema |
| `legacy/apoorva/test_api.py` | `API-Security-Scanner_Apoorva` | Preserved as optional reference |
| `legacy/apoorva/models.py` | `API-Security-Scanner_Apoorva` | Preserved as optional reference |
| `legacy/apoorva/api_discovery.py` | `API-Security-Scanner_Apoorva` | Preserved as optional reference |
| `legacy/apoorva/api_details.json` | `API-Security-Scanner_Apoorva` | Preserved as optional reference |

## Intentionally not merged

The final dashboard ZIP's duplicate `dashboard/dashboard.py`, `data/results.json`, `README.md`, and `requirements.txt` were not used because the integrated scanner has a different report schema and a fuller dependency set. Apoorva's duplicate `backend/main.py` and `requirements.txt` were also not used because they would replace the end-to-end orchestrator.

## HTML dashboard migration
- `frontend/index.html`, `frontend/style.css`, `frontend/app.js`: new browser dashboard built from the previous `dashboard.py` functionality.
- `backend/main.py`: changed to serve the frontend at `/` and `/dashboard`, expose `/api/reports/pdf`, and keep the existing scan/report APIs.
- `requirements.txt`: Streamlit and Plotly removed because the main dashboard no longer uses them. ML/training dependencies remain.
- `run_dashboard.bat`: now starts FastAPI instead of Streamlit.
- `start_servers.bat`: now opens `http://127.0.0.1:8000/` so the HTML dashboard appears directly.
- `legacy/dashboard_streamlit.py`: previous Streamlit dashboard retained for reference.
- `legacy/member3_streamlit_app.py`: previous Member 3 Streamlit UI retained for reference.
