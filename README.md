# AwareLink

The local ML edition is in **[awarelink_ml/](awarelink_ml/README.md)**. It recreates the URL, news-text, screenshot, history, sharing, feedback and administration workflows for one local computer or one server.

It uses trained local models, embedded SQLite and one streamed request per analysis. The serving environment has three direct Python dependencies, with no LLM API or remote database. English screenshot OCR additionally uses local Tesseract.

From this repository on Windows:

```powershell
Set-Location awarelink_ml
.\setup.ps1
.\start.ps1
```

Then open **http://127.0.0.1:8765**. See the [setup guide](awarelink_ml/README.md) for administrator configuration, OCR and server settings.

The [architecture review](awarelink_ml/docs/ARCHITECTURE.md) maps the original connection flow and the rebuilt pipeline. The [validation report](awarelink_ml/docs/VALIDATION.md) records automated and browser checks; the [performance report](awarelink_ml/docs/PERFORMANCE.md) includes measured connection reuse and latency.

These are research baselines. URL scoring describes historical domain patterns, screenshot checks read text, and news always requires source verification. The [model card](awarelink_ml/docs/MODEL_CARD.md) documents held-out metrics, dataset provenance and the news artifact's research-only terms.

The original `web_scraper10.py` and `web_design/` files remain as migration references. The new application has its own storage and API contract; consult the architecture notes before importing old MySQL records.
