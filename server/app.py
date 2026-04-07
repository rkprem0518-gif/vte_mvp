"""
server/app.py — Entry point for dep-vuln-triage.
Mounts /static and serves the UI at the root endpoint.
"""
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from dep_vuln_triage.env import app
import uvicorn

# ── Static files & UI ──────────────────────────────────────────────────────────
STATIC_DIR = os.path.join(os.path.dirname(__file__), "..", "static")

# Mount the /static path so CSS/JS are served
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Read the index.html once at startup
_INDEX_HTML = None

def _get_index() -> str:
    global _INDEX_HTML
    if _INDEX_HTML is None:
        with open(os.path.join(STATIC_DIR, "index.html"), "r", encoding="utf-8") as f:
            _INDEX_HTML = f.read()
    return _INDEX_HTML


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def ui_root():
    return _get_index()


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=7860,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()
