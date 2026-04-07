"""
server/app.py — Simple entry point for dep-vuln-triage.
All routing logic (API + UI) resides in dep_vuln_triage/env.py.
"""
from dep_vuln_triage.env import app
import uvicorn

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
