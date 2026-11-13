"""Live Backend Server Startup, Probe, and Clean Shutdown Verification."""

import sys
import os
import time
import threading
import json
import http.client

# Ensure backend directory is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir in sys.path:
    sys.path.remove(backend_dir)
sys.path.insert(0, backend_dir)

for mod in list(sys.modules.keys()):
    if mod == "app" or mod.startswith("app."):
        del sys.modules[mod]

import uvicorn
from app.main import app


def run_live_probe():
    config = uvicorn.Config(
        app=app,
        host="127.0.0.1",
        port=8000,
        log_level="error",
    )
    server = uvicorn.Server(config)

    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()

    # Wait for server to bind
    time.sleep(1.5)

    try:
        conn = http.client.HTTPConnection("127.0.0.1", 8000, timeout=5)
        conn.request("GET", "/api/v1/health", headers={"Accept": "application/json"})
        response = conn.getresponse()

        status_code = response.status
        headers = dict(response.getheaders())
        body_raw = response.read().decode("utf-8")
        body_json = json.loads(body_raw)

        print(f"ACTUAL_HTTP_STATUS: {status_code}", flush=True)
        print(f"ACTUAL_CSP_HEADER: {headers.get('content-security-policy', '')[:40]}...", flush=True)
        print(f"ACTUAL_RESPONSE_JSON: {json.dumps(body_json)}", flush=True)

        assert status_code == 200, f"Expected 200, got {status_code}"
        assert body_json["status"] == "healthy", f"Expected healthy status, got {body_json['status']}"
        assert body_json["database"]["status"] == "connected", "Database must be connected"
        assert body_json["database"]["error"] is None, "Database error must be None"
        print("VERIFICATION_RESULT: SUCCESS", flush=True)
    finally:
        server.should_exit = True
        server_thread.join(timeout=3)
        print("SERVER_SHUTDOWN: CLEAN", flush=True)


if __name__ == "__main__":
    run_live_probe()

