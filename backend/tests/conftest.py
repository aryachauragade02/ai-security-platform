import os
import sys
from pathlib import Path

# Tests always run in mock mode with the in-memory store: no keys, no network.
for name, value in {
    "GEMINI_API_KEY": "",
    "SUPABASE_URL": "",
    "SUPABASE_SERVICE_KEY": "",
    "GATEWAY_API_KEY": "",
    "ADMIN_API_KEY": "",
    "RATE_LIMIT_PER_MINUTE": "1000",
    "DEMO_RATE_LIMIT_PER_MINUTE": "1000",
    "SCAN_COOLDOWN_SECONDS": "0",
}.items():
    os.environ[name] = value

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c
