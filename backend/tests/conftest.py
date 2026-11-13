"""Pytest Configuration and Test Fixtures for PhishGuard.

Provides:
- Sys.path isolation to prevent interference from other workspace projects.
- Temporary SQLite database fixture.
- FastAPI TestClient fixture.
- Offline Network Isolation Guardian (intercepts socket/urllib calls).
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path
import socket
import urllib.request
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# 1. Guarantee PhishGuard backend is at the very head of sys.path
backend_path = str(Path(__file__).resolve().parent.parent)
if backend_path in sys.path:
    sys.path.remove(backend_path)
sys.path.insert(0, backend_path)

# Unload any stale "app" modules from other projects
for mod_name in list(sys.modules.keys()):
    if mod_name == "app" or mod_name.startswith("app."):
        del sys.modules[mod_name]

from app.database.base import Base
from app.database.session import get_db
from app.core.config import settings
from app.main import app as fastapi_app
import app.models  # noqa: F401


# 2. Offline Network Isolation Guardian
@pytest.fixture(autouse=True)
def enforce_offline_network_isolation(monkeypatch):
    """Guarantees that analysis and application code execute in strict offline mode.
    
    Any attempt to establish an outbound HTTP/HTTPS or urllib connection raises
    an immediate AssertionError, preventing unintentional external communication.
    """
    import http.client

    def forbidden_http_connect(*args, **kwargs):
        raise AssertionError(
            "SECURITY VIOLATION: Unauthorized outbound HTTP/HTTPS network connection attempt. "
            "PhishGuard must operate strictly in offline/air-gapped mode during analysis."
        )

    def forbidden_urlopen(*args, **kwargs):
        raise AssertionError(
            "SECURITY VIOLATION: Unauthorized urllib.request.urlopen call detected. "
            "PhishGuard must operate strictly in offline mode."
        )

    monkeypatch.setattr(http.client.HTTPConnection, "connect", forbidden_http_connect)
    monkeypatch.setattr(http.client.HTTPSConnection, "connect", forbidden_http_connect)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden_urlopen)
    yield


@pytest.fixture(autouse=True)
def reset_rate_limit_tracker():
    """Resets the rate limiter request tracking bucket and default limit before each test."""
    from app.core.config import settings
    from app.core.security import rate_tracker
    rate_tracker.limit = settings.RATE_LIMIT_PER_MINUTE
    rate_tracker.reset()
    yield
    rate_tracker.limit = settings.RATE_LIMIT_PER_MINUTE
    rate_tracker.reset()


# 3. Temporary Test Database Fixture
@pytest.fixture(scope="session")
def test_temp_dir():
    """Provides an isolated temporary directory for test databases and evidence."""
    temp_dir = Path(tempfile.mkdtemp(prefix="phishguard_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def test_db_session(test_temp_dir):
    """Provides a fresh transactional database session for each test function."""
    db_file = test_temp_dir / f"test_{tempfile.mktemp()[-8:]}.db"
    db_url = f"sqlite:///{db_file.as_posix()}"
    test_engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    session = TestingSessionLocal()
    from app.database.seed import seed_detection_rules
    seed_detection_rules(session)
    try:
        yield session
    finally:
        session.close()
        test_engine.dispose()


# 4. FastAPI TestClient Fixture
@pytest.fixture(scope="function")
def client(test_db_session):
    """Provides a TestClient with database session dependency overridden."""
    def override_get_db():
        try:
            yield test_db_session
        finally:
            pass

    fastapi_app.dependency_overrides[get_db] = override_get_db
    with TestClient(fastapi_app) as test_client:
        yield test_client
    fastapi_app.dependency_overrides.clear()
