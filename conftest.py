"""Keep the test suite offline and deterministic: never call a live LLM, never depend on a local blocklist.txt."""
import pytest


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    for k in ("FEATHERLESS_API_KEY", "LLM_API_KEY", "LLM_BASE_URL"):
        monkeypatch.delenv(k, raising=False)
    import service
    monkeypatch.setattr(service, "BLOCKLIST", set())
