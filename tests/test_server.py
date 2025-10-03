import pytest

from roboninja.server import RateLimiter, Settings


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("SERVER_NAME", "unit-test-app")
    monkeypatch.setenv("LOG_LEVEL", "debug")
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "7")

    settings = Settings.from_env()

    assert settings.name == "unit-test-app"
    assert settings.log_level == "DEBUG"
    assert settings.rate_limit_per_min == 7


def test_rate_limiter_allows_within_window():
    limiter = RateLimiter(limit_per_min=2)

    assert limiter.allow() is True
    assert limiter.allow() is True
    assert limiter.allow() is False
