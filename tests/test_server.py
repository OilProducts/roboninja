import pytest

from roboninja.server import Settings


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "debug")

    settings = Settings.from_env()

    assert settings.log_level == "DEBUG"
