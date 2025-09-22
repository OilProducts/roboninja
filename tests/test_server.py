import os

import pytest

from roboninja.server import RateLimiter, Settings, summarize_markdown_text


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


def test_summarize_markdown_text_strips_code_fences():
    md = "Intro line.\n```\ncode block\n```\nConclusion."
    summary = summarize_markdown_text(md, max_sentences=2)

    assert "code" not in summary
    assert summary.endswith(".")


def test_summarize_markdown_text_trims_headings():
    md = "# Heading\nSecond sentence. Third sentence. Fourth sentence."
    summary = summarize_markdown_text(md, max_sentences=2)

    assert summary.startswith("Heading")
    assert summary.count(".") == 2
