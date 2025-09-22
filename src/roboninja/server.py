"""RoboNinja FastMCP server module."""

from __future__ import annotations

import argparse
import functools
import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

try:
    from mcp.server.fastmcp import FastMCP
except Exception as exc:  # pragma: no cover
    FastMCP = None  # type: ignore[assignment]
    _FASTMCP_IMPORT_ERROR = exc
else:
    _FASTMCP_IMPORT_ERROR = None


@dataclass(frozen=True)
class Settings:
    """Runtime configuration derived from environment variables."""

    name: str
    log_level: str
    rate_limit_per_min: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            name=os.getenv("SERVER_NAME", "roboninja-server"),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            rate_limit_per_min=int(os.getenv("RATE_LIMIT_PER_MIN", "120")),
        )


class JsonFormatter(logging.Formatter):
    """Structured JSON log formatter keeping output MCP-friendly."""

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(record.created)),
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class RateLimiter:
    """Process-local rate limiter that tracks a per-minute window."""

    def __init__(self, limit_per_min: int):
        self.limit = max(1, limit_per_min)
        self.lock = threading.Lock()
        self.window_start = int(time.time() // 60)
        self.count = 0

    def allow(self) -> bool:
        now_min = int(time.time() // 60)
        with self.lock:
            if now_min != self.window_start:
                self.window_start = now_min
                self.count = 0
            if self.count < self.limit:
                self.count += 1
                return True
            return False


def _configure_logging(log_level: str) -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))
    root_logger.handlers[:] = [handler]
    return logging.getLogger("mcp.server")


def _ratelimited(limiter: RateLimiter):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not limiter.allow():
                raise RuntimeError(
                    f"Rate limit exceeded ({limiter.limit}/min). Try again later."
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def summarize_markdown_text(md: str, max_sentences: int = 3) -> str:
    """Limit Markdown content to a few sentence-like chunks."""

    cleaned = []
    fence = False
    for line in md.splitlines():
        s = line.strip()
        if s.startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        if s.startswith("#"):
            s = s.lstrip("# ")
        if s:
            cleaned.append(s)
    text = " ".join(cleaned)
    parts = [
        p.strip()
        for p in text.replace("?", ".").replace("!", ".").split(".")
        if p.strip()
    ]
    return ". ".join(parts[: max(1, max_sentences)]) + ("." if parts else "")


def create_app(settings: Optional[Settings] = None) -> FastMCP:
    if FastMCP is None:
        detail = ""
        if _FASTMCP_IMPORT_ERROR:
            detail = f"\nImport error: {_FASTMCP_IMPORT_ERROR}"
        raise RuntimeError(
            "The 'mcp' package is required. Install with: pip install \"mcp[cli]\"" + detail
        )

    settings = settings or Settings.from_env()
    log = _configure_logging(settings.log_level)
    limiter = RateLimiter(settings.rate_limit_per_min)

    app = FastMCP(settings.name)

    ratelimited = _ratelimited(limiter)
    store: Dict[str, str] = {}

    @app.tool()
    @ratelimited
    def ping() -> dict:
        """Health probe returning server metadata."""

        return {
            "ok": True,
            "name": settings.name,
            "time": time.time(),
            "monotonic": time.monotonic(),
            "rate_limit_per_min": settings.rate_limit_per_min,
        }

    @app.tool()
    @ratelimited
    def kv_set(key: str, value: str) -> dict:
        """Set a string value at `key` in the ephemeral store."""

        if not key:
            raise ValueError("key must be non-empty")
        store[key] = value
        log.info("kv_set", extra={"key": key, "size": len(value)})
        return {"ok": True, "key": key, "stored_len": len(value)}

    @app.tool()
    @ratelimited
    def kv_get(key: str) -> dict:
        """Return the stored value for `key`, if present."""

        if not key:
            raise ValueError("key must be non-empty")
        exists = key in store
        return {"ok": exists, "key": key, "value": store.get(key)}

    @app.tool()
    @ratelimited
    def echo(text: str, upper: bool = False, repeat: int = 1) -> str:
        """Echo text (optionally uppercased) `repeat` times."""

        if repeat < 1 or repeat > 16:
            raise ValueError("repeat must be between 1 and 16")
        out = text.upper() if upper else text
        return " ".join(out for _ in range(repeat))

    @app.tool()
    @ratelimited
    def summarize_markdown(md: str, max_sentences: int = 3) -> str:
        """Lightweight summariser for short Markdown strings."""

        return summarize_markdown_text(md, max_sentences)

    return app


def run_stdio(app: Optional[FastMCP] = None) -> None:
    if FastMCP is None:
        detail = ""
        if _FASTMCP_IMPORT_ERROR:
            detail = f"\nImport error: {_FASTMCP_IMPORT_ERROR}"
        raise RuntimeError(
            "The 'mcp' package is required. Install with: pip install \"mcp[cli]\"" + detail
        )

    app = app or create_app()
    try:
        from mcp.server.fastmcp import run

        run(app, transport="stdio")
    except Exception:
        try:
            app.run(transport="stdio")  # type: ignore[attr-defined]
        except Exception as exc:  # pragma: no cover
            logging.getLogger("mcp.server").error("Failed to run stdio server: %s", exc)
            raise


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Run RoboNinja MCP server")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio"],
        help="Transport to use",
    )
    args = parser.parse_args(argv)
    logging.getLogger("mcp.server").info(
        "Starting %s via %s", Settings.from_env().name, args.transport
    )
    run_stdio()


if FastMCP is not None:
    mcp = create_app()
else:
    mcp = None


if __name__ == "__main__":
    main()
