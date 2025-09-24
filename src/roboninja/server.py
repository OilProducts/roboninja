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
    logging.getLogger(__name__).debug("Failed to import FastMCP: %s", exc)
else:  # pragma: no cover - import success path exercised via app
    _FASTMCP_IMPORT_ERROR = None

from .binaryninja_service import (
    BinaryNinjaLicenseError,
    BinaryNinjaService,
    get_service_singleton,
    BinaryNinjaServiceError,
    BinaryNinjaUnavailableError,
)

try:  # pragma: no cover - optional import inside Binary Ninja
    import binaryninja
except Exception as exc:  # pragma: no cover
    binaryninja = None  # type: ignore
    logging.getLogger(__name__).debug("Binary Ninja import failed in server: %s", exc)


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

    # Suppress noisy per-call logging from the low-level MCP server unless explicitly re-enabled.
    logging.getLogger("mcp.server.lowlevel").setLevel(logging.WARNING)

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


def _bn_log(level: str, message: str) -> None:
    if binaryninja is None:
        return

    log_module = getattr(binaryninja, "log", None)
    if log_module is None:
        return

    log_func = {
        "debug": getattr(log_module, "log_debug", None),
        "info": getattr(log_module, "log_info", None),
        "warning": getattr(log_module, "log_warn", None),
        "error": getattr(log_module, "log_error", None),
    }.get(level)

    if callable(log_func):
        try:
            log_func(message)
        except Exception as exc:  # pragma: no cover
            logging.getLogger(__name__).debug("Binary Ninja log call failed: %s", exc)


def _log_tool_call(name: str, arguments: dict) -> None:
    payload = json.dumps({"tool": name, "arguments": arguments}, ensure_ascii=False)
    logging.getLogger("mcp.server").debug("Tool call: %s", payload)
    _bn_log("debug", f"RoboNinja tool call: {payload}")


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


def _parse_address(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = value.strip()
    if text.lower().startswith("0x"):
        return int(text, 16)
    return int(text)


def _wrap_service_call(fn):
    try:
        return fn()
    except BinaryNinjaLicenseError as exc:
        raise RuntimeError(f"Binary Ninja license error: {exc}") from exc
    except BinaryNinjaServiceError as exc:
        raise RuntimeError(str(exc)) from exc


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

    try:
        bn_service = get_service_singleton()
        bn_error: Optional[Exception] = None
    except (BinaryNinjaUnavailableError, BinaryNinjaLicenseError) as exc:
        bn_service = None
        bn_error = exc
        log.warning("Binary Ninja unavailable: %s", exc)

    def require_service() -> BinaryNinjaService:
        if bn_service is None:
            raise RuntimeError(
                "Binary Ninja service unavailable: "
                + (str(bn_error) if bn_error else "module not loaded")
            )
        return bn_service

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

    @app.tool()
    @ratelimited
    def bn_open(
        path: str,
        update_analysis: bool = True,
        analysis_timeout: Optional[float] = None,
        allow_create: bool = False,
    ) -> dict:
        """Open a binary with Binary Ninja and return a view handle."""

        _log_tool_call(
            "bn_open",
            {
                "path": path,
                "update_analysis": update_analysis,
                "analysis_timeout": analysis_timeout,
                "allow_create": allow_create,
            },
        )
        service = require_service()
        summary = _wrap_service_call(
            lambda: service.open_view(
                path,
                update_analysis=update_analysis,
                analysis_timeout=analysis_timeout,
                allow_create=allow_create,
            )
        )
        return {"ok": True, "view": summary}

    @app.tool()
    @ratelimited
    def bn_list() -> dict:
        """List active Binary Ninja views."""

        _log_tool_call("bn_list", {})
        service = require_service()
        return _wrap_service_call(service.list_views)

    @app.tool()
    @ratelimited
    def bn_close(handle: str) -> dict:
        """Close a Binary Ninja view by handle."""

        _log_tool_call("bn_close", {"handle": handle})
        service = require_service()
        return _wrap_service_call(lambda: service.close_view(handle))

    @app.tool()
    @ratelimited
    def bn_functions(
        handle: str,
        name_contains: Optional[str] = None,
        min_size: int = 0,
    ) -> dict:
        """Return function metadata for a view."""

        _log_tool_call(
            "bn_functions",
            {"handle": handle, "name_contains": name_contains, "min_size": min_size},
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.get_function_list(
                handle,
                name_contains=name_contains,
                min_size=min_size,
            )
        )

    @app.tool()
    @ratelimited
    def bn_function_summary(handle: str, function: str) -> dict:
        """Detailed summary for a specific function."""

        _log_tool_call("bn_function_summary", {"handle": handle, "function": function})
        service = require_service()
        return _wrap_service_call(lambda: service.get_function_summary(handle, function))

    @app.tool()
    @ratelimited
    def bn_hlil(
        handle: str,
        function: str,
        max_instructions: Optional[int] = None,
    ) -> dict:
        """Return High Level IL lines for a function."""

        _log_tool_call(
            "bn_hlil",
            {"handle": handle, "function": function, "max_instructions": max_instructions},
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.get_high_level_il(
                handle,
                function,
                max_instructions=max_instructions,
            )
        )

    @app.tool()
    @ratelimited
    def bn_basic_blocks(handle: str, function: str) -> dict:
        """List basic blocks for a function."""

        _log_tool_call("bn_basic_blocks", {"handle": handle, "function": function})
        service = require_service()
        return _wrap_service_call(lambda: service.get_basic_blocks(handle, function))

    @app.tool()
    @ratelimited
    def bn_rename_function(handle: str, function: str, new_name: str) -> dict:
        """Rename a Binary Ninja function to a new symbolic name."""

        _log_tool_call(
            "bn_rename_function",
            {"handle": handle, "function": function, "new_name": new_name},
        )
        service = require_service()
        return _wrap_service_call(lambda: service.rename_function(handle, function, new_name))

    @app.tool()
    @ratelimited
    def bn_set_comment(handle: str, address: str | int, text: str) -> dict:
        """Attach a repeatable comment at the specified address."""

        _log_tool_call(
            "bn_set_comment",
            {"handle": handle, "address": str(address), "text": text},
        )
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(lambda: service.set_comment(handle, addr, text))

    @app.tool()
    @ratelimited
    def bn_clear_comment(handle: str, address: str | int) -> dict:
        """Clear any comment at the given address."""

        _log_tool_call("bn_clear_comment", {"handle": handle, "address": str(address)})
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(lambda: service.clear_comment(handle, addr))

    @app.tool()
    @ratelimited
    def bn_disassemble(handle: str, address: str | int, count: int = 1) -> dict:
        """Return disassembly text starting at *address* for *count* instructions."""

        if count <= 0:
            raise RuntimeError("count must be positive")

        _log_tool_call(
            "bn_disassemble",
            {"handle": handle, "address": str(address), "count": count},
        )
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(lambda: service.disassemble(handle, addr, count=count))

    @app.tool()
    @ratelimited
    def bn_code_refs(handle: str, address: str | int, max_results: int | None = None) -> dict:
        """List code references targeting *address*."""

        _log_tool_call(
            "bn_code_refs",
            {"handle": handle, "address": str(address), "max_results": max_results},
        )
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(
            lambda: service.get_code_references(handle, addr, max_results=max_results)
        )

    @app.tool()
    @ratelimited
    def bn_data_refs(handle: str, address: str | int, max_results: int | None = None) -> dict:
        """List data references targeting *address*."""

        _log_tool_call(
            "bn_data_refs",
            {"handle": handle, "address": str(address), "max_results": max_results},
        )
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(
            lambda: service.get_data_references(handle, addr, max_results=max_results)
        )

    @app.tool()
    @ratelimited
    def bn_strings(handle: str, min_length: int = 4) -> dict:
        """Extract strings from the view."""

        _log_tool_call("bn_strings", {"handle": handle, "min_length": min_length})
        service = require_service()
        return _wrap_service_call(lambda: service.get_strings(handle, min_length=min_length))

    @app.tool()
    @ratelimited
    def bn_find_strings(
        handle: str,
        query: str | None = None,
        min_length: int = 4,
    ) -> dict:
        """Search strings discovered in the view."""

        if min_length <= 0:
            raise RuntimeError("min_length must be positive")

        _log_tool_call(
            "bn_find_strings",
            {"handle": handle, "query": query, "min_length": min_length},
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.find_strings(handle, query=query, min_length=min_length)
        )

    @app.tool()
    @ratelimited
    def bn_symbols(handle: str, symbol_type: Optional[str] = None) -> dict:
        """Enumerate symbols from the view."""

        _log_tool_call("bn_symbols", {"handle": handle, "symbol_type": symbol_type})
        service = require_service()
        return _wrap_service_call(lambda: service.get_symbols(handle, symbol_type=symbol_type))

    @app.tool()
    @ratelimited
    def bn_read(handle: str, address: str, length: int) -> dict:
        """Read bytes at an address from the view."""

        _log_tool_call("bn_read", {"handle": handle, "address": address, "length": length})
        service = require_service()
        addr_int = _parse_address(address)
        return _wrap_service_call(lambda: service.read_bytes(handle, addr_int, length))

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
    except Exception as exc:
        logging.getLogger("mcp.server").debug(
            "mcp.server.fastmcp.run failed, falling back to app.run: %s",
            exc,
        )
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
