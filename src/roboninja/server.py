"""RoboNinja FastMCP server module."""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
from typing import Annotated, Optional

from pydantic import Field

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


class Settings:
    """Runtime configuration for the FastMCP server."""

    __slots__ = ("log_level",)

    def __init__(self, log_level: str = "INFO") -> None:
        self.log_level = log_level

    @classmethod
    def from_env(cls) -> "Settings":
        value = (
            os.getenv("ROBONINJA_LOG_LEVEL")
            or os.getenv("MCP_LOG_LEVEL")
            or os.getenv("LOG_LEVEL")
        )
        if value:
            normalized = value.strip().upper()
            if normalized in logging._nameToLevel:
                return cls(normalized)
        return cls()


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


def _configure_logging(log_level: str) -> logging.Logger:
    handler = logging.StreamHandler()
    if handler.stream.isatty():
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    else:
        handler.setFormatter(JsonFormatter())
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))
    root_logger.handlers[:] = [handler]

    # Suppress noisy per-call logging from the low-level MCP server unless explicitly re-enabled.
    logging.getLogger("mcp.server.lowlevel").setLevel(logging.WARNING)

    return logging.getLogger("mcp.server")


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


def _estimate_payload_metrics(result: object) -> dict:
    metrics: dict[str, object] = {}

    serialized: Optional[str] = None
    try:
        serialized = json.dumps(result, ensure_ascii=False)
    except TypeError as exc:
        text = str(result)
        metrics["serialization_error"] = type(exc).__name__
        metrics["size_bytes"] = len(text.encode("utf-8", errors="replace"))
        metrics["size_chars"] = len(text)
    else:
        metrics["size_bytes"] = len(serialized.encode("utf-8"))
        metrics["size_chars"] = len(serialized)

    if isinstance(result, dict):
        metrics["top_level_keys"] = len(result)
    elif isinstance(result, list):
        metrics["top_level_items"] = len(result)

    return metrics


def _log_tool_result(name: str, result: object, duration: float) -> None:
    metrics = _estimate_payload_metrics(result)
    metrics.setdefault("size_bytes", 0)
    metrics.setdefault("size_chars", 0)
    metrics["tool"] = name
    metrics["duration_ms"] = round(duration * 1000.0, 2)

    payload = json.dumps(metrics, ensure_ascii=False)
    logging.getLogger("mcp.server").debug("Tool result: %s", payload)
    _bn_log("debug", f"RoboNinja tool result: {payload}")
def _parse_address(value: str | int) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError as exc:
        raise RuntimeError(f"Invalid address '{value}'. Provide an integer or hex string.") from exc


def _wrap_service_call(fn, *, tool_name: Optional[str] = None):
    start = time.perf_counter()
    try:
        result = fn()
    except BinaryNinjaLicenseError as exc:
        raise RuntimeError(f"Binary Ninja license error: {exc}") from exc
    except BinaryNinjaServiceError as exc:
        raise RuntimeError(str(exc)) from exc
    else:
        if tool_name:
            try:
                duration = time.perf_counter() - start
                _log_tool_result(tool_name, result, duration)
            except Exception:  # pragma: no cover - logging must not break tools
                logging.getLogger("mcp.server").debug(
                    "Failed to log result metrics for %s", tool_name, exc_info=True
                )
        return result


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
    app = FastMCP("roboninja-server")

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

    @app.tool(
        name="bn_list",
        description="List every Binary Ninja view currently tracked by the RoboNinja service.",
    )
    def bn_list() -> dict:
        """List active Binary Ninja views."""

        _log_tool_call("bn_list", {})
        service = require_service()
        return _wrap_service_call(service.list_views, tool_name="bn_list")

    @app.tool(
        name="bn_functions",
        description="Enumerate functions in a Binary Ninja view with optional name and size filters.",
    )
    def bn_functions(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view returned by `bn_list` or other tooling."),
        ],
        name_contains: Annotated[
            Optional[str],
            Field(
                default=None,
                description="Optional case-insensitive substring that function names must contain.",
            ),
        ] = None,
        min_size: Annotated[
            int,
            Field(default=0, ge=0, description="Minimum function size in bytes to include in the results."),
        ] = 0,
        limit: Annotated[
            Optional[int],
            Field(
                default=100,
                ge=0,
                description="Maximum number of functions to return (0 means no limit).",
            ),
        ] = 100,
    ) -> dict:
        """Return function metadata for a view."""

        _log_tool_call(
            "bn_functions",
            {
                "handle": handle,
                "name_contains": name_contains,
                "min_size": min_size,
                "limit": limit,
            },
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.get_function_list(
                handle,
                name_contains=name_contains,
                min_size=min_size,
                limit=limit if limit and limit > 0 else None,
            ),
            tool_name="bn_functions",
        )

    

    @app.tool(
        name="bn_hlil",
        description="Retrieve High Level IL text for a function, optionally limited to a maximum instruction count.",
    )
    def bn_hlil(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view that owns the function."),
        ],
        function: Annotated[
            str,
            Field(description="Function identifier: accepts a name or address (hex or decimal)."),
        ],
        max_instructions: Annotated[
            Optional[int],
            Field(
                default=None,
                ge=0,
                description="Optional cap on the number of HLIL instructions to return (0 means unlimited).",
            ),
        ] = None,
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
            ),
            tool_name="bn_hlil",
        )

    @app.tool(
        name="bn_rename_function",
        description="Assign a user-defined symbol name to a function within a Binary Ninja view.",
    )
    def bn_rename_function(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view containing the function to rename."),
        ],
        function: Annotated[
            str,
            Field(description="Function identifier: accepts a name or address (hex or decimal)."),
        ],
        new_name: Annotated[
            str,
            Field(description="Desired user-visible symbol name for the function."),
        ],
    ) -> dict:
        """Rename a Binary Ninja function to a new symbolic name."""

        _log_tool_call(
            "bn_rename_function",
            {"handle": handle, "function": function, "new_name": new_name},
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.rename_function(handle, function, new_name),
            tool_name="bn_rename_function",
        )

    @app.tool(
        name="bn_list_variables",
        description="List parameters, locals, and stack variables defined for a function.",
    )
    def bn_list_variables(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view containing the function."),
        ],
        function: Annotated[
            str,
            Field(description="Function identifier: accepts a name or address (hex or decimal)."),
        ],
        max_parameters: Annotated[
            Optional[int],
            Field(
                default=32,
                ge=0,
                description="Maximum parameter entries to return (0 means no cap).",
            ),
        ] = 32,
        max_stack: Annotated[
            Optional[int],
            Field(
                default=64,
                ge=0,
                description="Maximum stack variable entries to return (0 means no cap).",
            ),
        ] = 64,
        max_variables: Annotated[
            Optional[int],
            Field(
                default=64,
                ge=0,
                description="Maximum other variable entries to return (0 means no cap).",
            ),
        ] = 64,
    ) -> dict:
        """Enumerate variables associated with a function."""

        _log_tool_call(
            "bn_list_variables",
            {
                "handle": handle,
                "function": function,
                "max_parameters": max_parameters,
                "max_stack": max_stack,
                "max_variables": max_variables,
            },
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.list_variables(
                handle,
                function,
                max_parameters=max_parameters if max_parameters and max_parameters > 0 else None,
                max_stack=max_stack if max_stack and max_stack > 0 else None,
                max_variables=max_variables if max_variables and max_variables > 0 else None,
            ),
            tool_name="bn_list_variables",
        )

    @app.tool(
        name="bn_rename_variable",
        description="Rename and optionally retype a function variable (parameter, local, or stack slot).",
    )
    def bn_rename_variable(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view containing the variable."),
        ],
        function: Annotated[
            str,
            Field(description="Function identifier: accepts a name or address (hex or decimal)."),
        ],
        variable: Annotated[
            str,
            Field(
                description=(
                    "Variable identifier from `bn_list_variables`, such as `param:0`, `var:3`, or `stack:-0x40`."
                ),
            ),
        ],
        new_name: Annotated[
            str,
            Field(description="New user-defined name to assign to the variable."),
        ],
        new_type: Annotated[
            Optional[str],
            Field(
                default=None,
                description="Optional Binary Ninja type string to apply; omit to keep the existing type.",
            ),
        ] = None,
    ) -> dict:
        """Rename (and optionally retype) a function variable."""

        _log_tool_call(
            "bn_rename_variable",
            {
                "handle": handle,
                "function": function,
                "variable": variable,
                "new_name": new_name,
                "new_type": new_type,
            },
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.rename_variable(
                handle,
                function,
                variable,
                new_name,
                new_type=new_type,
            ),
            tool_name="bn_rename_variable",
        )

    @app.tool(
        name="bn_rename_stack_variable",
        description="Convenience wrapper to rename a stack variable by frame offset using `bn_rename_variable`.",
    )
    def bn_rename_stack_variable(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view containing the function."),
        ],
        function: Annotated[
            str,
            Field(description="Function identifier: accepts a name or address (hex or decimal)."),
        ],
        offset: Annotated[
            str | int,
            Field(description="Stack frame offset of the variable (accepts decimal or hex string)."),
        ],
        new_name: Annotated[
            str,
            Field(description="New user-defined name to assign to the stack variable."),
        ],
        new_type: Annotated[
            Optional[str],
            Field(
                default=None,
                description="Optional Binary Ninja type string to apply; omit to keep the existing type.",
            ),
        ] = None,
    ) -> dict:
        """Rename a stack variable by offset."""

        _log_tool_call(
            "bn_rename_stack_variable",
            {
                "handle": handle,
                "function": function,
                "offset": str(offset),
                "new_name": new_name,
                "new_type": new_type,
            },
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.rename_stack_variable(
                handle,
                function,
                offset,
                new_name,
                new_type=new_type,
            ),
            tool_name="bn_rename_stack_variable",
        )

    @app.tool(
        name="bn_define_data_variable",
        description="Define or rename a user data variable at a given virtual address.",
    )
    def bn_define_data_variable(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view where the data resides."),
        ],
        address: Annotated[
            str | int,
            Field(description="Address of the data variable (decimal or hex string)."),
        ],
        var_type: Annotated[
            str,
            Field(description="Binary Ninja type string describing the variable to define."),
        ],
        name: Annotated[
            Optional[str],
            Field(
                default=None,
                description="Optional symbol name to associate with the data variable.",
            ),
        ] = None,
    ) -> dict:
        """Define or rename a user data variable at the specified address."""

        _log_tool_call(
            "bn_define_data_variable",
            {
                "handle": handle,
                "address": str(address),
                "var_type": var_type,
                "name": name,
            },
        )
        service = require_service()
        return _wrap_service_call(
            lambda: service.define_data_variable(handle, address, var_type, name=name),
            tool_name="bn_define_data_variable",
        )

    @app.tool(
        name="bn_set_comment",
        description="Attach or overwrite a repeatable comment at a specific address.",
    )
    def bn_set_comment(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view where the comment should be written."),
        ],
        address: Annotated[
            str | int,
            Field(description="Address to annotate (decimal or hex string)."),
        ],
        text: Annotated[
            str,
            Field(description="Comment text to store at the address."),
        ],
    ) -> dict:
        """Attach a repeatable comment at the specified address."""

        _log_tool_call(
            "bn_set_comment",
            {"handle": handle, "address": str(address), "text": text},
        )
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(
            lambda: service.set_comment(handle, addr, text),
            tool_name="bn_set_comment",
        )

    @app.tool(
        name="bn_disassemble",
        description="Return linear disassembly text starting at the given address for a number of instructions.",
    )
    def bn_disassemble(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view to disassemble."),
        ],
        address: Annotated[
            str | int,
            Field(description="Starting address for disassembly (decimal or hex string)."),
        ],
        count: Annotated[
            int,
            Field(
                default=1,
                gt=0,
                description="Number of instructions to decode; must be a positive integer.",
            ),
        ] = 1,
    ) -> dict:
        """Return disassembly text starting at *address* for *count* instructions."""

        if count <= 0:
            raise RuntimeError("count must be positive")

        _log_tool_call(
            "bn_disassemble",
            {"handle": handle, "address": str(address), "count": count},
        )
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(
            lambda: service.disassemble(handle, addr, count=count),
            tool_name="bn_disassemble",
        )

    @app.tool(
        name="bn_code_refs",
        description="List code references targeting the specified address.",
    )
    def bn_code_refs(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view to query."),
        ],
        address: Annotated[
            str | int,
            Field(description="Target address to inspect for incoming code references."),
        ],
        max_results: Annotated[
            Optional[int],
            Field(
                default=None,
                ge=0,
                description="Optional cap on the number of references to return; omit for all.",
            ),
        ] = None,
    ) -> dict:
        """List code references targeting *address*."""

        _log_tool_call(
            "bn_code_refs",
            {"handle": handle, "address": str(address), "max_results": max_results},
        )
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(
            lambda: service.get_code_references(handle, addr, max_results=max_results),
            tool_name="bn_code_refs",
        )

    @app.tool(
        name="bn_data_refs",
        description="List data references targeting the specified address.",
    )
    def bn_data_refs(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view to query."),
        ],
        address: Annotated[
            str | int,
            Field(description="Target address to inspect for incoming data references."),
        ],
        max_results: Annotated[
            Optional[int],
            Field(
                default=None,
                ge=0,
                description="Optional cap on the number of references to return; omit for all.",
            ),
        ] = None,
    ) -> dict:
        """List data references targeting *address*."""

        _log_tool_call(
            "bn_data_refs",
            {"handle": handle, "address": str(address), "max_results": max_results},
        )
        service = require_service()
        addr = _parse_address(address)
        return _wrap_service_call(
            lambda: service.get_data_references(handle, addr, max_results=max_results),
            tool_name="bn_data_refs",
        )

    @app.tool(
        name="bn_symbols",
        description="Enumerate symbols in a Binary Ninja view, optionally filtered by symbol type.",
    )
    def bn_symbols(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view to inspect."),
        ],
        symbol_type: Annotated[
            Optional[str],
            Field(
                default=None,
                description="Optional symbol type name to filter by (e.g. `FunctionSymbol`, `DataSymbol`).",
            ),
        ] = None,
    ) -> dict:
        """Enumerate symbols from the view."""

        _log_tool_call("bn_symbols", {"handle": handle, "symbol_type": symbol_type})
        service = require_service()
        return _wrap_service_call(
            lambda: service.get_symbols(handle, symbol_type=symbol_type),
            tool_name="bn_symbols",
        )

    @app.tool(
        name="bn_read",
        description="Read raw bytes from a Binary Ninja view at the specified address.",
    )
    def bn_read(
        handle: Annotated[
            str,
            Field(description="Handle of the Binary Ninja view to read from."),
        ],
        address: Annotated[
            str,
            Field(description="Starting address for the read (decimal or hex string)."),
        ],
        length: Annotated[
            int,
            Field(gt=0, description="Number of bytes to read; must be a positive integer."),
        ],
    ) -> dict:
        """Read bytes at an address from the view."""

        _log_tool_call("bn_read", {"handle": handle, "address": address, "length": length})
        service = require_service()
        addr_int = _parse_address(address)
        return _wrap_service_call(
            lambda: service.read_bytes(handle, addr_int, length),
            tool_name="bn_read",
        )

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
    settings = Settings.from_env()
    logging.getLogger("mcp.server").info(
        "Starting RoboNinja server (log level=%s) via %s", settings.log_level, args.transport
    )
    run_stdio()


if FastMCP is not None:
    mcp = create_app()
else:
    mcp = None


if __name__ == "__main__":
    main()
