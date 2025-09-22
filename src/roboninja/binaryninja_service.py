"""Binary Ninja integration helpers for the RoboNinja MCP server."""

from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import binaryninja  # type: ignore
except Exception as exc:  # pragma: no cover - handled downstream
    binaryninja = None  # type: ignore
    _BINARYNINJA_IMPORT_ERROR = exc
else:  # pragma: no cover - import success path exercised via service methods
    _BINARYNINJA_IMPORT_ERROR = None


LICENSE_FILE_ENV_VARS = ("BN_LICENSE_PATH", "BINARYNINJA_LICENSE_PATH", "ROBONINJA_LICENSE_PATH")
LICENSE_KEY_ENV_VARS = ("BN_LICENSE", "BINARYNINJA_LICENSE", "ROBONINJA_LICENSE")


LICENSE_FILE_ENV_VARS = ("BN_LICENSE_PATH", "BINARYNINJA_LICENSE_PATH", "ROBONINJA_LICENSE_PATH")
LICENSE_KEY_ENV_VARS = ("BN_LICENSE", "BINARYNINJA_LICENSE", "ROBONINJA_LICENSE")


def _read_license_text() -> Optional[str]:
    for env in LICENSE_KEY_ENV_VARS:
        value = os.getenv(env)
        if value:
            return value

    for env in LICENSE_FILE_ENV_VARS:
        value = os.getenv(env)
        if value:
            candidate = Path(value).expanduser()
            if candidate.exists():
                try:
                    return candidate.read_text()
                except Exception:
                    continue

    default_path = Path.home() / ".binaryninja" / "license.dat"
    if default_path.exists():
        try:
            return default_path.read_text()
        except Exception:
            pass
    return None


def _ensure_license_loaded() -> None:
    if binaryninja is None:
        return
    license_count = getattr(binaryninja, "core_license_count", None)
    if callable(license_count):
        try:
            if license_count() > 0:
                return
        except Exception:
            pass

    setter = getattr(binaryninja, "core_set_license", None)
    if not callable(setter):
        return

    text = _read_license_text()
    if not text:
        return
    try:
        setter(text)
    except Exception:
        pass
def _format_addr(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return f"0x{int(value):x}"


@dataclass
class _ManagedView:
    handle: str
    path: str
    opened_at: float
    view: Any


class BinaryNinjaServiceError(RuntimeError):
    """Base error for Binary Ninja service failures."""


class BinaryNinjaUnavailableError(BinaryNinjaServiceError):
    """Raised when the Binary Ninja module is not importable."""


class BinaryNinjaLicenseError(BinaryNinjaServiceError):
    """Raised when Binary Ninja reports a licensing failure."""


class BinaryNinjaHandleError(BinaryNinjaServiceError):
    """Raised when a caller references an unknown view handle."""


class BinaryNinjaFunctionError(BinaryNinjaServiceError):
    """Raised when a requested function cannot be resolved."""


class BinaryNinjaService:
    """Thin lifecycle manager around Binary Ninja views for MCP tools."""

    def __init__(self) -> None:
        if binaryninja is None:
            detail = (
                f"Binary Ninja Python module not available: {_BINARYNINJA_IMPORT_ERROR}"
                if _BINARYNINJA_IMPORT_ERROR
                else "Binary Ninja Python module not available"
            )
            raise BinaryNinjaUnavailableError(detail)

        self._views: Dict[str, _ManagedView] = {}
        self._lock = threading.RLock()
        _ensure_license_loaded()

    # ------------------------------------------------------------------
    # View management
    # ------------------------------------------------------------------

    def open_view(
        self,
        path: str,
        *,
        update_analysis: bool = True,
        analysis_timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Open a binary at *path* and return metadata describing the view."""

        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Binary not found: {resolved}")

        start_time = time.time()
        try:
            view = binaryninja.load(str(resolved))  # type: ignore[union-attr]
        except RuntimeError as exc:  # Binary Ninja often throws RuntimeError
            message = str(exc)
            if "License is not valid" in message:
                raise BinaryNinjaLicenseError(message) from exc
            raise BinaryNinjaServiceError(f"Failed to open {resolved}: {message}") from exc
        except Exception as exc:  # pragma: no cover - defensive
            raise BinaryNinjaServiceError(f"Failed to open {resolved}: {exc}") from exc

        try:
            if update_analysis:
                self._update_analysis(view, analysis_timeout)

            handle = uuid.uuid4().hex
            managed = _ManagedView(handle=handle, path=str(resolved), opened_at=start_time, view=view)
            with self._lock:
                self._views[handle] = managed

            return self._view_summary(managed)
        except Exception:
            # Ensure we do not leak a view if post-processing fails
            try:
                view.file.close()
            except Exception:  # pragma: no cover - best effort cleanup
                pass
            raise

    def list_views(self) -> Dict[str, Any]:
        """Return metadata for all open views."""

        with self._lock:
            summaries = [self._view_summary(view) for view in self._views.values()]
        return {"views": summaries}

    def close_view(self, handle: str) -> Dict[str, Any]:
        """Close the BinaryView referenced by *handle*."""

        with self._lock:
            managed = self._views.pop(handle, None)
        if managed is None:
            raise BinaryNinjaHandleError(f"Unknown Binary Ninja handle: {handle}")

        try:
            managed.view.file.close()
        except Exception as exc:
            raise BinaryNinjaServiceError(f"Failed to close view {handle}: {exc}") from exc

        return {"closed": True, "handle": handle, "path": managed.path}

    # ------------------------------------------------------------------
    # Function inspection
    # ------------------------------------------------------------------

    def get_function_list(
        self,
        handle: str,
        *,
        name_contains: Optional[str] = None,
        min_size: int = 0,
    ) -> Dict[str, Any]:
        view = self._get_view(handle)
        name_filter = name_contains.lower() if name_contains else None

        functions = []
        for func in view.functions:
            if name_filter and name_filter not in func.name.lower():
                continue
            size = getattr(func, "total_bytes", getattr(func, "size", 0))
            if size < min_size:
                continue
            functions.append(
                {
                    "name": func.name,
                    "start": _format_addr(getattr(func, "start", None)),
                    "size": size,
                    "basic_block_count": len(getattr(func, "basic_blocks", [])),
                    "calling_convention": getattr(getattr(func, "calling_convention", None), "name", None),
                    "return_type": self._stringify(getattr(getattr(func, "type", None), "return_value", None)),
                }
            )

        return {"handle": handle, "functions": functions}

    def get_function_summary(self, handle: str, identifier: str) -> Dict[str, Any]:
        view = self._get_view(handle)
        func = self._resolve_function(view, identifier)

        return {
            "handle": handle,
            "name": func.name,
            "start": _format_addr(getattr(func, "start", None)),
            "size": getattr(func, "total_bytes", getattr(func, "size", 0)),
            "basic_block_count": len(getattr(func, "basic_blocks", [])),
            "calling_convention": getattr(getattr(func, "calling_convention", None), "name", None),
            "return_type": self._stringify(getattr(getattr(func, "type", None), "return_value", None)),
            "parameters": [self._stringify(param) for param in getattr(func, "parameter_vars", [])],
        }

    def get_high_level_il(
        self,
        handle: str,
        identifier: str,
        *,
        max_instructions: Optional[int] = None,
    ) -> Dict[str, Any]:
        view = self._get_view(handle)
        func = self._resolve_function(view, identifier)

        hlil = getattr(func, "hlil", None)
        if hlil is None:
            raise BinaryNinjaServiceError(f"Function {identifier} has no High Level IL available")

        instructions = [str(instr) for instr in getattr(hlil, "instructions", [])]
        if max_instructions is not None:
            instructions = instructions[: max(0, max_instructions)]

        return {"handle": handle, "function": func.name, "lines": instructions}

    def get_basic_blocks(self, handle: str, identifier: str) -> Dict[str, Any]:
        view = self._get_view(handle)
        func = self._resolve_function(view, identifier)

        blocks = []
        for block in getattr(func, "basic_blocks", []):
            edges = []
            for edge in getattr(block, "outgoing_edges", []):
                target = getattr(edge, "target", None)
                edges.append(
                    {
                        "type": getattr(edge, "type", None),
                        "target": _format_addr(getattr(target, "start", getattr(target, "addr", None)))
                        if target
                        else None,
                    }
                )
            blocks.append(
                {
                    "start": _format_addr(getattr(block, "start", None)),
                    "end": _format_addr(getattr(block, "end", None)),
                    "length": getattr(block, "length", None),
                    "outgoing_edges": edges,
                }
            )

        return {"handle": handle, "function": func.name, "blocks": blocks}

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    def get_strings(self, handle: str, *, min_length: int = 4) -> Dict[str, Any]:
        view = self._get_view(handle)
        strings = []
        try:
            iterator = view.get_strings()
        except AttributeError:  # pragma: no cover - compatibility shim
            iterator = view.strings

        for string in iterator:
            length = getattr(string, "length", None)
            if length is None or length < min_length:
                continue
            strings.append(
                {
                    "value": getattr(string, "value", ""),
                    "start": _format_addr(getattr(string, "start", None)),
                    "length": length,
                    "type": getattr(getattr(string, "type", None), "name", None),
                }
            )

        return {"handle": handle, "strings": strings}

    def get_symbols(self, handle: str, *, symbol_type: Optional[str] = None) -> Dict[str, Any]:
        view = self._get_view(handle)
        symbols = []
        filter_type = symbol_type.lower() if symbol_type else None

        for symbol in view.get_symbols():
            type_name = getattr(getattr(symbol, "type", None), "name", None)
            if filter_type and (type_name or "").lower() != filter_type:
                continue
            symbols.append(
                {
                    "name": getattr(symbol, "name", None),
                    "short_name": getattr(symbol, "short_name", None),
                    "full_name": getattr(symbol, "full_name", None),
                    "type": type_name,
                    "binding": getattr(getattr(symbol, "binding", None), "name", None),
                    "address": _format_addr(getattr(symbol, "address", None)),
                }
            )

        return {"handle": handle, "symbols": symbols}

    def read_bytes(self, handle: str, address: int, length: int) -> Dict[str, Any]:
        view = self._get_view(handle)
        if length <= 0:
            raise ValueError("length must be positive")
        data = view.read(address, length)
        if not data:
            raise BinaryNinjaServiceError(f"Unable to read {length} bytes at {hex(address)}")

        return {
            "handle": handle,
            "address": _format_addr(address),
            "bytes": data.hex(),
            "length": len(data),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_view(self, handle: str) -> Any:
        with self._lock:
            managed = self._views.get(handle)
        if managed is None:
            raise BinaryNinjaHandleError(f"Unknown Binary Ninja handle: {handle}")
        return managed.view

    def _resolve_function(self, view: Any, identifier: str) -> Any:
        ident = identifier.strip()
        # Try hex or decimal address first
        try:
            address = int(ident, 0)
        except ValueError:
            address = None

        if address is not None:
            matches = view.get_functions_at(address)
            if matches:
                return matches[0]

        matches = view.get_functions_by_name(ident)
        if matches:
            return matches[0]

        raise BinaryNinjaFunctionError(f"Function not found: {identifier}")

    def _update_analysis(self, view: Any, timeout: Optional[float]) -> None:
        if timeout is None:
            view.update_analysis_and_wait()
            return

        start = time.time()
        view.update_analysis()
        while True:
            state = getattr(getattr(view, "analysis_info", None), "state", None)
            if self._analysis_state_is_idle(state):
                break
            if time.time() - start > timeout:
                break
            time.sleep(0.1)

    def _analysis_state_is_idle(self, state: Any) -> bool:
        idle_state = getattr(getattr(binaryninja, "AnalysisState", None), "Idle", None)
        return idle_state is not None and state == idle_state

    def _view_summary(self, managed: _ManagedView) -> Dict[str, Any]:
        view = managed.view
        info = getattr(view, "analysis_info", None)
        progress = getattr(info, "progress", None)
        state = getattr(info, "state", None)
        analysis_state = getattr(state, "name", str(state) if state is not None else None)
        analysis_complete = self._analysis_state_is_idle(state)

        progress_percent = None
        if progress is not None:
            try:
                progress_percent = float(progress) * 100.0
            except Exception:  # pragma: no cover
                progress_percent = None

        return {
            "handle": managed.handle,
            "path": managed.path,
            "opened_at": managed.opened_at,
            "file_size": os.path.getsize(managed.path) if os.path.exists(managed.path) else None,
            "architecture": getattr(getattr(view, "arch", None), "name", None),
            "platform": getattr(getattr(view, "platform", None), "name", None),
            "entry_point": _format_addr(getattr(view, "entry_point", None)),
            "analysis_state": analysis_state,
            "analysis_progress": progress_percent,
            "analysis_complete": analysis_complete,
        }

    def _stringify(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        try:
            return str(value)
        except Exception:  # pragma: no cover - defensive
            return None
