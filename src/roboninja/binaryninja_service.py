"""Binary Ninja integration helpers for the RoboNinja MCP server."""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import Event, current_thread
from typing import Any, Dict, List, Optional, Tuple


LOG = logging.getLogger(__name__)

try:
    import binaryninja  # type: ignore
except Exception as exc:  # pragma: no cover - handled downstream
    binaryninja = None  # type: ignore
    _BINARYNINJA_IMPORT_ERROR = exc
    LOG.debug("Binary Ninja import failed: %s", exc)
else:  # pragma: no cover - import success path exercised via service methods
    _BINARYNINJA_IMPORT_ERROR = None


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
                except Exception as exc:
                    LOG.debug("Unable to read license file %s: %s", candidate, exc)
                    continue

    default_path = Path.home() / ".binaryninja" / "license.dat"
    if default_path.exists():
        try:
            return default_path.read_text()
        except Exception as exc:
            LOG.debug("Unable to read default license file %s: %s", default_path, exc)
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
        except Exception as exc:
            LOG.debug("core_license_count() failed: %s", exc)
            pass

    setter = getattr(binaryninja, "core_set_license", None)
    if not callable(setter):
        return

    text = _read_license_text()
    if not text:
        return
    try:
        setter(text)
    except Exception as exc:
        LOG.warning("Failed to set Binary Ninja license: %s", exc)


def _resolve_view_path(view) -> Optional[Path]:
    if view is None:
        return None
    file_obj = getattr(view, "file", None)
    candidate = None
    if file_obj is not None:
        candidate = getattr(file_obj, "original_filename", None) or getattr(file_obj, "filename", None)
    elif hasattr(view, "file_name"):
        candidate = getattr(view, "file_name")
    if not candidate:
        return None
    try:
        return Path(candidate).expanduser().resolve()
    except Exception:
        return None


def _get_plugin_active_view() -> Any | None:
    module = sys.modules.get("roboninja_plugin")
    if module is None:
        return None
    getter = getattr(module, "get_active_binary_view", None)
    if not callable(getter):
        return None
    try:
        return getter()
    except Exception:
        return None
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
    owns_view: bool


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




_SERVICE_SINGLETON: Optional["BinaryNinjaService"] = None


def get_service_singleton() -> "BinaryNinjaService":
    """Return a process-wide BinaryNinjaService instance."""

    global _SERVICE_SINGLETON
    if _SERVICE_SINGLETON is None:
        _SERVICE_SINGLETON = BinaryNinjaService()
    return _SERVICE_SINGLETON

class BinaryNinjaService:
    """Thin lifecycle manager around Binary Ninja views for MCP tools."""

    _log = logging.getLogger(__name__)

    def __init__(self, *, find_view_timeout: float = 5.0) -> None:
        if binaryninja is None:
            detail = (
                f"Binary Ninja Python module not available: {_BINARYNINJA_IMPORT_ERROR}"
                if _BINARYNINJA_IMPORT_ERROR
                else "Binary Ninja Python module not available"
            )
            raise BinaryNinjaUnavailableError(detail)

        self._views: Dict[str, _ManagedView] = {}
        self._lock = threading.RLock()
        self._find_view_timeout = max(0.0, find_view_timeout)
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
        allow_create: bool = False,
    ) -> Dict[str, Any]:
        """Open a binary at *path* and return metadata describing the view."""

        resolved = Path(path).expanduser().resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"Binary not found: {resolved}")

        plugin_view = _get_plugin_active_view()
        existing_view = None
        if plugin_view is not None:
            plugin_path = _resolve_view_path(plugin_view)
            if plugin_path == resolved:
                existing_view = plugin_view

        if existing_view is None:
            existing_view = self._find_existing_view(resolved)
        if existing_view is None and self._can_query_open_views() and self._find_view_timeout > 0:
            self._log.debug(
                "Waiting up to %.2fs for Binary Ninja to expose %s via get_open_views",
                self._find_view_timeout,
                resolved,
            )
            deadline = time.time() + self._find_view_timeout
            while time.time() < deadline:
                time.sleep(0.05)
                existing_view = self._find_existing_view(resolved)
                if existing_view is not None:
                    break

        owns_view = False

        start_time = time.time()
        try:
            if existing_view is not None:
                self._log.debug("Reusing existing BinaryView for %s", resolved)
                view = existing_view
            else:
                self._log.debug(
                    "No GUI BinaryView found for %s (allow_create=%s)",
                    resolved,
                    allow_create,
                )
                if not allow_create:
                    self._log.warning(
                        "Refusing to auto-create BinaryView for %s; GUI has not opened the file",
                        resolved,
                    )
                    raise BinaryNinjaServiceError(
                        "Binary Ninja GUI has not opened this file yet. "
                        "Open it in the UI or call bn_open with allow_create=True."
                    )
                self._log.info("Creating new BinaryView for %s on behalf of caller", resolved)
                view = binaryninja.load(str(resolved))  # type: ignore[union-attr]
                owns_view = True
        except RuntimeError as exc:  # Binary Ninja often throws RuntimeError
            message = str(exc)
            if "License is not valid" in message:
                raise BinaryNinjaLicenseError(message) from exc
            raise BinaryNinjaServiceError(f"Failed to open {resolved}: {message}") from exc
        except Exception as exc:  # pragma: no cover - defensive
            self._log.exception("Unexpected failure opening %s via Binary Ninja", resolved)
            raise BinaryNinjaServiceError(f"Failed to open {resolved}: {exc}") from exc

        try:
            if update_analysis and hasattr(view, "update_analysis"):
                self._update_analysis(view, analysis_timeout)

            handle = uuid.uuid4().hex
            managed = _ManagedView(
                handle=handle,
                path=str(resolved),
                opened_at=start_time,
                view=view,
                owns_view=owns_view,
            )
            with self._lock:
                self._views[handle] = managed

            return self._view_summary(managed)
        except Exception as exc:
            self._log.exception("Post-processing BinaryView %s failed", resolved)
            # Ensure we do not leak a view if post-processing fails
            if owns_view:
                try:
                    view.file.close()
                except Exception as exc:  # pragma: no cover - best effort cleanup
                    self._log.debug(
                        "Suppressed error while closing BinaryView for %s: %s",
                        resolved,
                        exc,
                        exc_info=True,
                    )
            raise

    def list_views(self) -> Dict[str, Any]:
        """Return metadata for all open views."""

        self._auto_attach_open_views()
        with self._lock:
            summaries = [self._view_summary(view) for view in self._views.values()]
        return {"views": summaries}

    def attach_existing_view(self, view: Any, *, path: Optional[str] = None) -> str:
        """Register an existing BinaryView with the service and return its handle."""

        resolved = None
        if path is not None:
            try:
                resolved = Path(path).expanduser().resolve()
            except Exception as exc:
                raise BinaryNinjaServiceError(f"Invalid Binary Ninja path: {path}") from exc
        if resolved is None:
            resolved = _resolve_view_path(view)
        if resolved is None:
            raise BinaryNinjaServiceError("Unable to determine Binary Ninja view path")

        handle = None
        with self._lock:
            for existing_handle, managed in self._views.items():
                if managed.view is view or managed.path == str(resolved):
                    handle = existing_handle
                    managed.view = view
                    managed.owns_view = False
                    self._views[existing_handle] = managed
                    break
            if handle is None:
                handle = uuid.uuid4().hex
                managed = _ManagedView(
                    handle=handle,
                    path=str(resolved),
                    opened_at=time.time(),
                    view=view,
                    owns_view=False,
                )
                self._views[handle] = managed

        self._log.debug("Attached existing BinaryView %s with handle %s", resolved, handle)
        return handle

    def close_view(self, handle: str) -> Dict[str, Any]:
        """Close the BinaryView referenced by *handle*."""

        with self._lock:
            managed = self._views.pop(handle, None)
        if managed is None:
            raise BinaryNinjaHandleError(f"Unknown Binary Ninja handle: {handle}")

        if managed.owns_view:
            try:
                managed.view.file.close()
            except Exception as exc:
                self._log.warning(
                    "Binary Ninja reported error closing view %s (%s): %s",
                    handle,
                    managed.path,
                    exc,
                )
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
        limit: Optional[int] = None,
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
            if limit and len(functions) >= limit:
                break

        return {"handle": handle, "functions": functions}

    

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
        if max_instructions is not None and max_instructions > 0:
            instructions = instructions[: max_instructions]

        return {"handle": handle, "function": func.name, "lines": instructions}

    # ------------------------------------------------------------------
    # Data extraction
    # ------------------------------------------------------------------

    def get_strings(self, handle: str, *, min_length: int = 4) -> Dict[str, Any]:
        view = self._get_view(handle)
        strings = []
        try:
            iterator = view.get_strings()
        except AttributeError:  # pragma: no cover - compatibility shim
            iterator = getattr(view, "strings", None)
        except Exception as exc:  # pragma: no cover - defensive
            self._log.debug("view.get_strings() failed: %s", exc, exc_info=True)
            raise BinaryNinjaServiceError(f"Failed to enumerate strings: {exc}") from exc

        if iterator is None:
            iterator = []

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

        try:
            symbol_iter = view.get_symbols()
        except Exception as exc:  # pragma: no cover - defensive
            self._log.debug("view.get_symbols() failed: %s", exc, exc_info=True)
            raise BinaryNinjaServiceError(f"Failed to enumerate symbols: {exc}") from exc

        for symbol in symbol_iter or []:
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
    # Mutation helpers
    # ------------------------------------------------------------------

    def rename_function(self, handle: str, identifier: str, new_name: str) -> Dict[str, Any]:
        if not new_name or not new_name.strip():
            raise ValueError("new_name must be a non-empty string")

        view = self._get_view(handle)
        func = self._resolve_function(view, identifier)

        if binaryninja is None or not hasattr(binaryninja, "Symbol"):
            raise BinaryNinjaServiceError("Binary Ninja Symbol API unavailable")

        try:
            symbol = binaryninja.Symbol(binaryninja.SymbolType.FunctionSymbol, func.start, new_name)

            def _apply() -> None:
                view.define_user_symbol(symbol)
                if hasattr(func, "user_name"):
                    func.user_name = new_name
                if hasattr(func, "name"):
                    func.name = new_name

            self._call_on_main_thread(_apply)
        except Exception as exc:  # pragma: no cover - BN specific failures
            self._log.debug(
                "Failed to rename function %s on handle %s: %s",
                identifier,
                handle,
                exc,
                exc_info=True,
            )
            raise BinaryNinjaServiceError(f"Unable to rename function: {exc}") from exc

        return {
            "handle": handle,
            "address": _format_addr(getattr(func, "start", None)),
            "name": new_name,
        }

    def list_variables(
        self,
        handle: str,
        identifier: str,
        *,
        max_parameters: Optional[int] = None,
        max_stack: Optional[int] = None,
        max_variables: Optional[int] = None,
    ) -> Dict[str, Any]:
        view = self._get_view(handle)
        func = self._resolve_function(view, identifier)

        def _collect() -> Dict[str, Any]:
            parameters = [
                self._describe_variable(var, kind="parameter", index=index)
                for index, var in enumerate(getattr(func, "parameter_vars", []) or [])
            ]
            if max_parameters and max_parameters > 0:
                parameters[:] = parameters[:max_parameters]

            stack_vars = [
                self._describe_variable(var, kind="stack")
                for var in getattr(func, "stack_layout", []) or []
            ]
            if max_stack and max_stack > 0:
                stack_vars[:] = stack_vars[:max_stack]

            variables = [
                self._describe_variable(var, kind="variable", index=index)
                for index, var in enumerate(getattr(func, "vars", []) or [])
            ]
            if max_variables and max_variables > 0:
                variables[:] = variables[:max_variables]

            return {
                "handle": handle,
                "function": getattr(func, "name", identifier),
                "parameters": parameters,
                "stack": stack_vars,
                "variables": variables,
            }

        return self._call_on_main_thread(_collect)

    def rename_variable(
        self,
        handle: str,
        identifier: str,
        variable_id: str,
        new_name: str,
        *,
        new_type: Any = None,
    ) -> Dict[str, Any]:
        view = self._get_view(handle)
        func = self._resolve_function(view, identifier)
        variable = self._resolve_variable_identifier(func, variable_id)
        type_override = self._parse_type_spec(view, new_type)
        effective_type = self._rename_variable_common(func, variable, new_name=new_name, type_override=type_override)
        func = self._resolve_function(view, identifier)

        def _refresh() -> Any:
            return self._resolve_variable_identifier(func, variable_id)

        try:
            refreshed = _refresh()
        except BinaryNinjaServiceError as exc:
            raise BinaryNinjaServiceError(f"Rename applied but variable lookup failed: {exc}") from exc

        current_name = getattr(refreshed, "name", None)
        if current_name != new_name:
            try:
                self._update_analysis(view, None)
            except Exception:  # pragma: no cover - analysis update best effort
                pass

            func = self._resolve_function(view, identifier)
            try:
                refreshed = _refresh()
            except BinaryNinjaServiceError as exc:
                raise BinaryNinjaServiceError(f"Rename applied but variable lookup failed: {exc}") from exc
            current_name = getattr(refreshed, "name", None)

        if current_name != new_name:
            raise BinaryNinjaServiceError(
                "Binary Ninja did not report the updated variable name; ensure the function is user-modifiable."
            )

        return {
            "handle": handle,
            "function": getattr(func, "name", identifier),
            "variable": variable_id,
            "name": new_name,
            "type": self._stringify(effective_type),
        }

    def rename_stack_variable(
        self,
        handle: str,
        identifier: str,
        offset: int | str,
        new_name: str,
        *,
        new_type: Any = None,
    ) -> Dict[str, Any]:
        offset_value = self._coerce_int(offset)
        return self.rename_variable(
            handle,
            identifier,
            f"stack:{offset_value}",
            new_name,
            new_type=new_type,
        )

    def define_data_variable(
        self,
        handle: str,
        address: int | str,
        var_type: Any,
        *,
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        view = self._get_view(handle)
        addr = self._coerce_int(address)
        parsed_type = self._parse_type_spec(view, var_type)

        def _apply():
            return view.define_user_data_var(addr, parsed_type, name)

        try:
            result = self._call_on_main_thread(_apply)
        except Exception as exc:  # pragma: no cover - BN specific failures
            self._log.debug(
                "Failed to define data variable at 0x%x on handle %s: %s",
                addr,
                handle,
                exc,
                exc_info=True,
            )
            raise BinaryNinjaServiceError(f"Unable to define data variable: {exc}") from exc

        return {
            "handle": handle,
            "address": _format_addr(addr),
            "name": getattr(result, "name", name),
            "type": self._stringify(getattr(result, "type", parsed_type)),
        }

    def set_comment(self, handle: str, address: int, text: str) -> Dict[str, Any]:
        if text is None:
            raise ValueError("text may not be None")

        view = self._get_view(handle)
        try:
            func = view.get_function_containing(address)
        except Exception as exc:
            self._log.debug(
                "get_function_containing(0x%x) failed; treating as global scope: %s",
                address,
                exc,
                exc_info=True,
            )
            func = None

        try:
            def _apply() -> None:
                if func is not None and hasattr(func, "set_comment_at"):
                    func.set_comment_at(address, text)
                else:
                    view.set_comment_at(address, text)

            self._call_on_main_thread(_apply)
        except Exception as exc:  # pragma: no cover - BN specific failures
            self._log.debug(
                "Failed to set comment at 0x%x on handle %s: %s",
                address,
                handle,
                exc,
                exc_info=True,
            )
            raise BinaryNinjaServiceError(f"Failed to set comment: {exc}") from exc

        return {
            "handle": handle,
            "address": _format_addr(address),
            "comment": text,
            "scope": "function" if func is not None else "global",
        }

    def clear_comment(self, handle: str, address: int) -> Dict[str, Any]:
        view = self._get_view(handle)
        try:
            func = view.get_function_containing(address)
        except Exception as exc:
            self._log.debug(
                "get_function_containing(0x%x) failed when clearing comment: %s",
                address,
                exc,
                exc_info=True,
            )
            func = None

        try:
            def _apply() -> None:
                if func is not None and hasattr(func, "set_comment_at"):
                    func.set_comment_at(address, "")
                if hasattr(view, "clear_comment_at"):
                    view.clear_comment_at(address)

            self._call_on_main_thread(_apply)
        except Exception as exc:  # pragma: no cover
            self._log.debug(
                "Failed to clear comment at 0x%x on handle %s: %s",
                address,
                handle,
                exc,
                exc_info=True,
            )
            raise BinaryNinjaServiceError(f"Failed to clear comment: {exc}") from exc

        return {
            "handle": handle,
            "address": _format_addr(address),
            "cleared": True,
        }

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def disassemble(self, handle: str, address: int, count: int = 1) -> Dict[str, Any]:
        if count <= 0:
            raise ValueError("count must be positive")

        view = self._get_view(handle)
        lines = []
        current = address

        for _ in range(count):
            try:
                result = self._call_on_main_thread(
                    lambda: self._disassemble_instruction(view, current)
                )
            except Exception as exc:  # pragma: no cover
                self._log.debug(
                    "Disassembly failed at 0x%x on handle %s: %s",
                    current,
                    handle,
                    exc,
                    exc_info=True,
                )
                raise BinaryNinjaServiceError(
                    f"Failed to disassemble at {hex(current)}: {exc}"
                ) from exc

            if result is None:
                self._log.debug(
                    "Binary Ninja returned no disassembly at 0x%x on handle %s; treating as empty",
                    current,
                    handle,
                )
                lines.append({"address": _format_addr(current), "text": "", "length": 0})
                break

            if not isinstance(result, tuple) or len(result) != 2:
                raise BinaryNinjaServiceError(
                    "Binary Ninja returned unexpected disassembly response"
                )

            text, length = result
            lines.append({"address": _format_addr(current), "text": text, "length": length})

            if not length:
                break
            current += int(length)

        return {"handle": handle, "instructions": lines}

    def get_code_references(
        self,
        handle: str,
        address: int,
        *,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        view = self._get_view(handle)

        limit: Optional[int]
        if max_results is None:
            limit = None
        elif max_results < 0:
            limit = None
        elif max_results == 0:
            return {"handle": handle, "address": _format_addr(address), "code_refs": []}
        else:
            limit = max_results

        try:
            refs = self._call_on_main_thread(
                lambda: view.get_code_refs(address, max_items=limit)
            )
        except Exception as exc:  # pragma: no cover
            self._log.debug(
                "Failed to enumerate code references at 0x%x on handle %s: %s",
                address,
                handle,
                exc,
                exc_info=True,
            )
            raise BinaryNinjaServiceError(f"Failed to enumerate code references: {exc}") from exc

        items = []
        for ref in refs or []:
            items.append(
                {
                    "address": _format_addr(getattr(ref, "address", None)),
                    "function": getattr(getattr(ref, "function", None), "name", None),
                    "arch": getattr(getattr(ref, "arch", None), "name", None),
                }
            )

        return {"handle": handle, "address": _format_addr(address), "code_refs": items}

    def get_data_references(
        self,
        handle: str,
        address: int,
        *,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        view = self._get_view(handle)

        limit: Optional[int]
        if max_results is None:
            limit = None
        elif max_results < 0:
            limit = None
        elif max_results == 0:
            return {"handle": handle, "address": _format_addr(address), "data_refs": []}
        else:
            limit = max_results

        try:
            refs = self._call_on_main_thread(
                lambda: view.get_data_refs(address, max_items=limit)
            )
        except Exception as exc:  # pragma: no cover
            self._log.debug(
                "Failed to enumerate data references at 0x%x on handle %s: %s",
                address,
                handle,
                exc,
                exc_info=True,
            )
            raise BinaryNinjaServiceError(f"Failed to enumerate data references: {exc}") from exc

        items = []
        for ref in refs or []:
            items.append(
                {
                    "address": _format_addr(ref),
                }
            )

        return {"handle": handle, "address": _format_addr(address), "data_refs": items}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_view(self, handle: str) -> Any:
        with self._lock:
            managed = self._views.get(handle)
        if managed is None:
            raise BinaryNinjaHandleError(f"Unknown Binary Ninja handle: {handle}")
        return managed.view

    def _can_query_open_views(self) -> bool:
        return callable(getattr(binaryninja, "get_open_views", None))

    def _find_existing_view(self, path: Path) -> Any | None:
        getter = getattr(binaryninja, "get_open_views", None)
        if not callable(getter):
            return None

        try:
            existing_views = getter()
        except Exception as exc:  # pragma: no cover
            self._log.debug("binaryninja.get_open_views() failed: %s", exc, exc_info=True)
            return None

        if existing_views:
            self._log.debug(
                "Binary Ninja reported %d open view(s); searching for %s",
                len(existing_views),
                path,
            )
        for view in existing_views or []:
            candidate_path = _resolve_view_path(view)
            if candidate_path is None:
                continue

            if candidate_path == path:
                self._log.debug("Matched BinaryView %s to requested path %s", view, path)
                return view

        self._log.debug(
            "No open BinaryView matched %s (examined %d view(s))",
            path,
            len(existing_views or []),
        )
        return None

    def _auto_attach_open_views(self) -> None:
        """Attach any UI-managed views that are not yet tracked by the service."""

        getter = getattr(binaryninja, "get_open_views", None)
        if not callable(getter):
            return

        try:
            open_views = getter() or []
        except Exception as exc:  # pragma: no cover - defensive
            self._log.debug(
                "binaryninja.get_open_views() failed during auto-attach: %s",
                exc,
                exc_info=True,
            )
            return

        for view in open_views:
            path = _resolve_view_path(view)
            if path is None:
                continue
            with self._lock:
                already_tracked = any(
                    managed.view is view or managed.path == str(path)
                    for managed in self._views.values()
                )
            if already_tracked:
                continue
            try:
                self.attach_existing_view(view, path=str(path))
            except Exception as exc:  # pragma: no cover - defensive
                self._log.debug(
                    "Failed to auto-attach BinaryView %s: %s",
                    path,
                    exc,
                    exc_info=True,
                )

    def _call_on_main_thread(self, func, *args, **kwargs):
        executor = getattr(binaryninja, "execute_on_main_thread_and_wait", None)
        if callable(executor):
            result: dict[str, Any] = {}

            def wrapper():
                try:
                    result["value"] = func(*args, **kwargs)
                except Exception as exc:  # pragma: no cover
                    result["error"] = exc
                    self._log.debug(
                        "Function %s raised when executed via execute_on_main_thread_and_wait: %s",
                        getattr(func, "__name__", repr(func)),
                        exc,
                        exc_info=True,
                    )

            executor(wrapper)
            if "error" in result:
                raise result["error"]
            return result.get("value")

        executor = getattr(binaryninja, "execute_on_main_thread", None)
        if callable(executor):
            if current_thread().name.startswith("BNWorker"):
                # avoid deadlock; fall back to waiting event
                done = Event()
                result: dict[str, Any] = {}

                def wrapper():
                    try:
                        result["value"] = func(*args, **kwargs)
                    except Exception as exc:  # pragma: no cover
                        result["error"] = exc
                        self._log.debug(
                            "Function %s raised when executed on BN main thread: %s",
                            getattr(func, "__name__", repr(func)),
                            exc,
                            exc_info=True,
                        )
                    finally:
                        done.set()

                executor(wrapper)
                done.wait()
                if "error" in result:
                    raise result["error"]
                return result.get("value")
            else:
                # On a non-BN thread; still wrap to ensure completion
                done = Event()
                result: dict[str, Any] = {}

                def wrapper():
                    try:
                        result["value"] = func(*args, **kwargs)
                    except Exception as exc:  # pragma: no cover
                        result["error"] = exc
                        self._log.debug(
                            "Function %s raised when dispatched to BN main thread: %s",
                            getattr(func, "__name__", repr(func)),
                            exc,
                            exc_info=True,
                        )
                    finally:
                        done.set()

                executor(wrapper)
                done.wait()
                if "error" in result:
                    raise result["error"]
                return result.get("value")

        return func(*args, **kwargs)

    def _disassemble_instruction(self, view: Any, address: int) -> Tuple[str, int]:
        """Return the disassembly text and length for a single instruction."""

        generator = view.disassembly_text(address)
        try:
            raw = next(generator)
        except StopIteration:
            return "", 0

        if isinstance(raw, tuple):
            line, length = raw
        else:
            line = raw
            length = getattr(raw, "length", getattr(raw, "instr_length", 0))

        if line is None:
            text = ""
        elif hasattr(line, "tokens"):
            try:
                text = "".join(getattr(token, "text", "") for token in line.tokens)
            except Exception:
                text = str(line)
        else:
            text = str(line)

        try:
            length_value = int(length)
        except Exception:
            length_value = 0

        return text, length_value

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
            except Exception as exc:  # pragma: no cover
                self._log.debug("Unable to coerce analysis progress %s to float: %s", progress, exc)
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
        except Exception as exc:  # pragma: no cover - defensive
            self._log.debug("Failed to stringify %r: %s", value, exc)
            return None

    def _coerce_int(self, value: int | str) -> int:
        if isinstance(value, int):
            return value
        text = str(value).strip()
        if not text:
            raise ValueError("Numeric value may not be empty")
        try:
            return int(text, 0)
        except ValueError as exc:
            raise ValueError(f"Invalid numeric value: {value}") from exc

    def _parse_type_spec(self, view: Any, spec: Any) -> Any:
        if spec is None:
            return None

        if binaryninja is None:
            raise BinaryNinjaUnavailableError("Binary Ninja unavailable; cannot parse type specification")

        if not isinstance(spec, str):
            return spec

        parser = getattr(view, "parse_type_string", None)
        if not callable(parser):
            raise BinaryNinjaServiceError("BinaryView does not support parse_type_string")

        try:
            parsed = parser(spec)
        except Exception as exc:
            raise BinaryNinjaServiceError(f"Failed to parse type '{spec}': {exc}") from exc

        if parsed is None:
            raise BinaryNinjaServiceError(f"Type parser returned no result for '{spec}'")

        if isinstance(parsed, tuple):
            parsed_type = parsed[0]
            if parsed_type is None:
                raise BinaryNinjaServiceError(f"Type parser did not return a type for '{spec}'")
            return parsed_type

        return parsed

    def _describe_variable(
        self,
        var: Any,
        *,
        kind: str,
        index: Optional[int] = None,
    ) -> Dict[str, Any]:
        source_type = getattr(getattr(var, "source_type", None), "name", None)
        storage = getattr(var, "storage", None)
        identifier: Optional[str]
        if kind == "parameter":
            identifier = f"param:{index}"
        elif kind == "stack":
            identifier = f"stack:{storage}"
        else:
            identifier = f"var:{index}"

        return {
            "id": identifier,
            "kind": kind,
            "index": index,
            "storage": storage,
            "source_type": source_type or self._stringify(getattr(var, "source_type", None)),
            "name": getattr(var, "name", None),
            "type": self._stringify(getattr(var, "type", None)),
        }

    def _resolve_variable_identifier(self, func: Any, variable_id: str) -> Any:
        if not variable_id:
            raise ValueError("variable identifier must be provided")

        if variable_id.startswith("param:"):
            index = self._coerce_int(variable_id.split(":", 1)[1])
            params: List[Any] = list(getattr(func, "parameter_vars", []) or [])
            if index < 0 or index >= len(params):
                raise BinaryNinjaServiceError(f"Parameter index out of range: {index}")
            return params[index]

        if variable_id.startswith("var:"):
            index = self._coerce_int(variable_id.split(":", 1)[1])
            vars_list: List[Any] = list(getattr(func, "vars", []) or [])
            if index < 0 or index >= len(vars_list):
                raise BinaryNinjaServiceError(f"Variable index out of range: {index}")
            return vars_list[index]

        if variable_id.startswith("stack:"):
            offset_text = variable_id.split(":", 1)[1]
            offset = self._coerce_int(offset_text)
            stack_var: Any | None = None

            def _from_layout() -> Any:
                layout: List[Any] = list(getattr(func, "stack_layout", []) or [])
                for candidate in layout:
                    if getattr(candidate, "storage", None) == offset:
                        return candidate
                return None

            try:
                stack_var = self._call_on_main_thread(_from_layout)
            except Exception:
                pass

            if stack_var is None:
                addr = getattr(func, "start", 0)

                def _lookup() -> Any:
                    return func.get_stack_var_at_frame_offset(offset, addr)

                try:
                    stack_var = self._call_on_main_thread(_lookup)
                except Exception as exc:  # pragma: no cover - BN specific failures
                    raise BinaryNinjaServiceError(
                        f"Unable to resolve stack variable at offset {offset_text}"
                    ) from exc

            if stack_var is None:
                raise BinaryNinjaServiceError(f"No stack variable defined at offset {offset_text}")

            return stack_var

        raise ValueError(f"Unsupported variable identifier '{variable_id}'")

    def _rename_variable_common(
        self,
        func: Any,
        variable: Any,
        *,
        new_name: str,
        type_override: Any,
    ) -> Any:
        if not new_name or not new_name.strip():
            raise ValueError("new_name must be a non-empty string")

        view = getattr(func, "view", None)

        def _apply() -> Any:
            effective_type = type_override or getattr(variable, "type", None)

            type_setter = getattr(variable, "set_type_async", None)
            if type_override is not None and callable(type_setter):
                type_setter(type_override)

            name_setter = getattr(variable, "set_name_async", None)
            if not callable(name_setter):
                raise BinaryNinjaServiceError("Binary Ninja variable does not support renaming via set_name_async")

            name_setter(new_name)

            if effective_type is None and type_override is None:
                effective_type = getattr(variable, "type", None)

            return effective_type

        try:
            effective_type = self._call_on_main_thread(_apply)
        except Exception as exc:  # pragma: no cover - BN specific failures
            self._log.debug(
                "Failed to rename variable %s in %s: %s",
                getattr(variable, "name", None),
                getattr(func, "name", None),
                exc,
                exc_info=True,
            )
            raise BinaryNinjaServiceError(f"Unable to rename variable: {exc}") from exc

        return effective_type
