"""Binary Ninja UI helper for the RoboNinja MCP server."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import venv
from pathlib import Path
from typing import Optional

from binaryninja import (  # type: ignore
    BinaryView,
    MessageBoxButtonSet,
    MessageBoxIcon,
    PluginCommand,
    show_message_box,
)

try:  # pragma: no cover - best effort import for open-view enumeration
    import binaryninja
except Exception:  # pragma: no cover
    binaryninja = None  # type: ignore

try:  # pragma: no cover - UI modules unavailable in headless mode
    from binaryninjaui import UIContext, UIContextNotification
except Exception:  # pragma: no cover - headless/non-UI environment
    UIContext = None  # type: ignore[assignment]
    UIContextNotification = object  # type: ignore[assignment]


log = logging.getLogger(__name__)

BinaryView.set_default_session_data("roboninja_initialized", False)

_ACTIVE_VIEW: Optional[BinaryView] = None


_MCP_THREAD = None
_MCP_READY = False
_MCP_SETUP_ATTEMPTED = False


def _venv_python(venv_path: Path) -> Path:
    if os.name == "nt":
        return venv_path / "Scripts" / "python.exe"
    return venv_path / "bin" / "python"


def _venv_site_packages(venv_path: Path) -> Path:
    if os.name == "nt":
        return venv_path / "Lib" / "site-packages"
    return venv_path / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"


def _ensure_mcp_available() -> bool:
    global _MCP_READY, _MCP_SETUP_ATTEMPTED
    if _MCP_READY:
        return True

    try:
        import mcp.server.fastmcp  # type: ignore
        _MCP_READY = True
        return True
    except Exception as exc:
        log.debug("Initial import of mcp.server.fastmcp failed: %s", exc)

    if _MCP_SETUP_ATTEMPTED:
        return False
    _MCP_SETUP_ATTEMPTED = True

    if os.getenv("ROBONINJA_DISABLE_AUTO_MCP_INSTALL"):
        log.warning("MCP package missing and auto-install disabled")
        return False

    venv_path = Path(__file__).resolve().parent / ".roboninja_venv"
    try:
        if not venv_path.exists():
            venv.EnvBuilder(with_pip=True).create(str(venv_path))

        python_exe = _venv_python(venv_path)
        if not python_exe.exists():
            raise RuntimeError(f"Unable to locate venv python at {python_exe}")

        subprocess.run(
            [str(python_exe), "-m", "pip", "install", "--upgrade", "pip"],
            check=False,
        )
        subprocess.run(
            [str(python_exe), "-m", "pip", "install", "mcp[cli]"],
            check=True,
        )

        site_dir = _venv_site_packages(venv_path)
        if site_dir.exists() and str(site_dir) not in sys.path:
            sys.path.insert(0, str(site_dir))

        import mcp.server.fastmcp  # type: ignore  # noqa: F401
        _MCP_READY = True
        return True
    except Exception as exc:
        log.warning("Failed to auto-install mcp package: %s", exc)
        return False


def _ensure_roboninja_on_path() -> None:
    candidates: list[Path] = []
    env = os.getenv("ROBONINJA_SOURCE")
    if env:
        candidates.append(Path(env))

    here = Path(__file__).resolve().parent
    candidates.append(here / "roboninja")
    candidates.append(here.parent / "roboninja")
    candidates.append(here.parent / "src")

    for candidate in candidates:
        try:
            candidate = candidate.expanduser().resolve()
        except Exception as exc:
            log.debug("Failed to resolve candidate RoboNinja path %s: %s", candidate, exc)
            continue
        if candidate.exists() and str(candidate) not in sys.path:
            log.debug("Adding %s to sys.path for RoboNinja", candidate)
            sys.path.insert(0, str(candidate))


def _start_mcp_server() -> None:
    global _MCP_THREAD
    if os.getenv("ROBONINJA_DISABLE_MCP_SERVER"):
        log.info("ROBONINJA_DISABLE_MCP_SERVER is set; skipping MCP server startup")
        return
    if _MCP_THREAD is not None and _MCP_THREAD.is_alive():
        log.debug("MCP server thread already running; skipping startup")
        return

    _ensure_roboninja_on_path()

    if not _ensure_mcp_available():
        log.warning("Skipping MCP server startup; mcp package unavailable")
        return

    try:
        from roboninja.server import create_app
    except Exception as exc:  # pragma: no cover
        log.warning("RoboNinja MCP server unavailable: %s", exc)
        return

    host = os.getenv("ROBONINJA_MCP_HOST", "127.0.0.1")
    port = int(os.getenv("ROBONINJA_MCP_PORT", "18765"))
    log.info(
        "Starting RoboNinja MCP server thread targeting %s:%s (transport=sse)",
        host,
        port,
    )

    def _worker() -> None:
        try:
            app = create_app()
            app.settings.host = host
            app.settings.port = port
            app.run(transport="sse")
        except Exception as exc:  # pragma: no cover
            log.error("RoboNinja MCP server failed: %s", exc)

    _MCP_THREAD = threading.Thread(
        target=_worker, name="RoboNinjaMCP", daemon=True
    )
    _MCP_THREAD.start()
    log.info("RoboNinja MCP server thread %s started", _MCP_THREAD.name)


_ensure_roboninja_on_path()
_start_mcp_server()

try:  # pragma: no cover - executed inside Binary Ninja
    from roboninja.binaryninja_service import (
        BinaryNinjaService,
        BinaryNinjaServiceError,
        get_service_singleton,
    )
except Exception as exc:  # pragma: no cover
    BinaryNinjaService = None  # type: ignore[assignment]
    _SERVICE_IMPORT_ERROR = exc
    log.debug("Failed to import BinaryNinjaService inside plugin: %s", exc)
else:  # pragma: no cover
    _SERVICE_IMPORT_ERROR = None


_SERVICE: Optional[BinaryNinjaService] = None


def _get_service() -> BinaryNinjaService:
    if BinaryNinjaService is None:
        raise RuntimeError(
            "The 'roboninja' package (with Binary Ninja support) is not available: "
            f"{_SERVICE_IMPORT_ERROR}"
        )

    global _SERVICE
    if _SERVICE is None:
        _SERVICE = get_service_singleton()
    return _SERVICE


def _close_view_quietly(service: BinaryNinjaService, handle: Optional[str]) -> None:
    if handle is None:
        return
    try:
        service.close_view(handle)
    except Exception as exc:
        log.debug("Error closing Binary Ninja view %s during cleanup: %s", handle, exc)


def _view_path_text(bv: BinaryView) -> Optional[str]:
    file_obj = getattr(bv, "file", None)
    if file_obj is not None:
        candidate = getattr(file_obj, "original_filename", None) or getattr(file_obj, "filename", None)
        if candidate:
            return candidate
    if hasattr(bv, "file_name"):
        candidate = getattr(bv, "file_name")
        if candidate:
            return str(candidate)
    return None


def _register_active_view(bv: BinaryView, *, source: str) -> None:
    global _ACTIVE_VIEW
    if bv is None:
        return

    path = _view_path_text(bv) or f"<anonymous:{id(bv):x}>"

    already = getattr(bv.session_data, "roboninja_initialized", False)
    _ACTIVE_VIEW = bv
    setattr(bv.session_data, "roboninja_initialized", True)
    log.info("RoboNinja initialized for %s via %s", path, source)

    attached = False
    if BinaryNinjaService is not None and path:
        try:
            service = _get_service()
        except Exception as exc:  # pragma: no cover
            log.warning("Skipping service attach for %s: %s", path, exc)
        else:
            attach = getattr(service, 'attach_existing_view', None)
            if callable(attach):
                try:
                    handle = attach(bv, path=path)
                    log.info("RoboNinja service registered %s with handle %s", path, handle)
                    attached = True
                except Exception as exc:  # pragma: no cover
                    log.warning("Failed to register active view with RoboNinja service: %s", exc)
            if not attached:
                try:
                    summary = service.open_view(path, update_analysis=False, allow_create=False)
                    handle = summary.get('handle') if isinstance(summary, dict) else None
                    log.info("RoboNinja service open_view registered %s with handle %s", path, handle)
                    attached = True
                except Exception as exc:  # pragma: no cover
                    log.warning("Unable to attach BinaryView %s to RoboNinja service: %s", path, exc)

    return path if attached else path


def _initialize_view_if_needed(bv: BinaryView, *, source: str) -> None:
    if bv is None:
        return
    if getattr(bv.session_data, "roboninja_initialized", False):
        return
    _register_active_view(bv, source=source)


def _initialize_existing_views() -> None:
    if binaryninja is None:
        return
    getter = getattr(binaryninja, "get_open_views", None)
    if not callable(getter):
        return
    try:
        views = getter() or []
    except Exception as exc:  # pragma: no cover
        log.debug("Unable to enumerate existing Binary Ninja views: %s", exc)
        return
    for view in views:
        if view is not None:
            _initialize_view_if_needed(view, source="existing-view")


def _schedule_initialize_existing_views() -> None:
    if binaryninja is None:
        _initialize_existing_views()
        return
    runner = getattr(binaryninja, "execute_on_main_thread_and_wait", None)
    if callable(runner):
        runner(_initialize_existing_views)
    else:
        _initialize_existing_views()


def roboninja_initialize(bv) -> None:  # pragma: no cover - UI entry point
    """Attach RoboNinja to the provided BinaryView."""

    if bv is None:
        show_message_box(
            "RoboNinja",
            "No BinaryView provided to RoboNinja.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    _register_active_view(bv, source="manual-command")
    path = _view_path_text(bv)
    if path is not None:
        show_message_box(
            "RoboNinja",
            f"RoboNinja is attached to:\n{path}",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon,
        )


def roboninja_initialize_refresh(bv) -> None:  # pragma: no cover - UI entry point
    """Re-attach RoboNinja to the active BinaryView."""

    if bv is None:
        show_message_box(
            "RoboNinja",
            "No BinaryView provided to RoboNinja.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    setattr(bv.session_data, "roboninja_initialized", False)
    _register_active_view(bv, source="manual-refresh")
    path = _view_path_text(bv)
    if path is not None:
        show_message_box(
            "RoboNinja",
            f"RoboNinja re-attached to:\n{path}",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon,
        )


def get_active_binary_view() -> Optional[BinaryView]:
    """Return the BinaryView currently tracked by RoboNinja (if any)."""

    return _ACTIVE_VIEW


class _AutoInitializeNotification(UIContextNotification):
    """Automatically attach RoboNinja when a view first loads or becomes active."""

    def _resolve_view(self, context, file_context=None):
        bv = None
        if file_context is not None:
            bv = getattr(file_context, "binaryView", None)
        if bv is not None:
            return bv
        if context is None:
            return None
        try:
            frame = context.getCurrentViewFrame()
            if frame is not None:
                return frame.getCurrentBinaryView()
        except Exception as exc:  # pragma: no cover - defensive
            log.debug("Unable to resolve BinaryView from UIContext: %s", exc)
        return None

    def OnAfterOpenFile(self, context, file_context) -> None:  # noqa: N802 (Binary Ninja API naming)
        bv = self._resolve_view(context, file_context)
        if bv is None:
            return
        _initialize_view_if_needed(bv, source="after-open")

    def OnViewCreated(self, context, frame):  # noqa: N802
        if frame is None:
            return
        bv = frame.getCurrentBinaryView()
        if bv is None:
            return
        _initialize_view_if_needed(bv, source="view-created")

    def OnViewChanged(self, context, frame):  # noqa: N802
        if frame is None:
            return
        bv = frame.getCurrentBinaryView()
        if bv is None:
            return
        _initialize_view_if_needed(bv, source="view-changed")


PluginCommand.register(
    r"RoboNinja\Initialize",
    "Attach RoboNinja to the current BinaryView",
    roboninja_initialize,
)

PluginCommand.register(
    r"RoboNinja\Initialize (Refresh)",
    "Re-attach RoboNinja to the current BinaryView",
    roboninja_initialize_refresh,
)

if UIContext is not None:  # pragma: no cover
    UIContext.registerNotification(_AutoInitializeNotification())
    _schedule_initialize_existing_views()
else:
    _schedule_initialize_existing_views()
