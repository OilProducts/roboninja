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
    MessageBoxButtonSet,
    MessageBoxIcon,
    PluginCommand,
    show_message_box,
)


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
    except Exception:
        pass

    if _MCP_SETUP_ATTEMPTED:
        return False
    _MCP_SETUP_ATTEMPTED = True

    if os.getenv("ROBONINJA_DISABLE_AUTO_MCP_INSTALL"):
        logging.getLogger(__name__).warning(
            "MCP package missing and auto-install disabled"
        )
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
        logging.getLogger(__name__).warning(
            "Failed to auto-install mcp package: %s", exc
        )
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
        except Exception:
            continue
        if candidate.exists() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))


def _start_mcp_server() -> None:
    global _MCP_THREAD
    if os.getenv("ROBONINJA_DISABLE_MCP_SERVER"):
        return
    if _MCP_THREAD is not None and _MCP_THREAD.is_alive():
        return

    _ensure_roboninja_on_path()

    if not _ensure_mcp_available():
        logging.getLogger(__name__).warning(
            "Skipping MCP server startup; mcp package unavailable"
        )
        return

    try:
        from roboninja.server import create_app
    except Exception as exc:  # pragma: no cover
        logging.getLogger(__name__).warning(
            "RoboNinja MCP server unavailable: %s", exc
        )
        return

    host = os.getenv("ROBONINJA_MCP_HOST", "127.0.0.1")
    port = int(os.getenv("ROBONINJA_MCP_PORT", "18765"))

    def _worker() -> None:
        try:
            app = create_app()
            app.settings.host = host
            app.settings.port = port
            app.run(transport="sse")
        except Exception as exc:  # pragma: no cover
            logging.getLogger(__name__).error(
                "RoboNinja MCP server failed: %s", exc
            )

    _MCP_THREAD = threading.Thread(
        target=_worker, name="RoboNinjaMCP", daemon=True
    )
    _MCP_THREAD.start()


_ensure_roboninja_on_path()
_start_mcp_server()

try:  # pragma: no cover - executed inside Binary Ninja
    from roboninja.binaryninja_service import BinaryNinjaService, BinaryNinjaServiceError
except Exception as exc:  # pragma: no cover
    BinaryNinjaService = None  # type: ignore[assignment]
    _SERVICE_IMPORT_ERROR = exc
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
        _SERVICE = BinaryNinjaService()
    return _SERVICE


def _close_view_quietly(service: BinaryNinjaService, handle: Optional[str]) -> None:
    if handle is None:
        return
    try:
        service.close_view(handle)
    except Exception:
        pass


def _format_functions(functions: list[dict]) -> str:
    if not functions:
        return "No functions discovered by RoboNinja."

    top = functions[: min(10, len(functions))]
    lines = [
        f"{fn.get('name', '<unnamed>')} @ {fn.get('start') or '??'} ({fn.get('size', 0)} bytes)"
        for fn in top
    ]
    message = "Top functions detected\n\n" + "\n".join(lines)

    remaining = len(functions) - len(top)
    if remaining > 0:
        message += f"\n\n+ {remaining} more"
    return message


def roboninja_summarize_functions(bv) -> None:  # pragma: no cover - UI entry point
    """Display a quick summary of functions using the RoboNinja service."""

    if bv is None:
        show_message_box(
            "RoboNinja",
            "No BinaryView provided to RoboNinja command.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    try:
        service = _get_service()
    except Exception as exc:
        show_message_box(
            "RoboNinja",
            f"Binary Ninja integration unavailable: \n{exc}",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    file_obj = getattr(bv, "file", None)
    path = None
    if file_obj is not None:
        path = getattr(file_obj, "original_filename", None) or getattr(
            file_obj, "filename", None
        )

    if not path:
        show_message_box(
            "RoboNinja",
            "Could not determine a filesystem path for the current BinaryView.",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        return

    handle: Optional[str] = None
    try:
        opened = service.open_view(path, update_analysis=False)
        handle = opened.get("handle")
        functions = service.get_function_list(handle)["functions"]
        message = _format_functions(functions)
    except BinaryNinjaServiceError as exc:
        message = f"Failed to analyze {path}: \n{exc}"
        show_message_box(
            "RoboNinja",
            message,
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        _close_view_quietly(service, handle)
        return
    except Exception as exc:
        show_message_box(
            "RoboNinja",
            f"Unexpected error: {exc}",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon,
        )
        _close_view_quietly(service, handle)
        return

    show_message_box(
        "RoboNinja Function Summary",
        message,
        MessageBoxButtonSet.OKButtonSet,
        MessageBoxIcon.InformationIcon,
    )
    _close_view_quietly(service, handle)


PluginCommand.register(
    r"RoboNinja\Summarize Functions",
    "Run RoboNinja MCP summarization against the current view",
    roboninja_summarize_functions,
)
