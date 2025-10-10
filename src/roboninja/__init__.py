"""RoboNinja FastMCP server package."""

from . import _patches  # noqa: F401
from .binaryninja_service import (
    BinaryNinjaFunctionError,
    BinaryNinjaHandleError,
    BinaryNinjaLicenseError,
    BinaryNinjaService,
    BinaryNinjaServiceError,
    BinaryNinjaUnavailableError,
)
from .cli import install_plugin
from .server import Settings, create_app, main, mcp, run_stdio

_patches.apply_patches()

__all__ = [
    "install_plugin",
    "BinaryNinjaFunctionError",
    "BinaryNinjaHandleError",
    "BinaryNinjaLicenseError",
    "BinaryNinjaService",
    "BinaryNinjaServiceError",
    "BinaryNinjaUnavailableError",
    "Settings",
    "create_app",
    "main",
    "mcp",
    "run_stdio",
]
