"""RoboNinja FastMCP server package."""

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
