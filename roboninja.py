"""Backward-compatible entry point for the RoboNinja MCP server.

Prefer importing from the installed package: ``from roboninja.server import mcp``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_pkg_root = Path(__file__).resolve().parent / "src"
if _pkg_root.exists():
    __path__ = [str(_pkg_root / "roboninja")]
    if str(_pkg_root) not in sys.path:
        sys.path.insert(0, str(_pkg_root))

from roboninja.server import create_app, main, mcp, run_stdio

__all__ = ["create_app", "main", "mcp", "run_stdio"]


if __name__ == "__main__":
    main()
