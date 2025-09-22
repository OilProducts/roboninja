"""Command-line entry points for RoboNinja."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from . import server


def _default_plugin_destination() -> Path:
    return Path.home() / ".binaryninja" / "plugins"


def _resolve_plugin_source() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "roboninja_plugin"


def _resolve_package_source() -> Path:
    return Path(__file__).resolve().parent


def _copy_tree(src: Path, dst: Path, force: bool = False) -> None:
    if dst.exists():
        if not force:
            raise FileExistsError(f"Destination already exists: {dst}")
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))


def install_plugin(
    destination: Optional[Path] = None,
    *,
    plugin_source: Optional[Path] = None,
    package_source: Optional[Path] = None,
    force: bool = False,
) -> Path:
    """Copy the RoboNinja Binary Ninja plugin and package into *destination*."""

    destination = destination or _default_plugin_destination()
    plugin_source = plugin_source or _resolve_plugin_source()
    package_source = package_source or _resolve_package_source()

    if not plugin_source.exists():
        raise FileNotFoundError(f"Plugin source not found: {plugin_source}")
    if not (plugin_source / "__init__.py").exists():
        raise FileNotFoundError("roboninja_plugin/__init__.py not found")

    if not package_source.exists():
        raise FileNotFoundError(f"Package source not found: {package_source}")

    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)

    plugin_dest = destination / "roboninja_plugin"
    package_dest = destination / "roboninja"

    _copy_tree(plugin_source, plugin_dest, force=force)
    _copy_tree(package_source, package_dest, force=force)

    return plugin_dest


def _run_proxy_cli(host: str, port: int, mcp_bin: Optional[str] = None) -> None:
    candidates: list[Path] = []
    if mcp_bin:
        candidates.append(Path(mcp_bin))
    else:
        candidates.append(Path(sys.executable).with_name("mcp"))
        candidates.append(Path(sys.exec_prefix) / "bin" / "mcp")
        candidates.append(Path(sys.prefix) / "bin" / "mcp")

    for candidate in candidates:
        if candidate and candidate.exists():
            mcp_executable = str(candidate)
            break
    else:
        which = shutil.which("mcp")
        if not which:
            raise RuntimeError("Unable to locate 'mcp' CLI. Install 'mcp[cli]' in this environment.")
        mcp_executable = which

    url = f"http://{host}:{port}"
    try:
        subprocess.run([mcp_executable, "proxy", "--url", url], check=True)
    except subprocess.CalledProcessError as exc:  # pragma: no cover
        raise RuntimeError(f"Failed to run mcp proxy: {exc}") from exc


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="roboninja")
    subparsers = parser.add_subparsers(dest="command")

    serve_parser = subparsers.add_parser("serve", help="Run the RoboNinja MCP server")
    serve_parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio"],
        help="Transport to use",
    )

    install_parser = subparsers.add_parser("install-plugin", help="Install the Binary Ninja plugin")
    install_parser.add_argument(
        "--dest",
        type=Path,
        default=None,
        help="Binary Ninja plugins directory (defaults to ~/.binaryninja/plugins)",
    )
    install_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite any existing RoboNinja plugin/package",
    )

    proxy_parser = subparsers.add_parser("proxy", help="Connect to the Binary Ninja-hosted MCP server")
    proxy_parser.add_argument(
        "--host", default="127.0.0.1", help="Host where the plugin MCP server listens",
    )
    proxy_parser.add_argument(
        "--port", type=int, default=18765, help="Port for the plugin MCP server",
    )
    proxy_parser.add_argument(
        "--mcp-bin", default=None, help="Override path to the 'mcp' CLI",
    )

    return parser


def run(argv: Optional[list[str]] = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "install-plugin":
        try:
            plugin_path = install_plugin(destination=args.dest, force=args.force)
        except FileExistsError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        print(f"Installed RoboNinja plugin to {plugin_path}")
        return

    if args.command == "proxy":
        try:
            _run_proxy_cli(args.host, args.port, args.mcp_bin)
        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if args.command == 'serve':
        server_args = []
        if hasattr(args, 'transport') and args.transport:
            server_args.extend(['--transport', args.transport])
        server.main(server_args)
        return

    if args.command is None:
        server.main(None)
        return

    parser.print_help()


__all__ = ["run", "install_plugin"]
