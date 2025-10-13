"""Command-line entry points for RoboNinja."""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

import anyio
import mcp.types as mcp_types
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client
from mcp.shared.message import SessionMessage


log = logging.getLogger(__name__)


def _default_plugin_destination() -> Path:
    return Path.home() / ".binaryninja" / "plugins"


def _resolve_plugin_source() -> Path:
    module_path = Path(__file__).resolve()
    candidates: list[Path] = []

    try:
        import roboninja_plugin  # type: ignore
    except Exception:
        pass
    else:
        candidates.append(Path(roboninja_plugin.__file__).resolve().parent)  # type: ignore[attr-defined]

    candidates.extend(
        [
            module_path.parent.parent / "roboninja_plugin",  # src/ checkout layout
            module_path.parent.parent.parent / "roboninja_plugin",  # legacy layout
        ]
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "Unable to locate the roboninja_plugin package. Checked: "
        + ", ".join(str(candidate) for candidate in candidates)
    )


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
    vendor_root = plugin_dest / "vendor"
    package_dest = vendor_root / "roboninja"
    legacy_package_dest = destination / "roboninja"

    if legacy_package_dest.exists() and not force:
        raise FileExistsError(
            f"Legacy RoboNinja package directory exists: {legacy_package_dest}. "
            "Remove it or re-run with '--force'."
        )

    _copy_tree(plugin_source, plugin_dest, force=force)
    vendor_root.mkdir(parents=True, exist_ok=True)
    _copy_tree(package_source, package_dest, force=force)

    if legacy_package_dest.exists():
        shutil.rmtree(legacy_package_dest)

    return plugin_dest


def _default_binaryninja_locations() -> list[Path]:
    candidates: list[Path] = []

    env_path = os.getenv("BINARYNINJA_PATH")
    if env_path:
        candidates.append(Path(env_path))

    if sys.platform == "darwin":
        candidates.extend(
            [
                Path("/Applications/Binary Ninja.app/Contents/MacOS/binaryninja"),
                Path.home() / "Applications" / "Binary Ninja.app" / "Contents" / "MacOS" / "binaryninja",
            ]
        )
    elif sys.platform.startswith("win"):
        candidates.extend(
            [
                Path("C:/Program Files/Binary Ninja/binaryninja.exe"),
                Path("C:/Program Files/Vector35/BinaryNinja/binaryninja.exe"),
            ]
        )
    else:
        candidates.extend(
            [
                Path("/usr/bin/binaryninja"),
                Path("/usr/local/bin/binaryninja"),
                Path("/opt/binaryninja/binaryninja"),
            ]
        )

    which = shutil.which("binaryninja")
    if which:
        candidates.append(Path(which))

    return candidates


def _locate_binaryninja(explicit: Optional[str] = None) -> Path:
    candidates: list[Path] = []

    if explicit:
        candidates.append(Path(explicit))

    candidates.extend(_default_binaryninja_locations())

    seen: set[Path] = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser()
        except Exception as exc:
            log.debug("Failed to expand Binary Ninja candidate path %s: %s", candidate, exc)
            continue

        if resolved in seen:
            continue
        seen.add(resolved)

        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved

    raise RuntimeError(
        "Unable to locate Binary Ninja executable. Specify it with '--bn-path'."
    )


def _wait_for_mcp_server(host: str, port: int, timeout: float, process: Optional[subprocess.Popen] = None) -> None:
    deadline = time.monotonic() + max(timeout, 0.0)
    last_error: Optional[Exception] = None

    while time.monotonic() <= deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("Binary Ninja exited before the MCP server became ready.")

        try:
            with socket.create_connection((host, port), timeout=1.5):
                return
        except OSError as exc:  # Connection refused or still starting
            last_error = exc
            time.sleep(0.5)

    raise TimeoutError(
        f"Timed out waiting for RoboNinja MCP server on {host}:{port}"
    ) from last_error


def _launch_session(
    binary: Path,
    *,
    bn_path: Optional[str] = None,
    host: str,
    port: int,
    timeout: float,
    extra_args: list[str],
) -> None:
    executable = _locate_binaryninja(bn_path)
    env = os.environ.copy()

    command = [str(executable), str(binary)] + extra_args

    try:
        process = subprocess.Popen(command, env=env)
    except FileNotFoundError as exc:
        raise RuntimeError(f"Failed to launch Binary Ninja: {exc}") from exc
    except OSError as exc:
        raise RuntimeError(f"Unable to start Binary Ninja: {exc}") from exc

    print(f"Launched Binary Ninja ({executable}) with {binary}")

    try:
        _wait_for_mcp_server(host, port, timeout, process)
    except TimeoutError as exc:
        raise TimeoutError(
            f"Timed out waiting for RoboNinja MCP server on {host}:{port}. "
            f"Binary Ninja is still running (PID {process.pid}). "
            "Verify the plugin started correctly or adjust --timeout if the SSE server is slow to come up."
        ) from exc
    except RuntimeError as exc:
        raise RuntimeError(str(exc)) from exc

    print(f"RoboNinja MCP server ready at http://{host}:{port}")
    try:
        handle = _auto_open_view(host, port, binary, timeout)
    except Exception as exc:
        log.warning("Auto-open of Binary Ninja view failed: %s", exc)
        print(f"Warning: Failed to auto-open Binary Ninja view: {exc}", file=sys.stderr)
    else:
        if handle:
            print(f"Auto-opened Binary Ninja view handle: {handle}")
    print(
        "Binary Ninja is hosting the SSE endpoint. Use 'roboninja proxy' to bridge to stdio "
        "or connect an SSE-capable MCP client directly."
    )


async def _stdin_reader() -> str | None:
    return await anyio.to_thread.run_sync(sys.stdin.readline)


async def _stdout_writer(text: str) -> None:
    await anyio.to_thread.run_sync(sys.stdout.write, text)
    await anyio.to_thread.run_sync(sys.stdout.flush)


async def _stderr_writer(text: str) -> None:
    await anyio.to_thread.run_sync(sys.stderr.write, text)
    await anyio.to_thread.run_sync(sys.stderr.flush)


async def _proxy_stdio_to_sse(url: str, timeout: float) -> None:
    async with sse_client(url, timeout=timeout) as streams:
        read_stream, write_stream = streams

        async def pump_server_messages(stream: MemoryObjectReceiveStream[SessionMessage | Exception]) -> None:
            async with stream:
                async for item in stream:
                    if isinstance(item, Exception):
                        await _stderr_writer(f"Proxy error from SSE stream: {item}\n")
                        continue
                    payload = item.message.model_dump_json(by_alias=True, exclude_none=True)
                    await _stdout_writer(payload + "\n")

        async def pump_stdin(stream: MemoryObjectSendStream[SessionMessage]) -> None:
            async with stream:
                while True:
                    line = await _stdin_reader()
                    if line == "":
                        break
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        message = mcp_types.JSONRPCMessage.model_validate_json(stripped)
                    except Exception as exc:  # pragma: no cover - defensive
                        log.debug("Invalid MCP message on stdin: %s", exc)
                        await _stderr_writer(f"Invalid MCP message on stdin: {exc}\n")
                        continue
                    await stream.send(SessionMessage(message))

        async with anyio.create_task_group() as tg:
            tg.start_soon(pump_server_messages, read_stream)
            tg.start_soon(pump_stdin, write_stream)


def _run_proxy_bridge(host: str, port: int, timeout: float) -> None:
    url = f"http://{host}:{port}/sse"
    try:
        anyio.run(_proxy_stdio_to_sse, url, timeout)
    except KeyboardInterrupt:
        print("Proxy interrupted.", file=sys.stderr)
    except Exception as exc:
        log.exception("Failed to connect to RoboNinja SSE server at %s", url)
        raise RuntimeError(f"Failed to connect to RoboNinja SSE server at {url}: {exc}") from exc


def _auto_open_view(host: str, port: int, path: Path, timeout: float) -> Optional[str]:
    """Placeholder for legacy auto-open behavior (deprecated)."""
    log.debug(
        "Auto-open skipped: bn_open tool not available (host=%s, port=%d, path=%s)",
        host,
        port,
        path,
    )
    return None


def _build_parser() -> tuple[argparse.ArgumentParser, argparse.ArgumentParser]:
    parser = argparse.ArgumentParser(
        prog="roboninja",
        description="RoboNinja Binary Ninja MCP helpers and CLI utilities",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command")

    launch_parser = subparsers.add_parser(
        "launch",
        help="Launch Binary Ninja on a target binary and ensure the MCP bridge is ready",
        description="Launch Binary Ninja on a target binary and ensure the MCP bridge is ready.",
    )
    launch_parser.add_argument(
        "binary",
        nargs="?",
        help="Path to the binary to open in Binary Ninja (omit to run the stdio server)",
    )
    launch_parser.add_argument(
        "--bn-path",
        dest="bn_path",
        default=None,
        help="Path to the Binary Ninja executable (defaults to auto-detect)",
    )
    launch_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host where the RoboNinja MCP server listens",
    )
    launch_parser.add_argument(
        "--port",
        type=int,
        default=18765,
        help="Port for the RoboNinja MCP server",
    )
    launch_parser.add_argument(
        "--timeout",
        type=float,
        default=45.0,
        help="Seconds to wait for the MCP server before giving up",
    )
    launch_parser.add_argument(
        "binary_args",
        nargs=argparse.REMAINDER,
        help="Additional arguments passed directly to Binary Ninja",
    )
    launch_parser.set_defaults(func=_handle_launch)

    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the RoboNinja MCP server (stdio transport)",
        description="Run the RoboNinja MCP server using the stdio transport.",
    )
    serve_parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio"],
        help="Transport to use",
    )

    install_parser = subparsers.add_parser(
        "install-plugin",
        help="Install the Binary Ninja plugin and package into the plugins directory",
        description="Install the Binary Ninja plugin and package into the plugins directory.",
    )
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

    proxy_parser = subparsers.add_parser(
        "proxy",
        help="Bridge the Binary Ninja-hosted MCP SSE server to stdio",
        description="Bridge the Binary Ninja-hosted MCP SSE server to stdio.",
    )
    proxy_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host where the plugin MCP server listens",
    )
    proxy_parser.add_argument(
        "--port",
        type=int,
        default=18765,
        help="Port for the plugin MCP server",
    )
    proxy_parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Seconds to wait when connecting to the SSE endpoint",
    )
    proxy_parser.set_defaults(func=_handle_proxy)

    serve_parser.set_defaults(func=_handle_serve)
    install_parser.set_defaults(func=_handle_install_plugin)

    return parser, launch_parser


def _handle_launch(args: argparse.Namespace) -> None:
    if not args.binary:
        from . import server as server_module

        server_module.main(None)
        return

    binary_path = Path(args.binary).expanduser().resolve()
    if not binary_path.exists():
        print(f"Error: Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    extra_args = list(args.binary_args)
    if extra_args and extra_args[0] == "--":
        extra_args = extra_args[1:]

    try:
        _launch_session(
            binary_path,
            bn_path=args.bn_path,
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            extra_args=extra_args,
        )
    except (TimeoutError, RuntimeError) as exc:
        if str(exc):
            print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)


def _handle_proxy(args: argparse.Namespace) -> None:
    try:
        _run_proxy_bridge(args.host, args.port, timeout=args.timeout)
    except Exception as exc:
        log.exception("Proxy bridge failed")
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def _handle_install_plugin(args: argparse.Namespace) -> None:
    try:
        plugin_path = install_plugin(destination=args.dest, force=args.force)
    except FileExistsError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        log.exception("Failed to install RoboNinja plugin")
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    print(f"Installed RoboNinja plugin to {plugin_path}")


def _handle_serve(args: argparse.Namespace) -> None:
    from . import server as server_module

    server_args = []
    if hasattr(args, "transport") and args.transport:
        server_args.extend(["--transport", args.transport])
    server_module.main(server_args)


def run(argv: Optional[list[str]] = None) -> None:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    parser, launch_parser = _build_parser()
    command_names = {"launch", "serve", "proxy", "install-plugin"}

    if not argv_list:
        args = launch_parser.parse_args([])
        args.func(args)
        return

    if argv_list[0] in ("-h", "--help"):
        parser.parse_args(argv_list)  # argparse prints help and exits
        return

    if argv_list[0] in command_names:
        args = parser.parse_args(argv_list)
        args.func(args)
        return

    args = launch_parser.parse_args(argv_list)
    args.func(args)


__all__ = ["run", "install_plugin"]
