"""Command-line entry points for RoboNinja."""

from __future__ import annotations

import argparse
import json
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

from . import server


log = logging.getLogger(__name__)


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


def _default_binaryninja_locations() -> list[Path]:
    candidates: list[Path] = []

    env_hints = [
        os.getenv("BINARYNINJA_PATH"),
    ]
    for hint in env_hints:
        if hint:
            candidates.append(Path(hint))

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
        "Unable to locate Binary Ninja executable. Specify it with '--bn-path' "
        "or set BINARYNINJA_PATH."
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
    env.setdefault("ROBONINJA_SOURCE", str(_resolve_package_source()))

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


async def _call_bn_open(url: str, path: Path, timeout: float) -> Optional[str]:
    async with sse_client(url, timeout=timeout) as streams:
        read_stream, write_stream = streams

        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "bn_open",
                {"path": str(path)},
            )

            data: Any = result.structuredContent
            if data is None and result.content:
                for block in result.content:
                    if getattr(block, "type", None) != "text":
                        continue
                    try:
                        candidate = json.loads(getattr(block, "text", ""))
                    except Exception as exc:
                        log.debug("Failed to parse text block as JSON: %s", exc)
                        continue
                    if isinstance(candidate, dict):
                        data = candidate
                        break

            if isinstance(data, dict):
                view = data.get("view")
                if isinstance(view, dict):
                    handle = view.get("handle")
                    if isinstance(handle, str) and handle:
                        return handle
            return None


def _auto_open_view(host: str, port: int, path: Path, timeout: float) -> Optional[str]:
    url = f"http://{host}:{port}/sse"
    return anyio.run(_call_bn_open, url, path, timeout)


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
        "--timeout", type=float, default=30.0, help="Seconds to wait when connecting to the SSE endpoint",
    )

    return parser


def _launch_from_cli(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="roboninja")
    parser.add_argument("binary", help="Path to the binary to open in Binary Ninja")
    parser.add_argument(
        "--bn-path",
        dest="bn_path",
        default=None,
        help="Path to the Binary Ninja executable (defaults to auto-detect)",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("ROBONINJA_MCP_HOST", "127.0.0.1"),
        help="Host where the RoboNinja MCP server listens",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("ROBONINJA_MCP_PORT", "18765")),
        help="Port for the RoboNinja MCP server",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("ROBONINJA_MCP_WAIT_TIMEOUT", "45")),
        help="Seconds to wait for the MCP server before giving up",
    )
    parser.add_argument(
        "binary_args",
        nargs=argparse.REMAINDER,
        help="Additional arguments passed directly to Binary Ninja",
    )

    args = parser.parse_args(argv)

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


def run(argv: Optional[list[str]] = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)

    known_commands = {"install-plugin", "proxy", "serve"}
    if argv:
        first = argv[0]
        if first not in known_commands:
            _launch_from_cli(argv)
            return

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "install-plugin":
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
        return

    if args.command == "proxy":
        try:
            _run_proxy_bridge(args.host, args.port, timeout=args.timeout)
        except Exception as exc:
            log.exception("Proxy bridge failed")
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
