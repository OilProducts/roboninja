# RoboNinja MCP Server

A Model Context Protocol server that exposes Binary Ninja analysis capabilities alongside a few utility endpoints. The package exposes a `FastMCP` application instance named `mcp` that can be loaded by the official MCP CLI or other MCP-compatible runtimes.

## Features
- JSON-formatted logging configured through environment variables
- In-process, per-minute rate limiting
- Binary Ninja-backed tools (open/close views, enumerate functions, inspect IL, strings, symbols, and bytes)
- Legacy utility helpers (`ping`, `echo`, lightweight key/value store)

## Installation
Use your preferred virtual environment manager. For example:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .[dev]
```

Binary Ninja must be installed and licensed locally. Ensure the `binaryninja` Python package resolves inside your environment (the default Binary Ninja installation ships with one). A quick verification:

```bash
.venv/bin/python - <<'PY'
import binaryninja
print(binaryninja.core_version())
PY
```

## Running
You can run the server through the MCP CLI (recommended) or directly via Python:

```bash
# Official CLI
pip install "mcp[cli]"
mcp run -m roboninja.server:mcp

# SSE server
mcp sse -m roboninja.server:mcp --host 0.0.0.0 --port 8000

# Stdio transport only
python -m roboninja --transport stdio

# Console script equivalent
roboninja serve --transport stdio
```

To inspect tools interactively, use the MCP inspector:

```bash
mcp inspector -m roboninja.server:mcp
```

## Binary Ninja Tooling
The following MCP tools are available when Binary Ninja is present:
- `bn_open` / `bn_close` / `bn_list` – manage Binary Ninja views
- `bn_functions` / `bn_function_summary` – enumerate functions and inspect metadata
- `bn_hlil` / `bn_basic_blocks` – explore high-level IL and basic block structure
- `bn_strings` / `bn_symbols` – extract text strings and symbol information
- `bn_read` – read raw bytes at an address

Each tool returns JSON-friendly payloads that can be consumed by downstream agents.

## Configuration
Environment variables control runtime behaviour:

- `LOG_LEVEL` (`INFO` by default)
- `SERVER_NAME` (`roboninja-server` by default)
- `RATE_LIMIT_PER_MIN` (integer, default `120`)


## Binary Ninja Plugin
An optional Binary Ninja plugin is available in `roboninja_plugin/`. Install the `roboninja` Python package in Binary Ninja's environment and copy the directory into the Binary Ninja plugin folder to expose the `RoboNinja → Summarize Functions` command. The plugin reuses the RoboNinja service to display the top functions detected in the current BinaryView.

Use `roboninja install-plugin` to copy the bundled Binary Ninja plugin and package into your plugins directory automatically (defaults to `~/.binaryninja/plugins`). Restart Binary Ninja afterwards to pick up the command.

Once the Binary Ninja plugin is installed and Binary Ninja is running, the plugin automatically hosts an MCP SSE server on `127.0.0.1:18765` (configurable via environment). Use `roboninja proxy` to bridge that server to stdio for Codex or other stdio-only clients. The plugin will automatically install `mcp[cli]` into a private virtual environment on first launch (set `ROBONINJA_DISABLE_AUTO_MCP_INSTALL=1` to opt out).

Set `ROBONINJA_SOURCE=/path/to/roboninja/src` before launching Binary Ninja if you want to test the plugin directly from a checkout without installing the package.
## Development
Run the test suite with:

```bash
pytest
```

The project uses the `src` layout and exposes the application via `roboninja.server:mcp`.
