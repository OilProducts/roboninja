# RoboNinja MCP Server

A minimal [FastMCP](https://github.com/modelcontextprotocol/servers/tree/main/python) server showcasing a few stateful tools and a simple rate limiter. The package exposes a single `FastMCP` application instance named `mcp` that can be loaded by the official MCP CLI or other MCP-compatible runtimes.

## Features
- JSON-formatted logging configured through environment variables
- In-process, per-minute rate limiting
- Stateful key/value store utilities (`kv_set` / `kv_get`)
- Text helpers (`ping`, `echo`, `summarize_markdown`)

## Installation
Use your preferred virtual environment manager. For example:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .[dev]
```

The `mcp` package (with the `cli` extra) is required at runtime. Installing this project with `pip` pulls it in automatically.

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
roboninja --transport stdio
```

To inspect tools interactively, use the MCP inspector:

```bash
mcp inspector -m roboninja.server:mcp
```

## Configuration
Environment variables control runtime behaviour:

- `LOG_LEVEL` (`INFO` by default)
- `SERVER_NAME` (`roboninja-server` by default)
- `RATE_LIMIT_PER_MIN` (integer, default `120`)

## Development
Run the test suite with:

```bash
pytest
```

The project uses the `src` layout and exposes the application via `roboninja.server:mcp`.
