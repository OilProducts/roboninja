# RoboNinja MCP Server

RoboNinja is a Model Context Protocol (MCP) server that exposes Binary Ninja® analysis features to MCP-compatible agents (including the official `mcp` CLI and Codex). The package exports a ready-to-use `FastMCP` application named `mcp` plus JSON-structured logging for downstream tooling.

## Prerequisites

- Binary Ninja installed locally with an appropriate license.
  - Headless automation requires a Commercial or Ultimate license. Non-Commercial licenses must keep the GUI open while using RoboNinja.
- Python 3.10+.
- Optional but recommended: a dedicated virtual environment.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .[dev]

# Install the Binary Ninja Python API into this virtualenv (Linux tarball layout)
python binaryninja/scripts/install_api.py
```

Verify that the API loads inside the environment:

```bash
.venv/bin/python - <<'PY'
import binaryninja
print(binaryninja.core_version())
PY
```

# Configuration

CLI flags control the RoboNinja launcher:

- `--bn-path PATH` – explicitly point at the Binary Ninja executable (otherwise common install locations and `PATH` are used).
- `--host HOST` – host where the GUI/plugin MCP SSE server listens (default `127.0.0.1`).
- `--port PORT` – port for that SSE server (default `18765`).
- `--timeout SECONDS` – seconds to wait for the SSE bridge before giving up (default `45`).

You can also set `BINARYNINJA_PATH` to point at the Binary Ninja executable; the CLI will honor it if provided.

### Plugin behaviour

- Hosts an MCP SSE server on `127.0.0.1:18765` by default so external agents can connect.
- Automatically installs `mcp[cli]` into a private virtualenv the first time it loads if the package is missing.

### Licensing options

RoboNinja attempts to load a license via, in order:

1. `BN_LICENSE`, `BINARYNINJA_LICENSE`, `ROBONINJA_LICENSE`
2. `BN_LICENSE_PATH`, `BINARYNINJA_LICENSE_PATH`, `ROBONINJA_LICENSE_PATH`
3. `~/.binaryninja/license.dat`

Set whichever matches your deployment.

## Usage

### Quick start (GUI-assisted)

```bash
# Launch Binary Ninja on a target file, wire up the SSE bridge, and auto-open the view.
roboninja /path/to/target/binary
```

- The CLI attempts to locate Binary Ninja automatically (common install paths and the `PATH`). Use `--bn-path` to override.
- After the GUI opens, the CLI waits for the plugin-hosted MCP SSE server (default `127.0.0.1:18765`) and issues a `bn_open` so agents immediately receive a handle.
- To pass additional arguments to Binary Ninja, append `--` and the desired flags (`roboninja target.bin -- --headless`).

### Bridging the GUI SSE server to stdio

```bash
roboninja proxy --host 127.0.0.1 --port 18765 --timeout 60
```

Increase `--timeout` if an environment takes longer than 30 seconds to expose the SSE endpoint.

### Headless / stdio server

```bash
# Via python -m
python -m roboninja --transport stdio

# Via console script (identical behaviour)
roboninja serve --transport stdio
```

### MCP CLI integration

```bash
pip install "mcp[cli]"
mcp run -m roboninja.server:mcp        # stdio transport
mcp sse -m roboninja.server:mcp --host 0.0.0.0 --port 8000  # SSE transport
mcp inspector -m roboninja.server:mcp  # inspect available tools
```

### Codex CLI integration

**Headless-capable (Commercial/Ultimate license)**  

```toml
[mcp_servers.roboninja]
command = "roboninja"
args = ["serve", "--transport", "stdio"]
# To override the Binary Ninja location:
# args = ["serve", "--transport", "stdio", "--bn-path", "/path/to/binaryninja"]
```

**GUI-only (Non-Commercial license)**  

1. Launch Binary Ninja with `roboninja /path/to/target/binary`.
2. Configure Codex to run the proxy:

```toml
[mcp_servers.roboninja]
command = "roboninja"
args = ["proxy"]
```

Restart `codex tui` or `codex exec` and connect to RoboNinja from the tool picker.

## Binary Ninja Plugin

### Install with the CLI

```bash
roboninja install-plugin              # copies plugin + package into ~/.binaryninja/plugins
roboninja install-plugin --dest /custom/path --force
```

### Manual installation

Copy `src/roboninja_plugin/` into Binary Ninja’s plugin directory (e.g., `~/.binaryninja/plugins`). The CLI command above automates this process and vendors the application code under `roboninja_plugin/vendor/`.

### Available commands

The plugin registers:

- `RoboNinja\Initialize` – attach RoboNinja to the active BinaryView.
- `RoboNinja\Initialize (Refresh)` – re-attach if state drifts.

Once attached, the plugin automatically:

- Starts an MCP SSE server on `127.0.0.1:18765`.
- Auto-installs `mcp[cli]` into a private virtualenv if the package is missing.
- Tracks the active BinaryView so CLI sessions can reuse it.

A minimal sample plugin lives in `binja_sample_plugin/` for reference.

## Available MCP tools

| Tool | Purpose | Notes |
| --- | --- | --- |
| `bn_open` | Open or attach to a BinaryView | Returns handle plus architecture, platform, entry point, and analysis progress. Set `allow_create=True` to load without the GUI. |
| `bn_list` | Enumerate active views | Includes views opened directly in the GUI. |
| `bn_close` | Close a view by handle | Respects ownership (does not close GUI-managed views). |
| `bn_functions` | List functions (filter by name/size) | Includes calling convention and return type. |
| `bn_function_summary` | Detailed function metadata | Parameters, size, blocks, etc. |
| `bn_hlil` | High Level IL listing | Optional `max_instructions`. |
| `bn_basic_blocks` | Basic block graph summary | Includes outgoing edge metadata. |
| `bn_strings` / `bn_find_strings` | Extract or search strings | `bn_find_strings` enforces positive `min_length`. |
| `bn_symbols` | Enumerate symbols (optional type filter) | Returns binding and address data. |
| `bn_disassemble` | Linear disassembly around an address | Positive `count` required. |
| `bn_code_refs` / `bn_data_refs` | Cross-references to an address | Optional `max_results`, gracefully handles `0`. |
| `bn_rename_function` | Apply a user symbol | Requires Binary Ninja symbol API. |
| `bn_set_comment` / `bn_clear_comment` | Manage comments at addresses | Works with function or global scopes. |
| `bn_read` | Read bytes from the view | Returns hex-encoded payload. |

## Server behaviour

- **Logging** – Non-interactive runs emit JSON lines (timestamp, level, message, logger name). Interactive CLI sessions fall back to plain text. Tool requests/results log extra metadata (payload sizes, durations) at DEBUG.

## Troubleshooting

- **License errors** – Set `BN_LICENSE`, `BN_LICENSE_PATH`, or Binary Ninja’s built-in license location before launching. Headless mode requires a Commercial/Ultimate license.
- **`bn_open` reports “GUI has not opened this file yet”** – Either open the binary in the GUI first or call `bn_open` with `allow_create=True`.
- **Proxy timeouts** – Increase `roboninja launch --timeout …` or `roboninja proxy --timeout …` for slower environments.
- **No SSE server from the plugin** – Check the Binary Ninja console for startup or `mcp[cli]` installation errors; the plugin starts the server automatically at launch.

## Development

- Run the test suite with:

  ```bash
  pytest
  ```

- The project uses the `src` layout and exposes the MCP application at `roboninja.server:mcp`.

## Future work

- `bn_view_info`: expose BinaryView metadata (architecture, platform, entry point, pointer size, segments/sections).
- `bn_patch_bytes`: write arbitrary byte sequences via transactions.
- `bn_tags`: create and manage tag types.
- `bn_highlight`: highlight instructions/blocks through `Function.set_auto_instr_highlight`.
- `bn_stack_vars`: surface and edit stack variables.
- `bn_calls`: enumerate call sites and callees.
- `bn_data_vars`: inspect data variables and associated types.
- `bn_flowgraph`: return control-flow graph structures for visualization.
- `bn_write_transaction`: provide transaction helpers for grouped writes.
- `bn_cfg_paths`: enumerate control-flow paths within a function.
- `bn_il_slice`: compute MLIL/LLIL slices.
- `bn_stack_canary`: report stack-protection metadata.
- `bn_type_library`: manage type libraries.
- `bn_platforms`: enumerate related platforms.
- `bn_debug_info`: surface debug information records.
- `bn_import_lifted_mlil`: parse or create synthetic MLIL snippets.
- `bn_section_entropy`: compute entropy over sections.
- `bn_symbol_xrefs`: combine symbol lookup with code/data references.
- `bn_bulk_rename`: support regex-style renaming for symbols/variables.
