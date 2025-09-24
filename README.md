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

# Install the Binary Ninja Python API into this virtualenv (Linux tarball layout)
python binaryninja/scripts/install_api.py
```

Note: The `install_api.py` helper lives inside the Binary Ninja installation. For the Linux tarball it can be found at `binaryninja/scripts/install_api.py`; adjust the path if you installed Binary Ninja elsewhere or on a different platform.

> **Licensing reminder:** Headless automation (anything that runs `binaryninja` without the UI) requires a Commercial or Ultimate Binary Ninja license. Non-Commercial licenses allow scripting only while the GUI is active, so keep the desktop application open when using RoboNinja.

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
# Quick launch Binary Ninja with the RoboNinja plugin and MCP proxy
# (use the path to the target program you want to analyze, not the Binary Ninja executable)
roboninja /path/to/target/binary

# Optional: point at a custom Binary Ninja executable
roboninja --bn-path "/opt/binaryninja/binaryninja" /path/to/target/binary

# Bridge the GUI-hosted SSE server to stdio for tools that need it (e.g. Codex)
roboninja proxy --host 127.0.0.1 --port 18765

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

The CLI auto-detects Binary Ninja from common install paths or by honoring the `BINARYNINJA_PATH` environment variable if you installed it elsewhere. It also primes the MCP server by issuing an initial `bn_open` for the target on launch, so downstream agents immediately receive a handle.
If your license does not include headless support, launch the GUI via `roboninja /path/to/target/binary` (or start Binary Ninja manually) before relying on RoboNinja tooling, and keep `roboninja proxy` running to bridge SSE to stdio.

To inspect tools interactively, use the MCP inspector:

```bash
mcp inspector -m roboninja.server:mcp
```

### Codex CLI Integration

The Codex CLI can consume RoboNinja via the Model Context Protocol. Choose the configuration that matches your Binary Ninja license:

**Headless-capable (Commercial/Ultimate)** – Codex talks directly to the stdio transport:

```toml
[mcp_servers.roboninja]
command = "roboninja"
args = ["serve", "--transport", "stdio"]
# Optional: if your Binary Ninja isn't on the PATH
# env = { "BINARYNINJA_PATH" = "/home/you/tools/binaryninja/binaryninja" }
```

**GUI-only (Non-Commercial)** – Launch Binary Ninja with `roboninja /path/to/target/binary`, then let Codex spawn the stdio↔SSE bridge:

```toml
[mcp_servers.roboninja]
command = "roboninja"
args = ["proxy"]
```

Make sure Binary Ninja is installed (and the API added to your virtualenv as shown above), then restart `codex tui` (or `codex exec`). RoboNinja will appear in Codex's MCP tool picker; connect to it and the agent will have access to the Binary Ninja-backed tools (`bn_open`, `bn_functions`, etc.). For GUI-only licenses, keep Binary Ninja running (e.g. launched via `roboninja /path/to/target/binary`) so the plugin continues to host the SSE server that the proxy attaches to.

## Binary Ninja Tooling
The following MCP tools are available when Binary Ninja is present:
- `bn_open` / `bn_close` / `bn_list` – manage Binary Ninja views
- `bn_functions` / `bn_function_summary` – enumerate functions and inspect metadata
- `bn_hlil` / `bn_basic_blocks` – explore high-level IL and basic block structure
- `bn_strings` / `bn_find_strings` / `bn_symbols` – extract or search text strings and symbol information
- `bn_disassemble` / `bn_code_refs` / `bn_data_refs` – inspect disassembly and cross references around an address
- `bn_rename_function` / `bn_set_comment` / `bn_clear_comment` – apply analyst-driven annotations inside Binary Ninja
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

## Future Work

- `bn_view_info`: expose path, architecture, platform, entry point, pointer size, and segment/section layout of the active BinaryView so agents can quickly orient themselves before deeper analysis.
- `bn_patch_bytes`: allow precise patching by writing arbitrary byte sequences via `BinaryView.write`, optionally within transactions for safety.
- `bn_tags`: provide commands to create tag types and add/remove tags at addresses, letting agents annotate findings in a way the GUI highlights.
- `bn_highlight`: enable instruction/block highlighting through `Function.set_auto_instr_highlight` to mark hot spots or review items directly in the disassembly.
- `bn_stack_vars`: surface and edit stack variables (`Function.stack_layout`, `create_user_stack_var`) to refine calling convention analysis or document arguments.
- `bn_calls`: return call sites and callees for selected functions using `Function.call_sites` and `Function.callees` so downstream tools can build call graphs quickly.
- `bn_data_vars`: enumerate data variables with types and addresses via `BinaryView.data_vars` / `get_data_var_at`, helping agents inspect tables, configuration blobs, or structures.
- `bn_symbols`: list/add/remove symbols (`BinaryView.get_symbols_by_name`, `define_user_symbol`) to keep naming synchronized between the GUI and automation.
- `bn_flowgraph`: generate control-flow graph structures (`Function.create_graph`) to hand off rich graph data to visualizers or further analysis stages.
- `bn_write_transaction`: wrap multiple writes in `begin_write_transaction` / `commit_write_transaction` helpers so scripted patches remain atomic and easy to roll back.

- `bn_cfg_paths`: enumerate control-flow paths within a function by traversing the flow graph produced by `Function.create_graph`.
- `bn_il_slice`: provide program slices from MLIL/LLIL via `MediumLevelILFunction.get_slice` or low-level equivalents to explain data/control dependencies.
- `bn_stack_canary`: report stack-protection metadata using `Function.has_canary()` and related calling convention helpers.
- `bn_type_library`: list or import type libraries (`BinaryView.type_libraries`, `TypeLibrary.load_from_file`) so agents can attach rich type info.
- `bn_platforms`: expose available or related platforms using `BinaryView.available_platforms` and `BinaryView.get_related_functions` for multi-platform binaries.
- `bn_debug_info`: surface debug-information records (`BinaryView.debug_info`) to answer source-line or variable provenance questions.
- `bn_import_lifted_mlil`: allow agents to parse or create synthetic MLIL via `BinaryView.parse_expression` for quick pattern modeling.
- `bn_section_entropy`: compute entropy over sections (using `BinaryView.sections` + `BinaryView.read`) to flag compressed or encrypted regions.
- `bn_symbol_xrefs`: combine symbol lookups with code/data references (`BinaryView.get_symbol_at`, `get_code_refs`, `get_data_refs`) for cross-reference reports.
- `bn_bulk_rename`: support regex-style renaming of symbols and variables using `BinaryView.get_symbols*` and `define_user_symbol`.
