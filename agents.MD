# Agent Notes

## Binary Ninja Environment
- Binary Ninja's Python API is available when using the project virtual environment at `.venv`.
- From the project root, run `source .venv/bin/activate` (or equivalent) before starting the MCP server.
- You can confirm the API is accessible with:
  ```bash
  $ .venv/bin/python - <<'PY'
  import binaryninja
  print(f"Binary Ninja version {binaryninja.core_version()} loaded")
  PY
  ```

## MCP Bridge
- The Binary Ninja plugin launches an MCP SSE server on `127.0.0.1:18765` by default.
- The plugin auto-installs `mcp[cli]` into a local virtualenv on first load (set `ROBONINJA_DISABLE_AUTO_MCP_INSTALL=1` to skip).
- Use `roboninja proxy` (optionally `--port`) to expose that server over stdio for Codex or other clients.
