# RoboNinja MCP Helper
Author: **RoboNinja**

_Expose RoboNinja MCP summarisation commands directly inside Binary Ninja._

## Description
This plugin registers a helper command under `RoboNinja → Summarize Functions` that reuses the RoboNinja MCP Binary Ninja service to list prominent functions in the current BinaryView. Results are displayed with a simple message box so that analysts can quickly verify Binary Ninja analysis state from within the UI.

The command relies on the `roboninja` Python package (which bundles the MCP server and service helpers). If the package is unavailable, or Binary Ninja cannot expose the underlying file path, the plugin shows an error explaining what went wrong.

## Installation
1. (Recommended) Run `roboninja install-plugin` from this repository or an installed package to copy both the plugin and the RoboNinja Python package into your Binary Ninja plugins directory. For example:
   ```bash
   roboninja install-plugin
   ```
   Use `--dest` to override the target directory or `--force` to overwrite an existing installation.
2. Alternatively, install the RoboNinja package into Binary Ninja's Python environment and copy this directory manually into the plugin folder:
   - **macOS:** `~/Library/Application Support/Binary Ninja/plugins`
   - **Linux:** `~/.binaryninja/plugins`
   - **Windows:** `%APPDATA%/Binary Ninja/plugins`
3. Restart Binary Ninja (or relaunch headless) to load the new command.
4. To connect a Model Context Protocol client, run `roboninja proxy` (or `roboninja proxy --port <port>` if you changed the defaults).

## License

This plugin is released under the terms of the [MIT license](./plugin.json).
