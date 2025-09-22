# Binary Ninja Integration Plan

This document expands the design for wiring Binary Ninja into the RoboNinja MCP server before coding begins.

## 1. Service Abstraction

Create a dedicated service module (e.g. `roboninja.binaryninja_service`) that wraps the Binary Ninja Python API. Its responsibilities:

- **Environment bootstrap**: verify `binaryninja` import, optionally accept `BINARY_NINJA_PATH` or configuration for headless mode, surface clear errors if licensing is missing.
- **View lifecycle management**: expose methods to open, cache, and close `BinaryView` objects. Generate opaque handles/IDs so the MCP surface never leaks raw Binary Ninja objects.
- **Analysis readiness**: after opening a view, ensure background analysis completes (`update_analysis_and_wait()`), or expose an async poller to report progress on large binaries.
- **Thread safety**: Binary Ninja requires operations on the main thread unless using the background API. The service should serialize access (thread lock or task queue) to avoid crashes when MCP handles concurrent requests.
- **Resource cleanup**: provide `close_view(handle)` and a context manager so tests do not leak file handles. Optionally add an LRU eviction policy to bound memory usage.
- **Structured responses**: convert Binary Ninja objects into simple dataclasses/dicts with stable fields (`FunctionInfo`, `BasicBlockInfo`, etc.) that can be JSON-serialized.

Proposed public API sketch:

```python
class BinaryNinjaService:
    def open_view(self, path: str, options: OpenOptions | None = None) -> ViewHandle: ...
    def list_views(self) -> list[ViewSummary]: ...
    def close_view(self, handle: ViewHandle) -> bool: ...
    def get_function_list(self, handle: ViewHandle, filter: FunctionFilter | None = None) -> list[FunctionInfo]: ...
    def get_il(self, handle: ViewHandle, function_name: str | None, address: int | None, level: ILLevel) -> ILResult: ...
    def get_basic_block(self, handle: ViewHandle, function_name: str, block_index: int) -> BasicBlockInfo: ...
    def list_strings(self, handle: ViewHandle, min_length: int = 4) -> list[StringInfo]: ...
    def list_symbols(self, handle: ViewHandle, kind: SymbolKind | None = None) -> list[SymbolInfo]: ...
    def patch_bytes(self, handle: ViewHandle, address: int, data: bytes) -> PatchResult: ...
    def add_comment(self, handle: ViewHandle, address: int, text: str) -> bool: ...
    def save_view(self, handle: ViewHandle, destination: str | None = None) -> SaveResult: ...
```

`ViewHandle` can be a UUID-backed dataclass storing the BinaryView reference plus metadata. All methods should raise service-specific exceptions mapped to user-friendly MCP errors.

## 2. Initial MCP Tool Surface

Wrap the service methods in FastMCP tools with clear JSON schemas:

1. **`bn_open`** (`path`, optional `analysis_timeout`) → returns `handle`, architecture, entry point, file type.
2. **`bn_list_views`** → enumerates currently opened handles with metadata (path, size, leftover analysis tasks).
3. **`bn_close`** (`handle`) → closes a view.
4. **`bn_functions`** (`handle`, optional `name_contains`, `min_size`) → list of functions with start address, size, symbol name, basic block count.
5. **`bn_function_summary`** (`handle`, `function`) → returns high-level details including calling convention, parameters, stack frame size.
6. **`bn_hlil`** (`handle`, `function`, optional `start`, `end`) → slices High Level IL as structured text or JSON tree.
7. **`bn_basic_blocks`** (`handle`, `function`) → outlines blocks with addresses and outgoing edges.
8. **`bn_strings`** (`handle`, optional `min_length`, `encoding`) → text strings discovered in the view.
9. **`bn_symbols`** (`handle`, optional `kind`) → exported/imported symbols.
10. **`bn_read`** (`handle`, `address`, `length`) → raw bytes in hex plus disassembly for convenience.
11. **`bn_patch`** (`handle`, `address`, `bytes_hex`) → apply a patch, returning success and prompting to save.
12. **`bn_comment`** (`handle`, `address`, `text`) → set repeatable comment.
13. **`bn_save`** (`handle`, optional `destination`) → save BNDB or patched binary.

Additional stretch tools once basics work:
- `bn_find_references` (cross-references to address/function)
- `bn_callgraph` (return nodes + edges for visualization)
- `bn_decompile_snippet` (decompile region to C-like text)
- `bn_run_plugin` (invoke Binary Ninja plugins by name, with caution)

## 3. Error Handling & Messaging

- Distinguish between user errors (bad path, invalid handle) and internal failures (Binary Ninja exceptions). Return structured error payloads with actionable messages.
- When analysis is still in progress, either block with configurable timeout or return a status indicating the caller should poll again.
- Surface license issues explicitly so the agent can prompt the user to activate Binary Ninja.

## 4. Testing Strategy

- Unit tests can mock the service layer to ensure MCP tools handle success/failure paths.
- Integration tests (optional) require Binary Ninja headless mode; guard them behind an environment flag to avoid CI failures when Binary Ninja is unavailable.
- Provide fixtures that spin up the service with a tiny sample binary (e.g. `/bin/true`) to validate analysis outputs.

## 5. Next Steps Before Coding

1. Decide on configuration inputs (env vars, CLI flags) for locating Binary Ninja and enabling headless mode.
2. Finalize the minimal tool list for the first milestone (recommend items 1–8 above).
3. Draft data models (`ViewSummary`, `FunctionInfo`, etc.) and error classes in `binaryninja_service.py`.
4. Plan concurrency—likely a single worker thread processing requests to the Binary Ninja API to maintain safety.
5. Once the design is accepted, implement the service layer, then wrap tools in `server.py`.
