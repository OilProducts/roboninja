import types

import pytest

from roboninja import binaryninja_service as bns


class _FakeAnalysisState:
    def __init__(self, name):
        self.name = name


class _FakeSymbol:
    def __init__(self, _type, address, name):
        self.type = _type
        self.address = address
        self.name = name


class _FakeBinaryView:
    def __init__(self, path, module):
        self._module = module
        self.path = path
        self.arch = types.SimpleNamespace(name="x86")
        self.platform = types.SimpleNamespace(name="linux")
        self.entry_point = 0x401000
        self.analysis_info = types.SimpleNamespace(
            state=module.AnalysisState.Idle,
            progress=1.0,
        )
        self.analysis_progress = types.SimpleNamespace(
            state=module.AnalysisState.Idle,
            progress=1.0,
        )
        self.basic_block = types.SimpleNamespace(
            start=0x401000,
            end=0x401010,
            length=16,
            outgoing_edges=[types.SimpleNamespace(type="unconditional", target=None)],
        )
        self.function = types.SimpleNamespace(
            name="func_401000",
            start=0x401000,
            total_bytes=32,
            basic_blocks=[self.basic_block],
            calling_convention=types.SimpleNamespace(name="cdecl"),
            type=types.SimpleNamespace(return_value="int"),
            parameter_vars=["arg0", "arg1"],
            hlil=types.SimpleNamespace(instructions=["return 0"]),
        )
        self.functions = [self.function]
        self._strings = [
            types.SimpleNamespace(
                value="hello",
                start=0x402000,
                length=5,
                type=types.SimpleNamespace(name="AsciiString"),
            )
        ]
        self._symbols = [
            types.SimpleNamespace(
                name="_start",
                short_name="_start",
                full_name="_start",
                type=types.SimpleNamespace(name="FunctionSymbol"),
                binding=types.SimpleNamespace(name="Global"),
                address=0x401000,
            )
        ]
        self._closed = False
        self.file = types.SimpleNamespace(
            close=self._close,
            filename=str(path),
            original_filename=str(path),
        )
        self._comments = {}
        self._code_refs = [
            types.SimpleNamespace(
                address=0x401005,
                function=self.function,
                arch=types.SimpleNamespace(name="x86"),
            )
        ]
        self._data_refs = [0x404000]

    def update_analysis(self):  # pragma: no cover - timeout path uses it
        self.analysis_info.state = self._module.AnalysisState.Idle

    def update_analysis_and_wait(self):
        self.analysis_info.state = self._module.AnalysisState.Idle

    def get_functions_at(self, addr):
        return [self.function] if addr == self.function.start else []

    def get_functions_by_name(self, name):
        return [self.function] if name == self.function.name else []

    def get_strings(self):
        return self._strings

    def get_symbols(self):
        return self._symbols

    def read(self, address, length):
        return b"\x90" * length

    def define_user_symbol(self, symbol):
        self.function.name = symbol.name

    def set_comment_at(self, address, text):
        self._comments[address] = text

    def clear_comment_at(self, address):
        self._comments.pop(address, None)

    def get_comment_at(self, address):
        return self._comments.get(address)

    def disassembly_text(self, address):
        yield (f"instr_{address:x}", 4)

    def get_code_refs(self, address):
        if address == 0x401000:
            return self._code_refs
        return []

    def get_data_refs(self, address):
        if address == 0x401000:
            return self._data_refs
        return []

    def _close(self):
        self._closed = True


def _install_fake_module(monkeypatch, tmp_path, *, open_ok=True):
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 16)

    analysis_state = types.SimpleNamespace(
        Idle=_FakeAnalysisState("Idle"),
        Running=_FakeAnalysisState("Running"),
    )

    open_views: list[_FakeBinaryView] = []

    def loader(path):
        if not open_ok:
            raise RuntimeError("License is not valid. Please supply a valid license.")
        view = _FakeBinaryView(path, fake_module)
        open_views.append(view)
        return view

    def get_open_views():
        return list(open_views)

    license_state = {"count": 0, "value": None}

    def core_license_count():
        return license_state["count"]

    def core_set_license(value):
        license_state["value"] = value
        license_state["count"] = 1

    def execute_on_main_thread_and_wait(fn):
        return fn()

    fake_module = types.SimpleNamespace(
        AnalysisState=analysis_state,
        load=loader,
        core_license_count=core_license_count,
        core_set_license=core_set_license,
        Symbol=_FakeSymbol,
        SymbolType=types.SimpleNamespace(FunctionSymbol="FunctionSymbol"),
        get_open_views=get_open_views,
        _open_views=open_views,
        execute_on_main_thread_and_wait=execute_on_main_thread_and_wait,
        _license_state=license_state,
    )

    monkeypatch.setattr(bns, "binaryninja", fake_module)
    monkeypatch.setattr(bns, "_BINARYNINJA_IMPORT_ERROR", None)

    return str(binary_path)


def test_service_unavailable_when_module_missing(monkeypatch):
    monkeypatch.setattr(bns, "binaryninja", None)
    monkeypatch.setattr(bns, "_BINARYNINJA_IMPORT_ERROR", ImportError("missing"))

    with pytest.raises(bns.BinaryNinjaUnavailableError):
        bns.BinaryNinjaService()


def test_open_list_and_close(monkeypatch, tmp_path):
    binary_path = _install_fake_module(monkeypatch, tmp_path)
    service = bns.BinaryNinjaService(find_view_timeout=0)

    opened = service.open_view(binary_path, update_analysis=False, allow_create=True)
    handle = opened["handle"]

    listed = service.list_views()
    assert listed["views"][0]["handle"] == handle

    funcs = service.get_function_list(handle)
    assert funcs["functions"][0]["name"] == "func_401000"

    summary = service.get_function_summary(handle, "func_401000")
    assert summary["parameters"] == ["arg0", "arg1"]

    hlil = service.get_high_level_il(handle, "func_401000")
    assert hlil["lines"] == ["return 0"]

    blocks = service.get_basic_blocks(handle, "func_401000")
    assert blocks["blocks"][0]["start"] == "0x401000"

    strings = service.get_strings(handle, min_length=1)
    assert strings["strings"][0]["value"] == "hello"

    symbols = service.get_symbols(handle)
    assert symbols["symbols"][0]["name"] == "_start"

    read = service.read_bytes(handle, 0x401000, 4)
    assert read["bytes"] == "90909090"

    renamed = service.rename_function(handle, "func_401000", "init")
    assert renamed["name"] == "init"

    comment = service.set_comment(handle, 0x401000, "entry point")
    assert comment["comment"] == "entry point"
    assert comment["scope"] == "function"

    cleared = service.clear_comment(handle, 0x401000)
    assert cleared["cleared"] is True

    disasm = service.disassemble(handle, 0x401000, count=2)
    assert len(disasm["instructions"]) == 2

    code_refs = service.get_code_references(handle, 0x401000)
    assert code_refs["code_refs"][0]["address"] == "0x401005"

    data_refs = service.get_data_references(handle, 0x401000)
    assert data_refs["data_refs"][0]["address"] == "0x404000"

    filtered_strings = service.find_strings(handle, query="hell")
    assert filtered_strings["strings"][0]["value"] == "hello"

    closed = service.close_view(handle)
    assert closed["closed"] is True


def test_open_reuses_existing_view(monkeypatch, tmp_path):
    binary_path = _install_fake_module(monkeypatch, tmp_path)
    service = bns.BinaryNinjaService(find_view_timeout=0)

    existing = _FakeBinaryView(binary_path, bns.binaryninja)
    bns.binaryninja._open_views.append(existing)

    opened = service.open_view(binary_path, update_analysis=False)
    handle = opened["handle"]

    managed = service._views[handle]
    assert managed.view is existing
    assert managed.owns_view is False

    service.close_view(handle)
    assert not existing._closed


def test_license_error_is_reported(monkeypatch, tmp_path):
    _install_fake_module(monkeypatch, tmp_path, open_ok=False)
    service = bns.BinaryNinjaService(find_view_timeout=0)

    with pytest.raises(bns.BinaryNinjaLicenseError):
        service.open_view(str(tmp_path / "sample.bin"), allow_create=True)


def test_license_loaded_from_env(monkeypatch, tmp_path):
    binary_path = _install_fake_module(monkeypatch, tmp_path)
    monkeypatch.setenv("BN_LICENSE", "fake-license")

    service = bns.BinaryNinjaService()
    assert service is not None
    assert bns.binaryninja._license_state["value"] == "fake-license"
    assert bns.binaryninja._license_state["count"] == 1
