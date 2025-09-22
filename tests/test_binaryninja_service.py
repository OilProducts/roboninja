import types

import pytest

from roboninja import binaryninja_service as bns


class _FakeAnalysisState:
    def __init__(self, name):
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
        self.file = types.SimpleNamespace(close=self._close)

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

    def _close(self):
        self._closed = True


def _install_fake_module(monkeypatch, tmp_path, *, open_ok=True):
    binary_path = tmp_path / "sample.bin"
    binary_path.write_bytes(b"\x00" * 16)

    analysis_state = types.SimpleNamespace(
        Idle=_FakeAnalysisState("Idle"),
        Running=_FakeAnalysisState("Running"),
    )

    def loader(path):
        if not open_ok:
            raise RuntimeError("License is not valid. Please supply a valid license.")
        return _FakeBinaryView(path, fake_module)

    license_state = {"count": 0, "value": None}

    def core_license_count():
        return license_state["count"]

    def core_set_license(value):
        license_state["value"] = value
        license_state["count"] = 1

    fake_module = types.SimpleNamespace(
        AnalysisState=analysis_state,
        load=loader,
        core_license_count=core_license_count,
        core_set_license=core_set_license,
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
    service = bns.BinaryNinjaService()

    opened = service.open_view(binary_path, update_analysis=False)
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

    closed = service.close_view(handle)
    assert closed["closed"] is True


def test_license_error_is_reported(monkeypatch, tmp_path):
    _install_fake_module(monkeypatch, tmp_path, open_ok=False)
    service = bns.BinaryNinjaService()

    with pytest.raises(bns.BinaryNinjaLicenseError):
        service.open_view(str(tmp_path / "sample.bin"))


def test_license_loaded_from_env(monkeypatch, tmp_path):
    binary_path = _install_fake_module(monkeypatch, tmp_path)
    monkeypatch.setenv("BN_LICENSE", "fake-license")

    service = bns.BinaryNinjaService()
    assert service is not None
    assert bns.binaryninja._license_state["value"] == "fake-license"
    assert bns.binaryninja._license_state["count"] == 1

