import logging
import threading
from types import SimpleNamespace

import pytest

from roboninja.binaryninja_service import BinaryNinjaService, BinaryNinjaServiceError, _ManagedView


def _make_service(view):
    service = object.__new__(BinaryNinjaService)
    service._log = logging.getLogger("roboninja.tests")
    service._views = {
        "handle": _ManagedView(
            handle="handle",
            path="dummy",
            opened_at=0.0,
            view=view,
            owns_view=False,
        )
    }
    service._lock = threading.RLock()
    service._find_view_timeout = 0.0
    return service


def test_disassemble_gracefully_handles_none_result():
    view = SimpleNamespace()
    service = _make_service(view)

    def fake_disassemble_instruction(_view, _addr):
        return None

    service._disassemble_instruction = fake_disassemble_instruction  # type: ignore[attr-defined]
    service._call_on_main_thread = lambda fn, *a, **k: fn()  # type: ignore[assignment]

    result = service.disassemble("handle", 0x402CE0, count=1)
    assert result["instructions"] == [
        {"address": "0x402ce0", "text": "", "length": 0}
    ]


@pytest.mark.parametrize(
    "method, field",
    [
        ("get_code_references", "code_refs"),
        ("get_data_references", "data_refs"),
    ],
)
def test_reference_queries_treat_none_as_empty(method, field):
    def get_refs(address, max_items=None):
        return None

    view = SimpleNamespace(
        get_code_refs=get_refs,
        get_data_refs=get_refs,
    )

    service = _make_service(view)
    service._call_on_main_thread = lambda fn, *a, **k: fn()  # type: ignore[assignment]

    query = getattr(service, method)
    result = query("handle", 0x400000)
    assert result[field] == []


def test_get_strings_handles_none_iterator():
    view = SimpleNamespace(get_strings=lambda: None)
    service = _make_service(view)
    service._call_on_main_thread = lambda fn, *a, **k: fn()  # type: ignore[assignment]

    result = service.get_strings("handle")
    assert result["strings"] == []


def test_get_strings_reports_enumeration_failure():
    def failing_strings():
        raise RuntimeError("boom")

    view = SimpleNamespace(get_strings=failing_strings)
    service = _make_service(view)
    service._call_on_main_thread = lambda fn, *a, **k: fn()  # type: ignore[assignment]

    with pytest.raises(BinaryNinjaServiceError, match="Failed to enumerate strings: boom"):
        service.get_strings("handle")


def test_get_symbols_handles_none_iterator():
    view = SimpleNamespace(get_symbols=lambda: None)
    service = _make_service(view)
    result = service.get_symbols("handle")
    assert result["symbols"] == []


def test_get_symbols_reports_enumeration_failure():
    def failing_symbols():
        raise RuntimeError("kaput")

    view = SimpleNamespace(get_symbols=failing_symbols)
    service = _make_service(view)

    with pytest.raises(BinaryNinjaServiceError, match="Failed to enumerate symbols: kaput"):
        service.get_symbols("handle")


class _DummyType:
    def __init__(self, text: str):
        self.text = text

    def __str__(self) -> str:
        return self.text


def _make_function():
    class _Variable(SimpleNamespace):
        def set_name_async(self, new_name):
            _record(
                "set_name_async",
                var=self,
                name=new_name,
            )
            self.name = new_name
            self.last_seen_name = new_name

        def set_type_async(self, new_type):  # type: ignore[override]
            _record(
                "set_type_async",
                var=self,
                type=new_type,
            )
            self.type = new_type

    param = _Variable(
        name="arg0",
        type=_DummyType("int"),
        storage=0,
        source_type=SimpleNamespace(name="RegisterVariableSourceType"),
        last_seen_name="arg0",
    )
    stack = _Variable(
        name="var_8",
        type=_DummyType("char*"),
        storage=-8,
        source_type=SimpleNamespace(name="StackVariableSourceType"),
        last_seen_name="var_8",
    )
    local = _Variable(
        name="tmp1",
        type=_DummyType("int32_t"),
        storage=4,
        source_type=SimpleNamespace(name="RegisterVariableSourceType"),
        last_seen_name="tmp1",
    )

    calls: list[dict[str, object]] = []

    def _record(action: str, **payload: object) -> None:
        if action == "set_name_async":
            var = payload.get("var")
            if var is not None:
                var.name = payload.get("name")
                var.last_seen_name = payload.get("name")
        elif action == "set_type_async":
            var = payload.get("var")
            if var is not None and payload.get("type") is not None:
                var.type = payload["type"]
        entry: dict[str, object] = {"action": action, **payload}
        calls.append(entry)

    def get_stack_var_at_frame_offset(_offset, _addr):
        raise AssertionError("stack layout lookup should be used")

    func = SimpleNamespace(
        name="target",
        start=0x4057e0,
        parameter_vars=[param],
        stack_layout=[stack],
        vars=[local],
        get_stack_var_at_frame_offset=get_stack_var_at_frame_offset,
    )
    return func, calls, param, stack, local


def test_list_variables_reports_kinds(monkeypatch):
    func, _, param, stack, local = _make_function()

    view = SimpleNamespace(
        get_functions_at=lambda addr: [],
        get_functions_by_name=lambda name: [func] if name == "target" else [],
        update_analysis_and_wait=lambda: None,
    )

    service = _make_service(view)
    service._call_on_main_thread = lambda fn, *a, **k: fn()  # type: ignore[assignment]

    result = service.list_variables("handle", "target")

    assert result["parameters"][0]["id"] == "param:0"
    assert result["parameters"][0]["name"] == param.name
    assert result["stack"][0]["id"] == f"stack:{stack.storage}"
    assert result["variables"][0]["id"] == "var:0"
    assert result["variables"][0]["name"] == local.name


def test_rename_variable_updates_user_name(monkeypatch):
    func, calls, _, stack, local = _make_function()

    dummy_type = _DummyType("uint32_t")

    view = SimpleNamespace(
        parse_type_string=lambda text: (dummy_type, text),
        get_functions_at=lambda addr: [],
        get_functions_by_name=lambda name: [func] if name == "target" else [],
        update_analysis_and_wait=lambda: None,
    )

    from roboninja import binaryninja_service as bn_service

    monkeypatch.setattr(bn_service, "binaryninja", SimpleNamespace())

    service = _make_service(view)
    service._call_on_main_thread = lambda fn, *a, **k: fn()  # type: ignore[assignment]

    result = service.rename_variable("handle", "target", "var:0", "renamed", new_type="uint32_t")

    assert calls, "set_name_async should be invoked"
    assert calls[-1]["action"] == "set_name_async"
    assert calls[-1]["var"] is local
    assert calls[-1]["name"] == "renamed"
    type_actions = [entry for entry in calls if entry["action"] == "set_type_async"]
    assert type_actions and type_actions[-1]["type"] is dummy_type
    assert result["name"] == "renamed"
    assert result["type"] == "uint32_t"


def test_rename_stack_variable_resolves_offset(monkeypatch):
    func, calls, _, stack, _ = _make_function()

    view = SimpleNamespace(
        get_functions_at=lambda addr: [],
        get_functions_by_name=lambda name: [func] if name == "target" else [],
        update_analysis_and_wait=lambda: None,
    )

    from roboninja import binaryninja_service as bn_service

    monkeypatch.setattr(bn_service, "binaryninja", SimpleNamespace())

    service = _make_service(view)
    service._call_on_main_thread = lambda fn, *a, **k: fn()  # type: ignore[assignment]

    result = service.rename_stack_variable("handle", "target", stack.storage, "stack_var")

    assert calls, "set_name_async should be invoked for stack variables"
    assert calls[-1]["action"] == "set_name_async"
    assert calls[-1]["var"] is stack
    assert calls[-1]["name"] == "stack_var"
    assert result["variable"] == f"stack:{stack.storage}"


def test_define_data_variable_calls_binary_view(monkeypatch):
    func, _, _, _, _ = _make_function()
    dummy_type = _DummyType("int")

    recorded: dict[str, object] = {}

    def define_user_data_var(addr, var_type, name):
        recorded["addr"] = addr
        recorded["var_type"] = var_type
        recorded["name"] = name
        return SimpleNamespace(name=name or "var_123", type=var_type)

    view = SimpleNamespace(
        parse_type_string=lambda text: (dummy_type, text),
        define_user_data_var=define_user_data_var,
        get_functions_at=lambda addr: [func] if addr == func.start else [],
        get_functions_by_name=lambda name: [func] if name == func.name else [],
    )

    from roboninja import binaryninja_service as bn_service

    monkeypatch.setattr(bn_service, "binaryninja", SimpleNamespace())

    service = _make_service(view)
    service._call_on_main_thread = lambda fn, *a, **k: fn()  # type: ignore[assignment]

    result = service.define_data_variable("handle", "0x1000", "int", name="global_counter")

    assert recorded == {"addr": 0x1000, "var_type": dummy_type, "name": "global_counter"}
    assert result["address"] == "0x1000"
    assert result["name"] == "global_counter"
    assert result["type"] == "int"
