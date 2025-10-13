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
