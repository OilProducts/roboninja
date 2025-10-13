import pytest

from roboninja.server import _parse_address


def test_parse_address_accepts_int_and_hex():
    assert _parse_address(0x10) == 0x10
    assert _parse_address("0x10") == 0x10
    assert _parse_address("16") == 16


def test_parse_address_reports_bad_input():
    with pytest.raises(RuntimeError, match="Invalid address 'notanaddr'"):
        _parse_address("notanaddr")
