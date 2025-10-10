import argparse
import os
import subprocess
from pathlib import Path

import pytest

from roboninja import cli


def test_install_plugin_copies_plugin_and_package(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    plugin_source = project_root / "roboninja_plugin"
    package_source = project_root / "src" / "roboninja"

    destination = tmp_path / "plugins"
    path = cli.install_plugin(
        destination=destination,
        plugin_source=plugin_source,
        package_source=package_source,
        force=True,
    )

    assert path == destination / "roboninja_plugin"
    assert (destination / "roboninja_plugin" / "__init__.py").exists()
    assert (destination / "roboninja" / "binaryninja_service.py").exists()

    with pytest.raises(FileExistsError):
        cli.install_plugin(
            destination=destination,
            plugin_source=plugin_source,
            package_source=package_source,
        )


def test_proxy_subcommand_uses_bridge(monkeypatch):
    recorded = {}

    def fake_bridge(host, port, timeout):
        recorded['host'] = host
        recorded['port'] = port
        recorded['timeout'] = timeout

    monkeypatch.setattr(cli, '_run_proxy_bridge', fake_bridge)

    cli.run(['proxy', '--host', '10.0.0.5', '--port', '18000', '--timeout', '12'])

    assert recorded == {'host': '10.0.0.5', 'port': 18000, 'timeout': 12.0}


def test_run_with_binary_argument_uses_launch(monkeypatch, tmp_path):
    binary = tmp_path / 'sample.bin'
    binary.write_text('data')

    recorded = {}

    def fake_launch_session(binary_path, *, bn_path, host, port, timeout, extra_args):
        recorded['binary'] = binary_path
        recorded['bn_path'] = bn_path
        recorded['host'] = host
        recorded['port'] = port
        recorded['timeout'] = timeout
        recorded['extra_args'] = extra_args

    monkeypatch.setattr(cli, '_launch_session', fake_launch_session)
    cli.run([str(binary)])

    assert recorded['binary'] == binary.resolve()
    assert recorded['bn_path'] is None
    assert recorded['host'] == '127.0.0.1'
    assert recorded['port'] == 18765
    assert recorded['timeout'] == 45.0
    assert recorded['extra_args'] == []


def test_locate_binaryninja_prefers_env(tmp_path, monkeypatch):
    executable = tmp_path / 'binaryninja'
    executable.write_text('')
    os.chmod(executable, 0o755)
    monkeypatch.setenv('BINARYNINJA_PATH', str(executable))

    result = cli._locate_binaryninja()
    assert result == executable


def test_launch_handler_passes_extra_args(monkeypatch, tmp_path):
    binary = tmp_path / 'program.bin'
    binary.write_text('dummy')

    recorded = {}

    def fake_launch_session(binary_path, *, bn_path, host, port, timeout, extra_args):
        recorded['binary'] = binary_path
        recorded['bn_path'] = bn_path
        recorded['host'] = host
        recorded['port'] = port
        recorded['timeout'] = timeout
        recorded['extra_args'] = extra_args

    monkeypatch.setattr(cli, '_launch_session', fake_launch_session)

    args = argparse.Namespace(
        binary=str(binary),
        bn_path=None,
        host='0.0.0.0',
        port=18765,
        timeout=45.0,
        binary_args=['--', '--headless'],
    )

    cli._handle_launch(args)

    assert recorded['binary'] == binary.resolve()
    assert recorded['bn_path'] is None
    assert recorded['host'] == '0.0.0.0'
    assert recorded['port'] == 18765
    assert recorded['extra_args'] == ['--headless']


def test_launch_session_calls_auto_open(monkeypatch, tmp_path, capsys):
    binary = tmp_path / 'target.bin'
    binary.write_text('data')

    executable = tmp_path / 'binaryninja'
    executable.write_text('')
    os.chmod(executable, 0o755)

    monkeypatch.setattr(cli, '_locate_binaryninja', lambda explicit: executable)

    class DummyProcess:
        pid = 1234

        def poll(self):
            return None

    monkeypatch.setattr(subprocess, 'Popen', lambda cmd, env: DummyProcess())
    monkeypatch.setattr(cli, '_wait_for_mcp_server', lambda host, port, timeout, process: None)

    recorded = {}

    def fake_auto_open(host, port, path, timeout):
        recorded['args'] = (host, port, path, timeout)
        return 'handle123'

    monkeypatch.setattr(cli, '_auto_open_view', fake_auto_open)

    cli._launch_session(
        binary,
        bn_path=None,
        host='127.0.0.1',
        port=18765,
        timeout=5.0,
        extra_args=[],
    )

    assert recorded['args'] == ('127.0.0.1', 18765, binary.resolve(), 5.0)
    captured = capsys.readouterr()
    assert 'Auto-opened Binary Ninja view handle: handle123' in captured.out
