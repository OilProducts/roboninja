from pathlib import Path

import pytest

import subprocess
import shutil
import sys

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


def test_proxy_invokes_mcp_cli(monkeypatch):
    recorded = {}

    def fake_run(args, check):
        recorded['args'] = args
        recorded['check'] = check

    monkeypatch.setattr(subprocess, 'run', fake_run)
    monkeypatch.setattr(shutil, 'which', lambda name: 'mcp')

    cli._run_proxy_cli('127.0.0.1', 18000, None)
    expected = Path(sys.executable).with_name('mcp')
    assert recorded['args'] == [str(expected), 'proxy', '--url', 'http://127.0.0.1:18000']
    assert recorded['check'] is True


def test_proxy_uses_explicit_path(tmp_path, monkeypatch):
    recorded = {}

    def fake_run(args, check):
        recorded['args'] = args
        recorded['check'] = check

    monkeypatch.setattr(subprocess, 'run', fake_run)
    dummy = tmp_path / 'mcp'
    dummy.write_text('#!/bin/sh\n')
    cli._run_proxy_cli('127.0.0.1', 19000, str(dummy))
    assert recorded['args'] == [str(dummy), 'proxy', '--url', 'http://127.0.0.1:19000']
    assert recorded['check'] is True
