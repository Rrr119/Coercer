#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from coercer.core.loader import find_and_load_coerce_methods
from coercer.core.modes.paths import action_paths

from .conftest import make_options


def _options(**overrides):
    defaults = dict(
        filter_method_name=[],
        filter_protocol_name=[],
        filter_pipe_name=[],
        auth_type=None,
        smb_port=445,
        http_port=80,
        ip_address=None,
        path_ip=None,
    )
    defaults.update(overrides)
    return make_options(**defaults)


def test_action_paths_lists_dfsnm_and_fsrvp(capsys):
    methods = find_and_load_coerce_methods()
    action_paths(methods, _options())
    out = capsys.readouterr().out
    assert "MS-DFSNM" in out
    assert "NetrDfsAddStdRoot" in out
    assert "NetrDfsRemoveStdRoot" in out
    assert "MS-FSRVP" in out
    assert "IsPathSupported" in out
    assert "IsPathShadowCopied" in out
    assert r"\PIPE\netdfs" in out
    assert r"\PIPE\Fssagentrpc" in out


def test_action_paths_renders_listener_ip(capsys):
    methods = find_and_load_coerce_methods()
    action_paths(methods, _options(ip_address="192.168.1.10"))
    out = capsys.readouterr().out
    assert "\\\\192.168.1.10\\" in out


def test_action_paths_honors_protocol_filter(capsys):
    methods = find_and_load_coerce_methods()
    action_paths(methods, _options(filter_protocol_name=["MS-DFSNM"]))
    out = capsys.readouterr().out
    assert "MS-DFSNM" in out
    assert "MS-FSRVP" not in out
    assert "MS-EFSR" not in out


def test_action_paths_honors_auth_type_filter(capsys):
    methods = find_and_load_coerce_methods()
    action_paths(
        methods,
        _options(filter_protocol_name=["MS-DFSNM"], auth_type="smb"),
    )
    out = capsys.readouterr().out
    assert "[smb]" in out
    assert "[http]" not in out


def test_action_paths_honors_method_filter(capsys):
    methods = find_and_load_coerce_methods()
    action_paths(methods, _options(filter_method_name=["NetrDfsAddStdRoot"]))
    out = capsys.readouterr().out
    assert "NetrDfsAddStdRoot" in out
    assert "NetrDfsRemoveStdRoot" not in out
