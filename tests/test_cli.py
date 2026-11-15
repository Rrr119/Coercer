#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from coercer.__main__ import parseArgs


def _parse(argv, monkeypatch):
    monkeypatch.setattr(sys, "argv", argv)
    return parseArgs()


def test_paths_mode_parses(monkeypatch):
    _, _, options = _parse(
        ["coercer", "paths", "-I", "192.168.1.10", "--auth-type", "smb"],
        monkeypatch,
    )
    assert options.mode == "paths"
    assert options.ip_address == "192.168.1.10"
    assert options.auth_type == "smb"


def test_scan_mode_timeout_option(monkeypatch):
    _, _, options = _parse(
        ["coercer", "scan", "-t", "192.168.1.20", "--timeout", "5"], monkeypatch
    )
    assert options.mode == "scan"
    assert options.timeout == 5


def test_coerce_mode_timeout_option(monkeypatch):
    _, _, options = _parse(
        [
            "coercer", "coerce",
            "-t", "192.168.1.20",
            "-l", "192.168.1.10",
            "--timeout", "2",
        ],
        monkeypatch,
    )
    assert options.timeout == 2


def test_fuzz_mode_timeout_option(monkeypatch):
    _, _, options = _parse(
        ["coercer", "fuzz", "-t", "192.168.1.20", "--timeout", "7"], monkeypatch
    )
    assert options.timeout == 7


def test_timeout_defaults_to_none(monkeypatch):
    _, _, options = _parse(["coercer", "scan", "-t", "192.168.1.20"], monkeypatch)
    assert options.timeout is None


def test_kerberos_options(monkeypatch):
    _, _, options = _parse(
        [
            "coercer", "scan",
            "-t", "dc01.domain.local",
            "-u", "user",
            "--no-pass",
            "-k",
            "--aesKey", "ff" * 32,
            "--dc-ip", "10.0.0.1",
        ],
        monkeypatch,
    )
    assert options.kerberos is True
    assert options.aesKey == "ff" * 32
    assert options.dc_ip == "10.0.0.1"


def test_hashes_parsing(monkeypatch):
    lmhash, nthash, options = _parse(
        [
            "coercer", "scan",
            "-t", "192.168.1.20",
            "-u", "user",
            "--hashes",
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        ],
        monkeypatch,
    )
    assert lmhash == "aad3b435b51404eeaad3b435b51404ee"
    assert nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_paths_mode_filters(monkeypatch):
    _, _, options = _parse(
        [
            "coercer", "paths",
            "--filter-protocol-name", "MS-DFSNM",
            "--filter-method-name", "NetrDfsAddStdRoot",
        ],
        monkeypatch,
    )
    assert options.filter_protocol_name == ["MS-DFSNM"]
    assert options.filter_method_name == ["NetrDfsAddStdRoot"]
