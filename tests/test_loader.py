#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from coercer.core.loader import find_and_load_coerce_methods
from coercer.structures.MethodType import MethodType


def _load():
    return find_and_load_coerce_methods()


def test_ms_dfsnm_methods_are_loaded():
    methods = _load()[MethodType.MICROSOFT_PROTOCOL]
    assert "MS-DFSNM" in methods
    assert set(methods["MS-DFSNM"].keys()) == {
        "NetrDfsAddStdRoot",
        "NetrDfsRemoveStdRoot",
    }


def test_ms_fsrvp_methods_are_loaded():
    methods = _load()[MethodType.MICROSOFT_PROTOCOL]
    assert "MS-FSRVP" in methods
    assert set(methods["MS-FSRVP"].keys()) == {
        "IsPathShadowCopied",
        "IsPathSupported",
    }


def test_ms_dfsnm_binding_information():
    methods = _load()[MethodType.MICROSOFT_PROTOCOL]
    for name, entry in methods["MS-DFSNM"].items():
        cls = entry["class"]
        np_access = cls.access["ncan_np"][0]
        assert np_access["namedpipe"] == r"\PIPE\netdfs"
        assert np_access["uuid"] == "4fc742e0-4a10-11cf-8273-00aa004ae673"
        assert np_access["version"] == "3.0"
        tcp_access = cls.access["ncacn_ip_tcp"][0]
        assert tcp_access["uuid"] == "4fc742e0-4a10-11cf-8273-00aa004ae673"
        assert tcp_access["version"] == "3.0"


def test_ms_fsrvp_binding_information():
    methods = _load()[MethodType.MICROSOFT_PROTOCOL]
    for name, entry in methods["MS-FSRVP"].items():
        cls = entry["class"]
        np_access = cls.access["ncan_np"][0]
        assert np_access["namedpipe"] == r"\PIPE\Fssagentrpc"
        assert np_access["uuid"] == "a8e0653c-2744-4389-a61d-7373df8b2292"
        assert np_access["version"] == "1.0"
        tcp_access = cls.access["ncacn_ip_tcp"][0]
        assert tcp_access["uuid"] == "a8e0653c-2744-4389-a61d-7373df8b2292"
        assert tcp_access["version"] == "1.0"


def test_ms_dfsnm_opnums():
    methods = _load()[MethodType.MICROSOFT_PROTOCOL]
    assert methods["MS-DFSNM"]["NetrDfsAddStdRoot"]["class"].function["opnum"] == 12
    assert (
        methods["MS-DFSNM"]["NetrDfsRemoveStdRoot"]["class"].function["opnum"] == 13
    )


def test_ms_fsrvp_opnums():
    methods = _load()[MethodType.MICROSOFT_PROTOCOL]
    assert methods["MS-FSRVP"]["IsPathSupported"]["class"].function["opnum"] == 8
    assert methods["MS-FSRVP"]["IsPathShadowCopied"]["class"].function["opnum"] == 9


def test_all_methods_expose_required_attributes():
    methods = _load()[MethodType.MICROSOFT_PROTOCOL]
    for protocol, functions in methods.items():
        for name, entry in functions.items():
            cls = entry["class"]
            assert cls.protocol["shortname"] == protocol
            assert cls.function["name"] == name
            assert len(cls.exploit_paths) != 0
            assert callable(cls.trigger)
            for auth_type, path in cls.exploit_paths:
                assert auth_type in ("smb", "http")
                assert "{{listener}}" in path
