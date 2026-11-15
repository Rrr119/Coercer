#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from coercer.core.Filter import Filter
from coercer.methods.MS_DFSNM.NetrDfsAddStdRoot import NetrDfsAddStdRoot
from coercer.methods.MS_FSRVP.IsPathSupported import IsPathSupported


def _filter(**kwargs):
    defaults = dict(
        filter_method_name=[], filter_protocol_name=[], filter_pipe_name=[]
    )
    defaults.update(kwargs)
    return Filter(**defaults)


def test_no_filter_matches_everything():
    f = _filter()
    assert f.method_matches_filter(NetrDfsAddStdRoot)
    assert f.method_matches_filter(IsPathSupported)


def test_filter_by_protocol_name():
    f = _filter(filter_protocol_name=["MS-DFSNM"])
    assert f.method_matches_filter(NetrDfsAddStdRoot)
    assert not f.method_matches_filter(IsPathSupported)


def test_filter_by_method_name():
    f = _filter(filter_method_name=["NetrDfsAdd"])
    assert f.method_matches_filter(NetrDfsAddStdRoot)
    assert not f.method_matches_filter(IsPathSupported)


def test_method_and_protocol_filters_are_combined():
    f = _filter(
        filter_method_name=["NetrDfsAdd"], filter_protocol_name=["MS-FSRVP"]
    )
    assert not f.method_matches_filter(NetrDfsAddStdRoot)


def test_pipe_filter():
    f = _filter(filter_pipe_name=["netdfs"])
    assert f.pipe_matches_filter(r"\PIPE\netdfs")
    assert not f.pipe_matches_filter(r"\PIPE\Fssagentrpc")

    f = _filter()
    assert f.pipe_matches_filter(r"\PIPE\anything")
