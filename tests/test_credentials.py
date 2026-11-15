#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from coercer.structures.Credentials import Credentials


def test_anonymous_credentials():
    creds = Credentials("", "", "", "", "")
    assert creds.is_anonymous()


def test_authenticated_credentials():
    creds = Credentials("user", "pass", "domain", "", "")
    assert not creds.is_anonymous()


def test_kerberos_attributes_default_to_disabled():
    creds = Credentials("user", "pass", "domain", "", "")
    assert creds.doKerberos is False
    assert creds.kdcHost is None
    assert creds.aesKey is None
    assert creds.dc_ip is None


def test_kerberos_attributes_are_stored():
    creds = Credentials(
        "user",
        "pass",
        "domain",
        "aad3b435b51404eeaad3b435b51404ee",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        doKerberos=True,
        kdcHost="10.0.0.1",
        aesKey="ff" * 32,
        dc_ip="10.0.0.1",
    )
    assert creds.doKerberos is True
    assert creds.kdcHost == "10.0.0.1"
    assert creds.aesKey == "ff" * 32
    assert creds.dc_ip == "10.0.0.1"
