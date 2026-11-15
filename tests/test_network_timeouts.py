#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from unittest import mock

from coercer.network import rpc, smb
from coercer.network.DCERPCSession import DCERPCSession
from coercer.structures.Credentials import Credentials


def _credentials(doKerberos=False):
    return Credentials(
        "user",
        "pass",
        "domain",
        "",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        doKerberos=doKerberos,
        kdcHost="10.0.0.1" if doKerberos else None,
        aesKey="ff" * 32 if doKerberos else None,
        dc_ip="10.0.0.1" if doKerberos else None,
    )


def test_is_port_open_applies_timeout():
    with mock.patch.object(rpc.socket, "socket") as socket_mock:
        instance = socket_mock.return_value
        rpc.is_port_open("192.0.2.1", 445, timeout=3)
        instance.settimeout.assert_called_once_with(3)


def test_is_port_open_without_timeout():
    with mock.patch.object(rpc.socket, "socket") as socket_mock:
        instance = socket_mock.return_value
        rpc.is_port_open("192.0.2.1", 445)
        instance.settimeout.assert_not_called()


def test_can_connect_to_pipe_applies_timeout():
    with mock.patch.object(
        smb.transport, "DCERPCTransportFactory"
    ) as factory_mock:
        rpctransport = factory_mock.return_value
        smb.can_connect_to_pipe(
            "192.0.2.1", r"\PIPE\netdfs", _credentials(), timeout=3
        )
        rpctransport.set_connect_timeout.assert_called_once_with(3)


def test_can_bind_to_interface_applies_timeout():
    with mock.patch.object(
        smb.transport, "DCERPCTransportFactory"
    ) as factory_mock:
        rpctransport = factory_mock.return_value
        result = smb.can_bind_to_interface(
            "192.0.2.1",
            r"\PIPE\netdfs",
            _credentials(),
            "4fc742e0-4a10-11cf-8273-00aa004ae673",
            "3.0",
            timeout=3,
        )
        rpctransport.set_connect_timeout.assert_called_once_with(3)
        assert result is True


def test_can_bind_to_interface_on_port_applies_timeout():
    with mock.patch.object(
        rpc.transport, "DCERPCTransportFactory"
    ) as factory_mock:
        rpctransport = factory_mock.return_value
        result = rpc.can_bind_to_interface_on_port(
            "192.0.2.1",
            49664,
            _credentials(),
            "a8e0653c-2744-4389-a61d-7373df8b2292",
            "1.0",
            timeout=3,
        )
        rpctransport.set_connect_timeout.assert_called_once_with(3)
        assert result is True


def test_portmap_discover_applies_timeout():
    with mock.patch.object(
        rpc.transport, "DCERPCTransportFactory"
    ) as factory_mock, mock.patch.object(rpc.epm, "hept_lookup", return_value=[]):
        rpctransport = factory_mock.return_value
        rpc.portmap_discover("192.0.2.1", 135, timeout=3)
        rpctransport.set_connect_timeout.assert_called_once_with(3)


def test_dcerpc_session_ncacn_ip_tcp_supports_timeout_and_kerberos():
    with mock.patch(
        "coercer.network.DCERPCSession.transport.DCERPCTransportFactory"
    ) as factory_mock:
        rpctransport = factory_mock.return_value
        session = DCERPCSession(credentials=_credentials(doKerberos=True), timeout=3)
        session.connect_ncacn_ip_tcp("dc01.domain.local", 49664)
        rpctransport.set_connect_timeout.assert_called_once_with(3)
        rpctransport.set_kerberos.assert_called_once_with(True, kdcHost="10.0.0.1")
        session.session.set_credentials.assert_called_once_with(
            "user",
            "pass",
            "domain",
            "",
            "31d6cfe0d16ae931b73c59d7e0c089c0",
            "ff" * 32,
        )


def test_dcerpc_session_ncacn_np_supports_timeout():
    with mock.patch(
        "coercer.network.DCERPCSession.transport.DCERPCTransportFactory"
    ) as factory_mock:
        rpctransport = factory_mock.return_value
        session = DCERPCSession(credentials=_credentials(), timeout=3)
        session.connect_ncacn_np("192.0.2.1", r"\PIPE\Fssagentrpc")
        rpctransport.set_connect_timeout.assert_called_once_with(3)


def test_dcerpc_session_without_timeout_keeps_impacket_default():
    with mock.patch(
        "coercer.network.DCERPCSession.transport.DCERPCTransportFactory"
    ) as factory_mock:
        rpctransport = factory_mock.return_value
        session = DCERPCSession(credentials=_credentials())
        session.connect_ncacn_np("192.0.2.1", r"\PIPE\netdfs")
        rpctransport.set_connect_timeout.assert_not_called()
