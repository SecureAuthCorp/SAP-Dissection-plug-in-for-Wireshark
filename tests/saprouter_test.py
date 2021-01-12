#!/usr/bin/env python
# ===========
# SAP Dissector Plugin for Wireshark
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# The plugin was designed and developed by Martin Gallo from
# SecureAuth's Innovation Labs team.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ==============

# Standard imports
import sys
import unittest
# External imports
from pysap.SAPNI import SAPNI
from pysap.SAPRouter import SAPRouter, SAPRouterRouteHop
from scapy.all import Ether, IP, TCP, Raw
# Custom imports
from basetestcase import WiresharkTestCase


class WiresharkSAPRouterTestCase(WiresharkTestCase):

    route_mapping = {
        "type": "type",
        "version": ("version", int),
        "route_ni_version": ("niversion", int),
        "route_entries": ("entries", int),
        "route_talk_mode": ("talkmode", int),
        "route_rest_nodes": ("restnodes", int),
        "route_length": ("routelength", int),
        "route_offset": ("routeoffset", int),
    }

    admin_mapping = {
        "type": "type",
        "version": ("niversion", int),
        "adm_command": ("command", int),
        "adm_password": "password",
        "adm_client_count": ("client_count", int),
        #"adm_client_ids": "client_id",
        "adm_address_mask": "address_mask",
    }

    control_mapping = {
        "type": "type",
        "version": ("niversion", int),
        "opcode": ("opcode", int),
        "return_code": ("returncode", int),
        "control_text_length": ("controllength", int),
        #"control_text_value": "controltext",
    }

    def test_saprouter_dissection(self):
        """Test dissection of a basic SAP Router packet. """
        pkt = Ether()/IP()/TCP(dport=3299)/SAPNI()/SAPRouter()

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapni', packet)
        self.assertEqual(int(packet['sapni'].length), 24)
        self.assertIn('saprouter', packet)

    def test_saprouter_route_dissection(self):
        """Test dissection of a SAP Router route request."""

        # Build the Route request packet
        router_string = [SAPRouterRouteHop(hostname="1.2.3.4",
                                           port=1234),
                         SAPRouterRouteHop(hostname="4.3.2.1",
                                           port=4321,
                                           password="password")]
        router_string_lens = list(map(len, list(map(str, router_string))))
        p = SAPRouter(type=SAPRouter.SAPROUTER_ROUTE,
                      route_entries=len(router_string),
                      route_talk_mode=1,
                      route_rest_nodes=1,
                      route_length=sum(router_string_lens),
                      route_offset=router_string_lens[0],
                      route_string=router_string)

        pkt = Ether()/IP()/TCP(sport=3299, dport=9999)/SAPNI()/p

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapni', packet)
        self.assertEqual(int(packet['sapni'].length), len(p))
        self.assertIn('saprouter', packet)
        self.assert_fields(p, packet["saprouter"], self.route_mapping)
        self.assertEqual("Route password found", packet['saprouter']._ws_expert_message)

    def test_saprouter_admin_info_request_dissection(self):
        """Test dissection of a SAP Router admin info request."""

        # Build the Admin packet
        p = SAPRouter(type=SAPRouter.SAPROUTER_ADMIN,
                      version=2,
                      adm_command=2,
                      adm_password="SomePa$$w0rd")

        pkt = Ether()/IP()/TCP(sport=3299, dport=9999)/SAPNI()/p

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapni', packet)
        self.assertEqual(int(packet['sapni'].length), len(p))
        self.assertIn('saprouter', packet)
        self.assert_fields(p, packet["saprouter"], self.admin_mapping)
        self.assertEqual("Info password found", packet['saprouter']._ws_expert_message)

    def test_saprouter_admin_cancel_trace_route_dissection(self):
        """Test dissection of a SAP Router admin cancel route and trace route request."""

        for command in [6, 12, 13]:
            # Build the Admin packet
            p = SAPRouter(type=SAPRouter.SAPROUTER_ADMIN,
                          version=2,
                          adm_command=command,
                          adm_client_count=2,
                          adm_client_ids=[1,2])

            pkt = Ether()/IP()/TCP(sport=3299, dport=9999)/SAPNI()/p

            packet = self.get_capture(pkt)[0]

            self.assertIn('sapni', packet)
            self.assertEqual(int(packet['sapni'].length), len(p))
            self.assertIn('saprouter', packet)
            self.assert_fields(p, packet["saprouter"], self.admin_mapping)

    def test_saprouter_admin_peer_trace_dissection(self):
        """Test dissection of a SAP Router admin set/clear peer trace."""

        for command in [10, 11]:
            # Build the Admin packet
            p = SAPRouter(type=SAPRouter.SAPROUTER_ADMIN,
                          version=2,
                          adm_command=command,
                          adm_address_mask="0.0.0.0")

            pkt = Ether()/IP()/TCP(sport=3299, dport=9999)/SAPNI()/p

            packet = self.get_capture(pkt)[0]

            self.assertIn('sapni', packet)
            self.assertEqual(int(packet['sapni'].length), len(p))
            self.assertIn('saprouter', packet)
            self.assert_fields(p, packet["saprouter"], self.admin_mapping)

    def test_saprouter_control_dissection(self):
        """Test dissection of a SAP Router control."""

        # Build the Control packet
        p = SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                      version=2,
                      opcode=1,
                      return_code=-99,
                      control_text_length=8,
                      control_text_value="SOMEDATA")

        pkt = Ether()/IP()/TCP(sport=3299, dport=9999)/SAPNI()/p

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapni', packet)
        self.assertEqual(int(packet['sapni'].length), len(p))
        self.assertIn('saprouter', packet)
        self.assert_fields(p, packet["saprouter"], self.control_mapping)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(WiresharkSAPRouterTestCase))
    return suite


if __name__ == "__main__":
    test_runner = unittest.TextTestRunner(verbosity=2, resultclass=unittest.TextTestResult)
    result = test_runner.run(suite())
    sys.exit(not result.wasSuccessful())
