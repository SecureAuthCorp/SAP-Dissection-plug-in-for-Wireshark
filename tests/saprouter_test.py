#!/usr/bin/env python
# ===========
# SAP Dissector Plugin for Wireshark
#
# Copyright (C) 2012-2016 by Martin Gallo, Core Security
#
# The plugin was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security.
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
import unittest
# External imports
from pysap.SAPNI import SAPNI
from pysap.SAPRouter import SAPRouter, SAPRouterRouteHop
from scapy.all import Ether, IP, TCP, Raw
# Custom imports
from basetestcase import WiresharkTestCase


class WiresharkSAPRouterTestCase(WiresharkTestCase):

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
        self.assertEqual(int(packet['sapni'].length), 60)
        self.assertIn('saprouter', packet)

        self.assertEqual(p.type, packet['saprouter'].type)
        self.assertEqual(p.version, int(packet['saprouter'].version))
        self.assertEqual(p.route_ni_version, int(packet['saprouter'].niversion))
        self.assertEqual(p.route_entries, int(packet['saprouter'].entries))
        self.assertEqual(p.route_talk_mode, int(packet['saprouter'].talkmode))
        self.assertEqual(p.route_rest_nodes, int(packet['saprouter'].restnodes))
        self.assertEqual(p.route_length, int(packet['saprouter'].routelength))
        self.assertEqual(p.route_offset, int(packet['saprouter'].routeoffset))
        self.assertEqual("Route password found", packet['saprouter']._ws_expert_message)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(WiresharkSAPRouterTestCase))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
