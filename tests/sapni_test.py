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
from scapy.all import Ether, IP, TCP
# Custom imports
from basetestcase import WiresharkTestCase


class WiresharkSAPNITestCase(WiresharkTestCase):

    def test_sapni_dissection(self):
        """Test dissection of a basic SAP NI packet. """
        pkt = Ether()/IP()/TCP(dport=3299)/SAPNI()/"LALA"

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapni', packet)
        self.assertEqual(int(packet['sapni'].length), 4)

    def test_sapni_ping(self):
        """Test dissection of a basic SAP NI PING packet. """
        pkt = Ether()/IP()/TCP(dport=3299)/SAPNI()/"NI_PING\x00"

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapni', packet)
        self.assertEqual(int(packet['sapni'].length), 8)
        self.assertIn('ping', dir(packet['sapni']))

    def test_sapni_pong(self):
        """Test dissection of a basic SAP NI PONG packet. """
        pkt = Ether()/IP()/TCP(dport=3299)/SAPNI()/"NI_PONG\x00"

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapni', packet)
        self.assertEqual(int(packet['sapni'].length), 8)
        self.assertIn('saprouter', packet)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(WiresharkSAPNITestCase))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
