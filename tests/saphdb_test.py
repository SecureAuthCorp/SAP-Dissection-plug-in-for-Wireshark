#!/usr/bin/env python
# ===========
# SAP Dissector Plugin for Wireshark
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# The plugin was designed and developed by Martin Gallo from
# SecureAuth Labs team.
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
from pysap.SAPHDB import SAPHDB
from scapy.all import Ether, IP, TCP
# Custom imports
from basetestcase import WiresharkTestCase


class WiresharkSAPHDBTestCase(WiresharkTestCase):

    def test_saphdb_dissection(self):
        """Test dissection of a basic SAP HDB packet. """
        pkt = Ether()/IP()/TCP(dport=30013)/SAPHDB()
        pkt.show2()

        packet = self.get_capture(pkt)[0]
        packet.show()

        self.assertIn('saphdb', packet)
        self.assertIn('message_header', dir(packet['saphdb']))
        print(packet["saphdb"].field_names)
        self.assertEqual(packet["saphdb"].message_header_varpartlength, "0")


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(WiresharkSAPHDBTestCase))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
