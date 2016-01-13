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
from pysap.SAPDiag import SAPDiag
from scapy.all import Ether, IP, TCP, Raw
# Custom imports
from basetestcase import WiresharkTestCase, read_data_file


class WiresharkSAPDiagTestCase(WiresharkTestCase):

    def test_sapdiag_dissection(self):
        """Test dissection of a basic SAP Diag packet. """
        pkt = Ether()/IP()/TCP(dport=3200)/SAPNI()/SAPDiag()

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapni', packet)
        self.assertEqual(int(packet['sapni'].length), 8)

        self.assertIn('sapdiag', packet)

    def test_invalid_write(self):
        """Test invalid write vulnerability in LZC code (CVE-2015-2282)"""

        test_case = read_data_file('invalid_write_testcase.data', False)

        pkt = Ether()/IP()/TCP(dport=3200)/SAPNI()/Raw(str(SAPDiag(compress=1))[:-8])/test_case

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapdiag', packet)
        self.assertEqual(-60, int(packet['sapdiag'].header_compression_returncode))

    def test_invalid_read(self):
        "Test invalid read vulnerability in LZH code (CVE-2015-2278)"

        test_case = read_data_file('invalid_read_testcase.data', False)

        pkt = Ether()/IP()/TCP(dport=3200)/SAPNI()/Raw(str(SAPDiag(compress=1))[:-8])/test_case

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapdiag', packet)
        self.assertEqual(1, int(packet['sapdiag'].header_compression_returncode))
        self.assertEqual("The uncompressed payload length (0) differs with the reported length (661)",
                         packet['sapdiag'].header_compression_uncomplength_invalid)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(WiresharkSAPDiagTestCase))
    return suite


if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=2).run(suite())
