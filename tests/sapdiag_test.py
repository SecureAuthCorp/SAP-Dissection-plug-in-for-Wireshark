#!/usr/bin/env python
# SAP Dissector Plugin for Wireshark
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
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
#
# Author:
#   Martin Gallo (@martingalloar) from SecureAuth's Innovation Labs team.
#

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

    def test_invalid_read(self):
        "Test invalid read vulnerability in LZH code (CVE-2015-2278)"

        test_case = read_data_file('invalid_read_testcase.data', False)

        pkt = Ether()/IP()/TCP(dport=3200)/SAPNI()/Raw(str(SAPDiag(compress=1))[:-8])/test_case

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapdiag', packet)
        self.assertEqual(1, int(packet['sapdiag'].header_compression_returncode))
        self.assertEqual("The uncompressed payload length (0) differs with the reported length (661)",
                         packet['sapdiag'].header_compression_uncomplength_invalid)

    def test_login_screen(self):
        """Test decompression of a login screen packet. The result is
        compared with data obtained from SAP GUI."""

        login_screen_compressed = read_data_file('nw_703_login_screen_compressed.data')
        login_screen_decompressed = read_data_file('nw_703_login_screen_decompressed.data')

        pkt = Ether()/IP()/TCP(dport=3200)/SAPNI()/Raw(str(SAPDiag(compress=1))[:-8])/login_screen_compressed

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapdiag', packet)
        self.assertEqual(1, int(packet['sapdiag'].header_compression_returncode))
        self.assertEqual(len(login_screen_decompressed), int(packet['sapdiag'].header_compression_uncomplength))

    def test_login(self):
        """Test decompression of a login packet. The result is
        compared with data obtained from SAP GUI."""

        login_compressed = read_data_file('sapgui_730_login_compressed.data')
        login_decompressed = read_data_file('sapgui_730_login_decompressed.data')

        pkt = Ether()/IP()/TCP(dport=3200)/SAPNI()/Raw(str(SAPDiag(compress=1))[:-8])/login_compressed

        packet = self.get_capture(pkt)[0]

        self.assertIn('sapdiag', packet)
        self.assertEqual(1, int(packet['sapdiag'].header_compression_returncode))
        self.assertEqual(len(login_decompressed), int(packet['sapdiag'].header_compression_uncomplength))


if __name__ == "__main__":
    unittest.main(verbosity=2)
