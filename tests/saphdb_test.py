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
import sys
import unittest
# External imports
from scapy.all import Ether, IP, TCP
from pysap.SAPHDB import SAPHDB, SAPHDBSegment, SAPHDBPart
# Custom imports
from basetestcase import WiresharkTestCase


class WiresharkSAPHDBTestCase(WiresharkTestCase):

    def test_saphdb_dissection(self):
        """Test dissection of a basic SAP HDB packet. """
        pkt = Ether()/IP()/TCP(dport=30013)
        pkt /= SAPHDB(segments=[SAPHDBSegment(segmentkind=1, segmentno=1),
                                SAPHDBSegment(segmentkind=2, segmentno=2,
                                              parts=[SAPHDBPart(),
                                                     SAPHDBPart()])])

        packet = self.get_capture(pkt)[0]
        self.assertIn('saphdb', packet)
        self.assertIn('message_header', dir(packet['saphdb']))
        self.assertEqual(int(packet["saphdb"].sessionid), pkt[SAPHDB].sessionid)
        self.assertEqual(int(packet["saphdb"].noofsegm), len(pkt[SAPHDB].segments))
        self.assertEqual(int(packet["saphdb"].varpartlength), 80)


if __name__ == "__main__":
    unittest.main(verbosity=2)
