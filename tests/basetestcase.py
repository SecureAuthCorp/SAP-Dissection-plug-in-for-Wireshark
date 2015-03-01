#!/usr/bin/env python
# ===========
# SAP Dissector Plugin for Wireshark
#
# Copyright (C) 2015 Core Security Technologies
#
# The plugin was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security Technologies.
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
from os import remove, path
# External imports
import pyshark
from scapy.all import *


pyshark.config.CONFIG_PATH = path.join(path.dirname(__file__), "pyshark.ini")


class WiresharkTestCase(unittest.TestCase):
    
    tests_filename = "tests.pcap"

    def get_capture(self, pkt):
        """Write down a scapy packet to a pcap file and dissect it using
        tshark."""
        wrpcap(self.tests_filename, pkt)
        cap = pyshark.FileCapture(self.tests_filename)
        return cap

    def tearDown(self):
        if path.exists(self.tests_filename):
            remove(self.tests_filename)
