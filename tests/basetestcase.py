#!/usr/bin/env python
# ===========
# SAP Dissector Plugin for Wireshark
#
# Copyright (C) 2012-2017 by Martin Gallo, Core Security
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
from os import remove, path
from binascii import unhexlify
from os.path import join as join, dirname
# External imports
import pyshark
from scapy.all import *


TSHARK_PATH = "./tshark"


def read_data_file(filename, unhex=True):
    filename = join(dirname(__file__), 'data', filename)
    with open(filename, 'r') as f:
        data = f.read()

    data = data.replace('\n', ' ').replace(' ', '')
    if unhex:
        data = unhexlify(data)

    return data


class WiresharkTestCase(unittest.TestCase):

    tests_filename = "tests.pcap"

    def get_capture(self, pkt):
        """Write down a scapy packet to a pcap file and dissect it using
        tshark."""
        # Remove the pcap if already exists
        if path.exists(self.tests_filename):
            remove(self.tests_filename)
        # Write it using scapy
        wrpcap(self.tests_filename, pkt)
        # Parse it using pyshark
        cap = pyshark.FileCapture(self.tests_filename, tshark_path=TSHARK_PATH)
        return cap

    def assert_fields(self, scapy_pkt, pyshark_pkt, mapping):
        """Checks value of fields against a scapy packet and a pyshark packet
        given a mapping or attribute names and transform functions.
        """
        for field, value in scapy_pkt.fields.items():
            if field in mapping:
                if isinstance(mapping[field], tuple) and len(mapping[field]) == 2:
                    field, function = mapping[field]
                else:
                    field = mapping[field]
                    function = None

                pyshark_value = getattr(pyshark_pkt, field)

                if function is not None:
                    pyshark_value = function(pyshark_value)

                self.assertEqual(value, pyshark_value)

    def tearDown(self):
        if path.exists(self.tests_filename):
            remove(self.tests_filename)
