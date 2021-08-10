#!/bin/bash
# SAP Dissector Plugin for Wireshark
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
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

set -e

# Add the wireshark-dev ppa
sudo add-apt-repository ppa:wireshark-dev/stable -y

# Update repo cache
sudo apt-get update -qq

# Install build requirements
export DEBIAN_FRONTEND=noninteractive
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo apt-get install -yqq cmake wireshark wireshark-dev tshark

# Install test requirements
sudo apt-get install -yqq libxml2-dev libxslt-dev python2.7-dev python-pip
sudo -H sh -c "python2 -m pip install --upgrade pip setuptools wheel"
sudo -H sh -c "python2 -m pip install pysap"

git clone https://github.com/martingalloar/pyshark-legacy
sudo -H sh -c "python2 -m pip install pyshark-legacy/src"
