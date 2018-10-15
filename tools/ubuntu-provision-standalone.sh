#!/bin/bash
# ===========
# SAP Dissector Plugin for Wireshark
#
# Copyright (C) 2012-2018 by Martin Gallo, SecureAuth Corporation
#
# The plugin was designed and developed by Martin Gallo from
# SecureAuth Corporation's Labs team.
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
sudo apt-get install -yqq libxml2-dev libxslt-dev python-dev python-pip
sudo -H sh -c "CXX=g++ CC=gcc pip install pysap pyshark-legacy"
