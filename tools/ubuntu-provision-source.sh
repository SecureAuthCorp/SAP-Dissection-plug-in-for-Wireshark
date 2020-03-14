#!/bin/bash
# ===========
# SAP Dissector Plugin for Wireshark
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
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

set -e

# Update repo cache
sudo apt-get update -qq

# Install build requirements
sudo gem install asciidoctor
sudo apt-get install -yqq cmake libglib2.0-dev qttools5-dev qttools5-dev-tools libqt5svg5-dev qtmultimedia5-dev qt5-default libpcap-dev bison flex make python3 python3-pip perl libgcrypt-dev

# Check out source
mkdir -p ${HOME}/wireshark-$WIRESHARK_BRANCH
cd ${HOME}/wireshark-$WIRESHARK_BRANCH
git init
if ! git config remote.origin.url > /dev/null; then
  git remote add -t $WIRESHARK_BRANCH -f origin https://github.com/wireshark/wireshark;
fi
git checkout $WIRESHARK_BRANCH

# Link the plugin to the plugins directory if required
if [ ! -e plugins/epan/sap ]; then
  ln -s $PLUGIN_DIR plugins/epan/sap
fi

# Apply the patch if required
if git apply --check $PLUGIN_DIR/wireshark-$WIRESHARK_BRANCH.patch &> /dev/null; then
  git apply $PLUGIN_DIR/wireshark-$WIRESHARK_BRANCH.patch
fi

# Install test requirements
sudo apt-get install -yqq libxml2-dev libxslt-dev python-dev python-pip
sudo -H sh -c "pip install pip -U"
sudo -H sh -c "pip install setuptools -U"
sudo -H sh -c "CXX=g++ CC=gcc pip install pysap pyshark-legacy"
