#!/bin/bash
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

set -e

# Update repo cache
sudo apt-get update -qq

# Install build requirements
sudo apt-get build-dep -yqq wireshark
sudo apt-get install -yqq cmake qt5-default libqt5multimedia5 qtmultimedia5-dev qttools5-dev qttools5-dev-tools

# Check out source
mkdir -p ${HOME}/wireshark-$WIRESHARK_BRANCH
cd ${HOME}/wireshark-$WIRESHARK_BRANCH
git init
if ! git config remote.origin.url > /dev/null; then
  git remote add -t $WIRESHARK_BRANCH -f origin https://github.com/wireshark/wireshark;
fi
git checkout $WIRESHARK_BRANCH

# Link the plugin to the plugins directory if required
if [ ! -e plugins/sap ]; then
  ln -s $PLUGIN_DIR plugins/sap
fi

# Apply the patch if required
if git apply --check $PLUGIN_DIR/wireshark-$WIRESHARK_BRANCH.patch &> /dev/null; then
  git apply $PLUGIN_DIR/wireshark-$WIRESHARK_BRANCH.patch
fi

# Install test requirements
sudo apt-get install -yqq libxml2-dev libxslt-dev python-dev python-pip
sudo -H sh -c "CXX=g++ CC=gcc pip install pysap pyshark"
