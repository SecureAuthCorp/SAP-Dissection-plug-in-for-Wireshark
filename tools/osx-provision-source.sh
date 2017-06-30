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

#Update to last brew release
brew update

#install some libs needed by Wireshark
brew install c-ares glib libgcrypt gnutls lua cmake nghttp2 snappy lz4 libxml2

#install Qt5
brew install qt5

#Fix qt5 lib link
brew link --force qt5
VERSION=`brew info qt5 | grep /usr/local/Cellar | tail -n 1 | cut -d '/' -f6 | cut -d ' ' -f1`
#sudo rm /usr/local/mkspecs /usr/local/plugins
sudo ln -s /usr/local/Cellar/qt5/$VERSION/mkspecs /usr/local/
sudo ln -s /usr/local/Cellar/qt5/$VERSION/plugins /usr/local/

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
brew install --with-python libdnet
brew install https://raw.githubusercontent.com/secdev/scapy/master/.travis/pylibpcap.rb

sudo -H sh -c "CXX=g++ CC=gcc pip install pysap pyshark"
