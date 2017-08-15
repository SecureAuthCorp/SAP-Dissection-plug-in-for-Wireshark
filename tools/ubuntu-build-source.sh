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

# Disable Application bundle on MacOS
CMAKE_OPTIONS=-DENABLE_APPLICATION_BUNDLE=OFF

# Build tshark and plugins
cd ${HOME}/wireshark-${WIRESHARK_BRANCH}
mkdir -p build && cd build && cmake .. ${CMAKE_OPTIONS} && make -j3 tshark sap

# Build entire wireshark if required
if [ "${BUILD_WIRESHARK}" == "yes" ]; then
    make -j3 all;
fi
