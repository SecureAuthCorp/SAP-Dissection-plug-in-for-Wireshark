#!/bin/bash

set -e

# Build tshark and plugins
mkdir -p build && cd build && cmake ${HOME}/wireshark-$WIRESHARK_BRANCH && make -j3 plugins tshark sap
export PATH=${PATH}:${HOME}/wireshark-$WIRESHARK_BRANCH/build
