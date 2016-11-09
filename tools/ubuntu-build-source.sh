#!/bin/bash

set -e

# Build tshark and plugins
mkdir -p build && cd build && cmake ${HOME}/wireshark-${WIRESHARK_BRANCH} && make -j3 tshark sap

if [ ${BUILD_WIRESHARK} == "yes" ]; then
    make -j3 wireshark
fi

export PATH=${PATH}:${HOME}/wireshark-${WIRESHARK_BRANCH}/build
