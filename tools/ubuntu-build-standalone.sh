#!/bin/bash

set -e

# Build sap plugin
mkdir -p build && cd build && cmake ${PLUGIN_DIR} && make && make install
