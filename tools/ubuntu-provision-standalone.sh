#!/bin/bash

set -e

# Update repo cache
sudo apt-get update -qq

# Install build requirements
export DEBIAN_FRONTEND=noninteractive
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo apt-get install -yqq cmake wireshark wireshark-dev tshark

# Install test requirements
sudo apt-get install -yqq libxml2-dev libxslt-dev python-dev python-pip
sudo -H sh -c "CXX=g++ CC=gcc pip install pysap pyshark"
