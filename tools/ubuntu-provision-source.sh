#!/bin/bash

set -e

# Update repo cache
sudo apt-get update -qq

# Install build requirements
sudo apt-get build-dep -yqq wireshark
sudo apt-get install -yqq cmake qt5-default libqt5multimedia5 qtmultimedia5-dev qttools5-dev qttools5-dev-tools

# Check out source and patch
mkdir -p ${HOME}/wireshark-$WIRESHARK_BRANCH
cd ${HOME}/wireshark-$WIRESHARK_BRANCH
git init
git remote add -t $WIRESHARK_BRANCH -f origin https://github.com/wireshark/wireshark;
git checkout $WIRESHARK_BRANCH
ln -s $PLUGIN_DIR plugins/sap
git apply $PLUGIN_DIR/wireshark-$WIRESHARK_BRANCH.patch

# Install test requirements
sudo apt-get install -yqq libxml2-dev libxslt-dev python-dev
sudo -H sh -c "CXX=g++ CC=gcc pip install pysap pyshark"
