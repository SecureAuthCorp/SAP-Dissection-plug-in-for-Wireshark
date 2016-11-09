#!/bin/bash

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
if git apply --check $PLUGIN_DIR/wireshark-$WIRESHARK_BRANCH.patch; then
  git apply $PLUGIN_DIR/wireshark-$WIRESHARK_BRANCH.patch
fi

# Install test requirements
sudo apt-get install -yqq libxml2-dev libxslt-dev python-dev python-pip
sudo -H sh -c "CXX=g++ CC=gcc pip install pysap pyshark"
