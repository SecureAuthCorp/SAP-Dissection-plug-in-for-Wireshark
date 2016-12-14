# ===========
# SAP Dissector Plugin for Wireshark
#
# Copyright (C) 2012-2016 by Martin Gallo, Core Security
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

# Add Cygwin to PATH
set PATH=%PATH%;C:\cygwin64\bin\
set PATH=C:\cygwin64\bin\;%PATH%

# Get Wireshark and checkout the branch
mkdir c:\projects\wireshark
cd c:\projects\wireshark
git init

git remote add -t master-2.2 -f origin https://github.com/wireshark/wireshark
git checkout master-2.2

# Set necessary environment variables:
set CYGWIN=nodosfilewarning
set WIRESHARK_BASE_DIR=c:\projects
set WIRESHARK_TARGET_PLATFORM=win64
set QT5_BASE_DIR=c:\Qt\5.6\msvc2013

# Insert our plugin files to wireshark
mkdir C:\projects\wireshark\plugins\sap
xcopy /E c:\projects\sap C:\projects\wireshark\plugins\sap

# Run the adjustment scripts
git apply plugins/sap/wireshark-master-2.2.patch
Invoke-WebRequest -Uri https://cygwin.com/setup-x86_64.exe -OutFile c:\projects\cygwin-setup.exe
mkdir c:\projects\cyg-packages
c:\projects\cygwin-setup.exe -q -n -N -d -R C:\cygwin64 -s http://ftp.hawo.stw.uni-erlangen.de/cygwin/ -l c:\projects\cyg-packages -P flex -P bison
set WIRESHARK_CYGWIN_INSTALL_PATH=C:\cygwin64
