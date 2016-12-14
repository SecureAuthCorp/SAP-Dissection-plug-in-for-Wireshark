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

mkdir c:\projects\sap\build
cd c:\projects\sap\build
cmake -DENABLE_CHM_GUIDES=on -G "Visual Studio 12 Win64" c:\projects\wireshark
msbuild /m /p:Configuration=%Configuration% /logger:"C:\\Program Files\\AppVeyor\\BuildAgent\\Appveyor.MSBuildLogger.dll" plugins\sap\sap.vcxproj
