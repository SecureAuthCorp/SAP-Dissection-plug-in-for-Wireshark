SAP Dissector Plugin for Wireshark
==================================

[![Build Status](https://travis-ci.org/CoreSecurity/SAP-Dissection-plug-in-for-Wireshark.svg?branch=master)](https://travis-ci.org/CoreSecurity/SAP-Dissection-plug-in-for-Wireshark)

Copyright (C) 2014 Core Security Technologies

The plugin was designed and developed by Martin Gallo from the Security 
Consulting Services team of Core Security Technologies.

Version 0.1.5 (XXX 2014)


Overview
--------

SAP Netweaver [1] is a technology platform for building and integrating SAP
business applications. Communication between components uses different network
protocols. While some of them are standard and well-known protocols, other
are proprietaries and public information is not available.

This plugin provides dissection on SAP's NI, Message Server, Router, Diag and
Enqueue protocols. The dissectors are based on information acquired at
researching the different protocols and services. Additional experimental
support is included for SAP's RFC and SNC protocols. Detailed information
about the research can be found at [2], [3], [4], [5] and [6]. 


Features
--------

This plugin counts on several different dissectors:

- SAP NI Protocol dissector

    This is the dissector for SAP's Network Interface (NI) protocol. The 
    dissector handles the reassemble of fragmented TCP packets and identifies 
    keep-alive messages (`PING`/`PONG`). It also calls the respective sub-dissector
    according to the port being used.

- SAP Router Protocol dissector

    This dissector includes support for the SAP Router protocol, handling route,
    control messages and error information packets. The dissector also calls 
    the SNC sub-dissector when SNC frames are found.

- SAP Diag Protocol dissector

    The main dissector of the plugin. It dissects the main headers used by the 
    Diag protocol: DP, Diag and Compression headers. The dissector also handles 
    decompression of the payload data and includes dissection of relevant Diag 
    payload items, including Support Bits and common `APPL`/`APPL4` items. 
    Wireshark's expert information capabilities are used to remark malformed or 
    wrong packets. The dissector also calls the RFC sub-dissector when an 
    embedded RFC call is found and the SNC sub-dissector when SNC frames are 
    found.

- SAP Message Server Protocol dissector

    This module dissects the packets used by SAP's Message Server Protocol.

- SAP Enqueue Protocol dissector

	This module dissects packets used by SAP's Standalone Enqueue and
	Replication Servers.

- SAP RFC (Remote Function Call) Protocol dissector (experimental)

    This dissector perform some basic dissection on the main components of the 
    RFC protocol. It dissects general items and does some basic reassembling 
    and decompression of table contents.
    
- SAP SNC (Secure Network Connection) Protocol dissector (experimental)

	This dissector perform some basic parsing of SNC frames. 
    

Installation & Build
--------------------

This Wireshark plugin is not distributed as part of the Wireshark source. The 
following steps are required to compile the plugin:

1) Download Wireshark version 1.10 source from [7] or checkout the code from 
   the source repository [8].

2) Decompress the package.

3) Run the auto configuration script (`autogen.sh`) and compile the source.

4) Copy the SAP Wireshark Plugin to a new `plugins/sap` directory.

5) Windows Build: Add plugins/sap directory to `Makefile.nmake` and 
   `plugins/Makefile.am`.
   
   Non-Windows Build: Add `plugins/sap` directory to `Makefile.am`, `configure.in`
   and `plugins/Makefile.am`.
   
   This step can be performed using the patch file provided. At the root
   directory run:
   
	git apply plugins/sap/wireshark.patch

6) Compile and install as described in Wireshark `INSTALL` file.

It's worth mentioning that compression libraries for SAP Diag/RFC protocol are 
originally written in C++, thus the entire plugin needs to be compiled for C++. 
See Wireshark's portability notes for more information [9].

It was reported that compiling Wireshark on OS X requires fixing link for the
gettext library if it was installed using home-brew.


Example uses
------------

SAP Diag Gui Logon Password filter:

`DYNT_ATOM` items contains data entered into screen fields. The following filter 
could be used for identify the packets with filled fields, in search for 
interesting data. Early packets in a Diag session probably contains values for 
fields username and password.

	sapdiag.item.value.dyntatom.item.type == 130

The same results can be achieved also using expert info (security group):

	sapdiag and expert.group==security


License
-------

This Wireshark plugin is distributed under the GPLv2 license. Check the `COPYING`
file for more details.


References
----------

[1] http://www.sap.com/platform/netweaver/index.epx

[2] http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=SAP_Dissection_plu-gin_for_Wireshark

[3] http://www.coresecurity.com/content/sap-netweaver-dispatcher-multiple-vulnerabilities

[4] http://www.coresecurity.com/content/SAP-netweaver-msg-srv-multiple-vulnerabilities

[5] http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=publication&name=Uncovering_SAP_vulnerabilities

[6] http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=publication&name=saps_network_protocols_revisited

[7] http://www.wireshark.org/download.html

[8] https://code.wireshark.org/review/wireshark

[9] https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=doc/README.developer;hb=refs/heads/master-1.10


Contact
-------

Whether you want to report a bug or give some suggestions on this package, drop 
us a few lines at oss@coresecurity.com or contact the author email 
mgallo@coresecurity.com.
