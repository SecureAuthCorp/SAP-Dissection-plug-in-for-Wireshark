SAP Dissector Plugin for Wireshark
==================================

[![Build Status](https://travis-ci.org/CoreSecurity/SAP-Dissection-plug-in-for-Wireshark.svg?branch=master)](https://travis-ci.org/CoreSecurity/SAP-Dissection-plug-in-for-Wireshark)

Copyright (C) 2012-2016 by Martin Gallo, Core Security

Version 0.3.2.dev (XXX 2016)


Overview
--------

[SAP Netweaver](https://www.sap.com/platform/netweaver/index.epx) [1] is a
technology platform for building and integrating SAP business applications.
Communication between components uses different network protocols. While
some of them are standard and well-known protocols, others are proprietaries
and public information is not available.

This [Wireshark](https://www.wireshark.org/) [2] plugin  provides dissection
of SAP's NI, Message Server, Router, Diag and Enqueue protocols. The
dissectors are based on information acquired at researching the different
protocols and services. Additional experimental support is included for SAP's
RFC and SNC protocols. Detailed information about the research can be found
at [3], [4], [5], [6] and [7].


Features
--------

This plugin counts on several different dissectors:

- SAP NI Protocol dissector

    This is the dissector for SAP's Network Interface (NI) protocol. The
    dissector handles the reassemble of fragmented TCP packets and identifies
    keep-alive messages (`PING`/`PONG`). It also calls the respective
    sub-dissector according to the port being used.

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

    This module dissects the packets used by SAP's Message Server Protocol in
    its binary non-HTTP format, for both internal and external ports.

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

This Wireshark plugin is not distributed as part of the Wireshark source. It
can be build as a standalone plugin, or as part of Wireshark, and is compatible
with version 2.0.

### Building on Linux ###

#### As a standalone plugin ####

To build the plugin on Debian/Ubuntu linux distributions:

    sudo apt-get install wireshark wireshark-dev
    mkdir build
    cd build
    cmake ..
    make
    make install

#### As part of Wireshark ####

The following steps are required to compile the plugin as part of Wireshark:

1) Download [Wireshark version 2.0 source](https://www.wireshark.org/download.html) [8]
   or checkout the code from the [source repository](https://code.wireshark.org/review/wireshark) [9].

2) Decompress the package.

3) Configure and build the package, as described in [Wireshark's development
   guide](https://www.wireshark.org/docs/wsdg_html_chunked/) [10].

4) Copy the SAP Wireshark Plugin to a new `plugins/sap` directory.

5) Configure the plugin to be included in the build process. This step can be
   performed using the patch file provided. At the root directory run:

	git apply plugins/sap/wireshark-master-2.0.patch

6) Perform a new build including the plugin. At the root directory run:

    mkdir build
    cd build
    cmake ..
    make
    make install


### Building on Windows ###

Windows build can be only performed as part of the whole Wireshark. The
following steps are required to compile the plugin on Windows:

1) Follow the [step-to-step guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html)
for building Wireshark on Windows [12].

2) Copy the SAP Wireshark Plugin to a new `plugins/sap` directory.

3) Configure the plugin to be included in the build process. This step can be
   performed using the patch file provided. At the root directory run:

	git apply plugins/sap/wireshark-master-2.0.patch

4) Perform a new build including the plugin.


### Building on OSX ###

The build process for OSX is similar to the one for Linux systems. It was
reported that compiling Wireshark on OSX requires fixing link for the `gettext`
library if it was installed using `home-brew`.


### Additional notes ###

It's worth mentioning that compression libraries for SAP Diag/RFC protocol are
originally written in C++, thus the entire plugin needs to be compiled for C++.
See [Wireshark's portability notes](https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=doc/README.developer;hb=refs/heads/master-2.0)
for more information [11].


Example uses
------------

SAP Diag Gui Logon Password filter:

`DYNT_ATOM` items contains data entered into screen fields. The following
filter could be used for identifying packets containing fields marked as
"invisible" (fields that are masked in the SAP GUI screen) in search for
sensitive data. Early packets in a Diag session probably contains values for
user id and password fields.

	sapdiag.item.value.dyntatom.item.attr.INVISIBLE == 1

The same results can be achieved also using expert info (security group):

	sapdiag.item.value.dyntatom.item.password


License
-------

This Wireshark plugin is distributed under the GPLv2 license. Check the `COPYING`
file for more details.


Authors
-------

The library was designed and developed by Martin Gallo from the Security
Consulting Services team of Core Security.

### Contributors ###

Contributions made by:

  * Joris van de Vis
  * Anton Bolshakov
  * Valeriy Gusev
  * Daniel Berlin
  * Victor Portal Gonzalez
  * Dave Hartley
  * Jean-Paul Roliers
  * Dongha Shin
  * Luca Di Stefano


References
----------

[1] https://www.sap.com/platform/netweaver/index.epx

[2] https://www.wireshark.org/

[3] https://www.coresecurity.com/corelabs-research/open-source-tools/sap-dissection-plug-in-wireshark

[4] https://www.coresecurity.com/content/sap-netweaver-dispatcher-multiple-vulnerabilities

[5] https://www.coresecurity.com/content/SAP-netweaver-msg-srv-multiple-vulnerabilities

[6] https://www.coresecurity.com/corelabs-research/publications/uncovering-sap-vulnerabilities-reversing-and-breaking-diag-protocol-brucon2012

[7] https://www.coresecurity.com/corelabs-research/publications/sap-network-protocols-revisited

[8] https://www.wireshark.org/download.html

[9] https://code.wireshark.org/review/wireshark

[10] https://www.wireshark.org/docs/wsdg_html_chunked/

[11] https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=doc/README.developer;hb=refs/heads/master-1.12

[12] https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html

Contact
-------

Whether you want to report a bug or give some suggestions on this package, drop
us a few lines at `oss@coresecurity.com` or contact the author email
`mgallo@coresecurity.com`.
