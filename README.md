SAP Dissector Plugin for Wireshark
==================================

[![Build Status](https://travis-ci.org/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark.svg?branch=master-0.7)](https://travis-ci.org/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark)
[![Build status](https://ci.appveyor.com/api/projects/status/x6emndcoufys3iro?svg=true)](https://ci.appveyor.com/project/CoreSecurity/sap-dissection-plug-in-for-wireshark)

SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.

Version 0.7.1.dev (XXX 2019)


Overview
--------

[SAP Netweaver](https://www.sap.com/platform/netweaver/index.epx) [1] and
[SAP HANA](https://www.sap.com/products/hana.html) [2] are technology platforms for
building and integrating SAP business applications. Communication between components
uses different network protocols. While some of them are standard and well-known
protocols, others are proprietaries and public information is not available.

This [Wireshark](https://www.wireshark.org/) [3] plugin provides dissection
of SAP's NI, Message Server, Router, Diag, Enqueue, IGS and SNC protocols. The
dissectors are based on information acquired at researching the different
protocols and services. Additional experimental support is included for SAP's
RFC protocol. Detailed information about the research can be found at [4],
[5], [6], [7] and [8].


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

- SAP SNC (Secure Network Connection) Protocol dissector

	This dissector parses SNC frames and their fields. When the frames contains
	wrapped data that wasn't encrypted, it allows calling dissectors to get
	access to the unwrapped data for further dissecting it, as the case of Diag
	dissector when SNC is used in authentication only or integrity protection
	quality of protection levels.

- SAP IGS (Internet Graphic Server) Protocol dissector

  This dissector parses packets used by SAP's IGS services.

- SAP RFC (Remote Function Call) Protocol dissector (experimental)

  This dissector perform some basic dissection on the main components of the
  RFC protocol. It dissects general items and does some basic reassembling
  and decompression of table contents.


Installation & Build
--------------------

This Wireshark plugin is not distributed as part of the Wireshark source. It
can be build as a standalone plugin, or as part of Wireshark, and is compatible
with version 3.0.

### Installing on Linux ###

#### As a standalone plugin ####

To build and install the plugin on Debian/Ubuntu linux distributions:

    sudo add-apt-repository ppa:wireshark-dev/stable -y
    sudo apt-get update
    sudo apt-get install wireshark wireshark-dev
    git clone https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/
    cd SAP-Dissection-plug-in-for-Wireshark/
    mkdir build
    cd build
    cmake ..
    make
    make install

#### As part of Wireshark ####

The following steps are required to build and install the plugin as part of Wireshark:

1) Download and decompress the [Wireshark version 3.0 source](https://www.wireshark.org/download.html) [9]
   or checkout the code from the [source repository](https://code.wireshark.org/review/wireshark) [10].

    git clone https://code.wireshark.org/review/wireshark
    cd wireshark
    git checkout master-3.0

2) Copy the SAP Wireshark Plugin to a new `plugins/epan/sap` directory.

    git clone https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/ plugins/epan/sap

3) Configure the plugin to be included in the build process. This step can be
   performed using the patch file provided. At the root directory run:

    git apply plugins/epan/sap/wireshark-master-3.0.patch

4) Perform a new build including the plugin. At the root directory run:

    mkdir -p build
    cd build
    cmake ..
    make
    make install


#### Using Vagrant ####

[Vagrant](https://www.vagrantup.com/) is a Virtual Machine management software
that allows creating reproducible virtual machines. In order to make it easier
to compile and test the plugin, a pre-configured Vagrantfile is provided for
using it with Vagrant 1.8. The Vagrantfile provided with the plugin is configured
to use [VirtualBox](https://www.virtualbox.org/) and perform a build of the
plugin inside a Ubuntu 18.04 distribution.

Two machines are provided to build the plugin:

* `source`: for building the plugin as part of Wireshark.
* `standalone`: for building the plugin as a standalone plugin.

The following steps can be used to setup a Vagrant machine and build the plugin:

1) Install VirtualBox and Vagrant 1.8 or greater.

    sudo apt-get install virtualbox vagrant

2) Inside the plugin's directory, launch the desired Vagrant machine, in this
case `standalone`:

    vagrant up standalone

3) Login into the Vagrant machine and run Wireshark:

    vagrant ssh standalone
    wireshark


### Installing on Windows ###

Windows build can be only performed as part of the whole Wireshark. The
following steps are required to compile the plugin on Windows:

1) Follow the [step-to-step guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html) [11]
for building Wireshark on Windows.

2) Copy the SAP Wireshark Plugin to a new `plugins/epan/sap` directory.

3) Configure the plugin to be included in the build process. This step can be
   performed using the patch file provided. At the root directory run:

    git apply plugins/epan/sap/wireshark-master-3.0.patch

4) Perform a new build including the plugin.


### Installing on OSX ###

The build process for OSX is similar to the one for Linux systems. It was
reported that compiling Wireshark on OSX requires fixing link for the `gettext`
library if it was installed using `home-brew`.


### Penetration testing distribution and frameworks ###

The plugin is available for installation on several penetration testing
distributions and frameworks.

#### Installing on Pentoo ####

Installation on the [Pentoo](http://www.pentoo.ch/) livecd distribution:

	emerge net-misc/wireshark-sap-plugin

#### Installing with The PenTesters Framework (PTF) ####

Installation on Debian, Ubuntu and ArchLinux can be performed using
[The PenTesters Framework (PTF)](https://github.com/trustedsec/ptf). From inside
the `ptf` command-line, run:

  use modules/intelligence-gathering/sap-wireshark-plugin
  install


### Additional notes ###

It's worth mentioning that compression libraries for SAP Diag/RFC protocol are
originally written in C++, thus the entire plugin needs to be compiled for C++.
See [Wireshark's portability notes](https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=doc/README.developer;hb=refs/heads/master-3.0)
for more information [12].


Usage
-----

### Traffic dissection ###

After the plugin is installed, it will automatically dissect SAP protocols'
traffic if using default ports. If required, ports can be modified on SAP NI
protocol as well as sub-dissectors' preferences.

![SAP NI preferences](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/raw/master/docs/sapni_preferences.png "SAP NI preferences")

![SAP Diag preferences](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/raw/master/docs/sapdiag_preferences.png "SAP Diag preferences")


### SAP Diag Gui Logon Password filter ###

`DYNT_ATOM` items contains data entered into screen fields. The following
filter could be used for identifying packets containing fields marked as
"invisible" (fields that are masked in the SAP GUI screen) in search for
sensitive data. Early packets in a Diag session probably contains values for
user id and password fields.

	sapdiag.item.value.dyntatom.item.attr.INVISIBLE == 1

The same results can be achieved also using expert info (security group):

	sapdiag.item.value.dyntatom.item.password

![SAP Diag login password](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/raw/master/docs/sapdiag_login_password.png "SAP Diag login password")


License
-------

This Wireshark plugin is distributed under the GPLv2 license. Check the `COPYING`
file for more details.


Authors
-------

The library was designed and developed by Martin Gallo from
SecureAuth Labs team.

### Contributors ###

Contributions made by:

  * Joris van de Vis ([@jvis](https://twitter.com/jvis))
  * Anton Bolshakov ([@blshkv](https://github.com/blshkv))
  * Valeriy Gusev
  * Daniel Berlin ([@daberlin](https://github.com/daberlin))
  * Victor Portal Gonzalez
  * Dave Hartley ([@nmonkee](https://twitter.com/nmonkee))
  * Jean-Paul Roliers
  * Dongha Shin
  * Luca Di Stefano
  * Alexis La Goutte ([@alagoutte](https://github.com/alagoutte))
  * Yvan Genuer ([@iggy38](https://github.com/iggy38))
  * Mathieu Geli ([@gelim](https://github.com/gelim)))


References
----------

[1] https://www.sap.com/platform/netweaver/index.epx

[2] https://www.sap.com/products/hana.html

[3] https://www.wireshark.org/

[4] https://www.secureauth.com/labs/open-source-tools/sap-dissection-plug-wireshark

[5] https://www.secureauth.com/labs/advisories/sap-netweaver-dispatcher-multiple-vulnerabilities

[6] https://www.secureauth.com/labs/advisories/SAP-netweaver-msg-srv-multiple-vulnerabilities

[7] https://www.secureauth.com/labs/publications/uncovering-sap-vulnerabilities-reversing-and-breaking-diag-protocol

[8] https://www.secureauth.com/labs/publications/sap-network-protocols-revisited

[9] https://www.wireshark.org/download.html

[10] https://code.wireshark.org/review/wireshark

[11] https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=doc/README.developer;hb=refs/heads/master-3.0

[12] https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html


Contact
-------

Whether you want to report a bug or give some suggestions on this package, drop
us a few lines at `oss@secureauth.com` or contact the author email
`mgallo@secureauth.com`.
