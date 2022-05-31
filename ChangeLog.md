Changelog
=========

v0.10.1 - 2022-XX-XX
-------------------

- Switched to Wireshark 3.6 branch.
- `src/packet-saphdb.c`: Added missing `StatementContextOption` values ([\#22](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/issues/22)). Thanks [@nnnoel](https://github.com/nnnnoel)!
- `src/packet-saprfc.c`: Improve dissection of RFC message items and extended dissection of RFC tables ([\#23](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/issues/23)). Thanks [@biesigrr](https://github.com/biesigrr)!


v0.9.1 - 2021-01-25
-------------------

- Switched to Wireshark 3.4 branch.
- `src/packet-saphdb.c`: Added dissection of KRB5 tokens in GSS authentication.  
- `src/packet-saphdb.c`: Fixed type of options 51 and 52 in `CONNECTOPTIONS` part. Thanks [@jvis](https://twitter.com/jvis)!


v0.8.2 - 2020-07-15
-------------------

- Replaced AppVeyor and Travis builds with GitHub Actions.
- Added support for dissecting HANA SQL Command Network Protocol packets.
- `src/packet-sapdiag.c`: Fixed compiler warnings.
- `src/packet-saphdb.c`: New dissector for HDB protocol.
- `src/packet-sapigs.c`: Fixed compiler warnings.
- `src/packet-sapms.c`: Fixed compiler warnings.
- `src/packet-sapms.c`: Added a couple of Message Server fields based on Mathieu ([@gelim](https://github.com/gelim)) and Dmitry ([@_chipik](https://twitter.com/_chipik)) work on pysap. Thanks!
- `src/packet-saprouter.c`: Fixed compiler warnings.
- `src/packet-sapsnc.c`: Fixed compiler warnings.
- `tests/saphdb_test.py`: Basic unit test for validating dissection of HDB packet's header.


v0.8.1 - 2020-03-20
-------------------

- Switched to Wireshark 3.2 branch. Ported the plugin to the use of new APIs.
- Building with Visual Studio 2017 and QT 5.12 in AppVeyor builds.
- `src/packet-saprouter.c`: Improved conversation handling for route request/accept packets.


v0.7.1 - 2019-12-19
-------------------

- Switched to Wireshark 3.0 branch. Ported the plugin to the use of new APIs.
- `src/packet-sapdiag.c`: Added support bits for SAP Gui 7.50.


v0.6.1 - 2018-07-12
-------------------

- Switched to Wireshark 2.6 branch. Ported the plugin to the use of new APIs. ([\#16](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/issues/16))
- Building with Visual Studio 2015 and QT 5.9 in AppVeyor builds.
- Dropped support for automake-based builds.


v0.5.2 - 2018-03-17
-------------------

- Version released at Troopers'18
- Added support for dissecting the IGS protocol. Thanks Yvan Genuer ([@iggy38](https://github.com/iggy38))! ([\#14](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/issues/14))


v0.5.1 - 2017-10-24
-------------------

- Switched to Wireshark 2.4 branch. Ported the plugin to the use of new APIs.
- Building in OSX with Travis.
- `src/packet-sapsnc.c`: Minor changes based on checkAPI's findings.
- `src/packet-sapms.c`: Added Message Server Domain field. Thanks Albert Zedlitz!


v0.4.2 - 2017-06-30
-------------------
- Added initial support for dissecting SNC frames and some of their fields.
- `src/packet-sapdiag.c`: Dissection of SNC frames uses new helper functions.
- `src/packet-sapprotocol.c`: Clarified some column strings.
- `src/packet-saprouter.c`: Clarified some column strings.
- `src/packet-saprouter.c`: Added parsing of niping tool messages.
- `src/packet-saprouter.c`: Dissection of SNC frames uses new helper functions.
- `src/packet-sapsnc.c`: Added more fields as part of the SNC frame dissection.


v0.4.1 - 2016-12-30
-------------------

- Switched to Wireshark 2.2 trunk. Ported the plugin to the use of new APIs.
- Added Vagrant configuration files to build and run the plugin.
- Added provision and build scripts to use in both Travis and Vagrant build
  process.
- Building in Windows with Appveyor.
- `src/sapdecompress.cpp`: Removed use of value_string for decompression return code ([\#10](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/issues/10)).


v0.3.2 - 2016-10-21
-------------------

- ChangeLog file in Markdown format for better documentation.
- Improvements over the code, indent, removed warnings, etc. ([\#4](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/pull/4), [\#5](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/pull/5) and [\#6](https://github.com/SecureAuthCorp/SAP-Dissection-plug-in-for-Wireshark/pull/4)).
  Thanks [Alexis La Goutte](https://github.com/alagoutte)!
- `src/packet-sapdiag.c`: Partially dissecting `Info flag` Diag item.
- `src/packet-sapdiag.c`: Splitted `SBA`/`SFE`/`SLC` fields.
- `src/packet-sapdiag.c`: Parsing list focus item, list cell text value, renamed error flag to error number.
- `src/packet-sapdiag.c`: Added dissection of `Control Properties` item.


v0.3.1 - 2016-03-25
-------------------

- Switched to Wireshark 2.0 trunk. Ported the plugin to the use of new APIs.
- `src/packet-sapdiag.c`: Added support bits found in SAP GUI versions 7.20 patch level 9 and 7.40.


v0.2.3 - 2015-11-05
-------------------

- Minor documentation improvements.
- Fixed some issues in Windows builds.
- Added some basic unit test on dissecting SAP Router packets.
- `src/packet-saprouter.c`: Better tracking of conversations. Now it's possible to trace request response packets and
  see the route information if the packet trace included that information. Thanks Luca!
- `src/vpa108csulzh.cpp`: Improved the fix for CVE-2015-2278 by properly initializing arrays. Thanks [ret5ret](https://github.com/ret5ret)!


v0.2.2 - 2015-06-24
-------------------

- The plugin can be build as a standalone plugin. Thanks [Anton Bolshakov](https://github.com/blshkv)!


v0.2.1 - 2015-03-13
-------------------

- Switched to Wireshark 1.12 trunk. Ported the plugin to the use of new APIs (`wmem`, expert, etc.)
- Fixed vulnerabilities in `LZC` and `LZH` compression libraries ([CVE-2015-2282 and CVE-2015-2278](https://www.coresecurity.com/advisories/sap-lzc-lzh-compression-multiple-vulnerabilities)).
  Added test cases for checking proper fixes.
- Added basic packet parsing testing with travis, using `pyshark`. It allows to check that the plugin is built and
  loaded correctly.
- Moved to a layout with all source in `src` folder.
- Test building with clang on travis.
- `src/packet-saprouter.c`: Added unknown field to router error	messages.
- `src/packet-saprouter.c`: Changed scope of hostname/password strings allocations.


v0.1.5 - 2015-01-16
-------------------

- Added travis script for testing builds.
- Fixed compilation on OSX. Thanks Valeriy !
- General minor fixes and code improvements.
- `packet-sapdiag.c`: Added dissection of error messages, fixed parsing	of some atom items for old versions.
- `packet-sapdiag.c`: Better highlighting of all invisible fields as potential passwords. Fixed parsing of GUI patch
  level item for old versions. Thanks Victor for the feedback!
- `packet-sapenqueue.c`: Added dissection of admin trace requests.
- `packet-saprouter.c`: Added dissection of error fields. Route strings field are now search-able.
- `sapdecompress.h`: Improved routines and added handling of some error conditions.
- `saphelpers.h`: Fixed use of helpers on different dissectors.


v0.1.4 - 2014-03-25
-------------------

- Version released at Troopers'14.
- Changelog now in GNU format.
- Switched to Wireshark 1.10 trunk.
- Moved to the use of the new memory allocation API (`wmem`) on all dissectors.
- `packet-sapdiag.c`: Fixed some support bits and added new ones found on SAP GUI version 7.30.
- `packet-sapdiag.c`: Added dissection of new Diag Items: `WindowsSize`.
- `packet-sapenqueue.c`: New dissector. Parsing of Enqueue Server packets.
- `packet-sapms.c`: New dissector. Parsing of Message Server packets.
- `packet-sapprotocol.c`: Sub-dissectors tables are now handled only on the NI Protocol dissector.
- `packet-sapprotocol.h`: Exported function to look at the NI Protocol sub-dissector table.
- `packet-saprfc.c`: The RFC dissector now registers two separate handlers: one for internal calls (e.g. from SAP Diag
  dissector) and another for external communications (e.g. RFC or Gateway Monitor).
- `packet-saprfc.c`: Refactored almost all of the dissector code. Added lot of new fields and fixed some issues.
- `packet-saprfc.c`: Fixed reassemble of RFC tables.
- `packet-saprouter.c`: Added dissection of Admin and Control messages.
- `packet-saprouter.c`: Protocol port preference changed to a range to cover the port used by `niping`.
- `packet-sapsnc.c`: New dissector. Moved dissection of SNC frames to a new dissector for using it as sub-dissector of
  both SAP Router and SAP Diag packets.
- `sapdecompress.h`: Exported return code strings for using it in both Diag and RFC dissectors.
- `wireshark.patch`: Switched patch file to Git as the repository isn't updated on SVN now.


v0.1.3 - 2013-03-22
-------------------

- `packet-sapdiag.c`, `packet-saprfc.c`: Fixed compilations errors on RFC and Diag dissectors and removed some warnings.


v0.1.2 - 2012-09-27
-------------------

- Version released at Brucon'12.
- `packet-saprouter.c`: Fixed minor issues and added dissection of Admin requests. Thanks [Dave](https://twitter.com/nmonkee) for the
  feedback and reporting the issues.
- `packet-saprouter.c`: Route and Admin passwords are highlighted as Security via expert warnings.
- `packet-sapdiag.c`: Added dissection of new Diag Atom types, as used in NW 7.01 and early versions, and UI Events.
- `packet-sapdiag.c`: Added a preference setting for enabling highlighting of unknown Diag Item/Atom types and password
  fields via expert warnings.
- `packet-saprfc.c`: Added a preference setting for enabling highlighting of unknown RFC types via expert warnings.


v0.1.1 - 2012-07-29
-------------------

- Initial version released at Defcon 20.
