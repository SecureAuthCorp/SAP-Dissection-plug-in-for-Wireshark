# Makefile.am
#
# Automake file for SAP Dissector Plugin for Wireshark
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
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
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


include $(top_srcdir)/Makefile.am.inc
include $(top_srcdir)/plugins/epan/Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = sap

PLUGIN_VERSION = 0.6.1

# the dissector sources (without any helpers)
DISSECTOR_SRC = \
	src/packet-sapdiag.c \
	src/packet-sapenqueue.c \
	src/packet-sapigs.c \
	src/packet-saprouter.c \
	src/packet-sapprotocol.c \
	src/packet-saprfc.c \
	src/packet-sapms.c \
	src/packet-sapsnc.c

# corresponding headers
DISSECTOR_INCLUDES = \
	src/packet-sapprotocol.h

# Dissector helpers. They're included in the source files in this
# directory, but they're not dissectors themselves, i.e. they're not
# used to generate "plugin.c".
DISSECTOR_SUPPORT_SRC = \
	src/sapdecompress.cpp \
	src/vpa105CsObjInt.cpp \
	src/vpa106cslzc.cpp \
	src/vpa107cslzh.cpp \
	src/vpa108csulzh.cpp

if HAVE_WARNINGS_AS_ERRORS
AM_CFLAGS = -Werror
endif

plugindir = @plugindir@

epan_plugin_LTLIBRARIES = sap.la

sap_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(DISSECTOR_SRC) \
	$(DISSECTOR_SUPPORT_SRC) \
	$(DISSECTOR_INCLUDES)

sap_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

sap_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

sap_la_LDFLAGS = $(PLUGIN_LDFLAGS)

sap_la_LIBADD = @PLUGIN_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS =

#
# Build plugin.c, which contains the plugin version[] string, a
# function plugin_register() that calls the register routines for all
# protocols, and a function plugin_reg_handoff() that calls the handoff
# registration routines for all protocols.
#
# We do this by scanning sources.  If that turns out to be too slow,
# maybe we could just require every .o file to have an register routine
# of a given name (packet-aarp.o -> proto_register_aarp, etc.).
#
# Formatting conventions:  The name of the proto_register_* routines an
# proto_reg_handoff_* routines must start in column zero, or must be
# preceded only by "void " starting in column zero, and must not be
# inside #if.
#
# REGISTER_SRC_FILES is assumed to have all the files that need to be scanned.
#
# For some unknown reason, having a big "for" loop in the Makefile
# to scan all the files doesn't work with some "make"s; they seem to
# pass only the first few names in the list to the shell, for some
# reason.
#
# Therefore, we use a script to generate the register.c file.
# The first argument is the directory in which the source files live.
# The second argument is "plugin", to indicate that we should build
# a plugin.c file for a plugin.
# All subsequent arguments are the files to scan.
#
plugin.c: $(DISSECTOR_SRC) $(top_srcdir)/tools/make-dissector-reg \
    $(top_srcdir)/tools/make-dissector-reg.py
	@if test -n "$(PYTHON)"; then \
		echo Making plugin.c with python ; \
		$(PYTHON) $(top_srcdir)/tools/make-dissector-reg.py $(srcdir) \
		    plugin $(DISSECTOR_SRC) ; \
	else \
		echo Making plugin.c with shell script ; \
		$(top_srcdir)/tools/make-dissector-reg $(srcdir) \
		    $(plugin_src) plugin $(DISSECTOR_SRC) ; \
	fi

#
# Currently plugin.c can be included in the distribution because
# we always build all protocol dissectors. We used to have to check
# whether or not to build the snmp dissector. If we again need to
# variably build something, making plugin.c non-portable, uncomment
# the dist-hook line below.
#
# Oh, yuk.  We don't want to include "plugin.c" in the distribution, as
# its contents depend on the configuration, and therefore we want it
# to be built when the first "make" is done; however, Automake insists
# on putting *all* source into the distribution.
#
# We work around this by having a "dist-hook" rule that deletes
# "plugin.c", so that "dist" won't pick it up.
#
#dist-hook:
#	@rm -f $(distdir)/plugin.c

CLEANFILES = \
	sap \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	\
	plugin.c

EXTRA_DIST = \
	plugin.rc.in		\
	CMakeLists.txt

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(CLEAN_SRC_FILES) $(CLEAN_HEADER_FILES)
