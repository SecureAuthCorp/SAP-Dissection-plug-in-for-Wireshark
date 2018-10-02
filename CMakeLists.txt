# ===========
# SAP Dissector Plugin for Wireshark
#
# Copyright (C) 2012-2018 by Martin Gallo, Core Security
#
# The plugin was designed and developed by Martin Gallo from
# Core Security's CoreLabs team.
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

project(sap-wireshark-plugin C CXX)

cmake_minimum_required(VERSION 2.6)
set(CMAKE_BACKWARDS_COMPATIBILITY 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Wireshark)

if(Wireshark_FOUND AND Wireshark_VERSION_MAJOR EQUAL 2 AND Wireshark_VERSION_MINOR EQUAL 6)

  MESSAGE(STATUS "Wireshark 2.6 libraries found, performing a stand-alone plug-in build.")

  if(NOT CMAKE_INSTALL_LIBDIR )
    set(CMAKE_INSTALL_LIBDIR ~/.local/lib/wireshark/plugins/${Wireshark_VERSION_MAJOR}.${Wireshark_VERSION_MINOR}/epan)
  endif(NOT CMAKE_INSTALL_LIBDIR )
  MESSAGE(STATUS "Plug-in will be installed in: ${CMAKE_INSTALL_LIBDIR}")

  INCLUDE(UseMakePluginReg)

  set(GLIB2_MIN_VERSION 2.4.0)

  find_package(GLIB2)
  include_directories (${GLIB2_INCLUDE_DIRS})

  include_directories (${Wireshark_INCLUDE_DIR})

  set(LINK_MODE_LIB SHARED)
  set(LINK_MODE_MODULE MODULE)

  # Plugin name and version info (major minor micro)
  set(PLUGIN_VERSION "0.6.2")
  add_definitions(-DPLUGIN_VERSION=\"${PLUGIN_VERSION}\")

else(Wireshark_FOUND AND Wireshark_VERSION_MAJOR EQUAL 2 AND Wireshark_VERSION_MINOR EQUAL 6)

  MESSAGE(STATUS "Wireshark 2.6 libraries not found, performing an in-tree Wireshark plug-in build.")

  include(WiresharkPlugin)

  # Plugin name and version info (major minor micro extra)
  set_module_info(sap 0 6 2 0)

endif(Wireshark_FOUND AND Wireshark_VERSION_MAJOR EQUAL 2 AND Wireshark_VERSION_MINOR EQUAL 6)

set(DISSECTOR_SRC
	src/packet-sapdiag.c
	src/packet-sapenqueue.c
	src/packet-sapigs.c
	src/packet-saprouter.c
	src/packet-sapprotocol.c
	src/packet-saprfc.c
	src/packet-sapms.c
	src/packet-sapsnc.c
)

set(DISSECTOR_SUPPORT_SRC
	src/sapdecompress.cpp
	src/vpa105CsObjInt.cpp
	src/vpa106cslzc.cpp
	src/vpa107cslzh.cpp
	src/vpa108csulzh.cpp
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

set_source_files_properties(
	${CLEAN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
  ${DISSECTOR_SUPPORT_SRC}
)

if(Wireshark_FOUND AND Wireshark_VERSION_MAJOR EQUAL 2 AND Wireshark_VERSION_MINOR EQUAL 6)

  add_library(sap ${LINK_MODE_MODULE}
                  ${PLUGIN_FILES}
                  ${PLUGIN_RC_FILE}
  )

  set_target_properties(sap PROPERTIES
          PREFIX ""
          LINK_FLAGS "${WS_LINK_FLAGS}"
          FOLDER "Plugins"
  )

  target_link_libraries(sap wireshark)

  install(TARGETS sap
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

else(Wireshark_FOUND AND Wireshark_VERSION_MAJOR EQUAL 2 AND Wireshark_VERSION_MINOR EQUAL 6)

  add_plugin_library(sap epan)

  target_link_libraries(sap epan)

  install_plugin(sap epan)

  file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
  CHECKAPI(
  	NAME
  	  sap
  	SWITCHES
  	  -g abort -g termoutput -build
  	SOURCES
  	  ${DISSECTOR_SRC}
  	  ${DISSECTOR_HEADERS}
  )

endif(Wireshark_FOUND AND Wireshark_VERSION_MAJOR EQUAL 2 AND Wireshark_VERSION_MINOR EQUAL 6)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
