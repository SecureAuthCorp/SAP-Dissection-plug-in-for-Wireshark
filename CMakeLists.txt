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

project(sap-wireshark-plugin C CXX)

cmake_minimum_required(VERSION 2.6)
set(CMAKE_BACKWARDS_COMPATIBILITY 2.6)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake) 

find_package(Wireshark)

if(WIRESHARK_FOUND)

  MESSAGE(STATUS "Wireshark libraries found, performing a stand-alone plug-in build.") 

  if(NOT CMAKE_INSTALL_LIBDIR )
    set(CMAKE_INSTALL_LIBDIR ~/.wireshark/plugins)
  endif(NOT CMAKE_INSTALL_LIBDIR )
  MESSAGE(STATUS "Plug-in will be installed in: ${CMAKE_INSTALL_LIBDIR}")

  INCLUDE(UseMakeDissectorReg)

  set(GLIB2_MIN_VERSION 2.4.0)

  find_package(GLIB2)
  include_directories (${GLIB2_INCLUDE_DIRS})

  include_directories (${WIRESHARK_INCLUDE_DIRS})

  set(LINK_MODE_LIB SHARED)
  set(LINK_MODE_MODULE MODULE)

else(WIRESHARK_FOUND)

  MESSAGE(STATUS "Wireshark libraries not found, performing a Wireshark plug-in build.") 

  include(WiresharkPlugin)
  set_module_info(sap 0 3 2 0)

endif(WIRESHARK_FOUND)

set(DISSECTOR_SRC
	src/packet-sapdiag.c
	src/packet-sapenqueue.c
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

if (WERROR)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS -Werror
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_dissector_files(plugin.c
	plugin
	${DISSECTOR_SRC}
        ${DISSECTOR_SUPPORT_SRC}
)

if(WIRESHARK_FOUND)

  add_library(sap ${LINK_MODE_MODULE}
                  ${PLUGIN_FILES}
  )

  set_target_properties(sap PROPERTIES PREFIX "")
  set_target_properties(sap PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

  target_link_libraries(sap wireshark)

  install(TARGETS sap
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} NAMELINK_SKIP
          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  )

else(WIRESHARK_FOUND)

  add_plugin_library(sap)

  install(TARGETS sap
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
          RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/${CPACK_PACKAGE_NAME}/plugins/${CPACK_PACKAGE_VERSION}
  )

endif(WIRESHARK_FOUND)

