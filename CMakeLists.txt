# ===========
# SAP Dissector Plugin for Wireshark
#
# Copyright (C) 2015 Core Security Technologies
#
# The plugin was designed and developed by Martin Gallo from the Security
# Consulting Services team of Core Security Technologies.
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

set(DISSECTOR_SRC
	packet-sapdiag.c
	packet-sapenqueue.c
	packet-saprouter.c
	packet-sapprotocol.c
	packet-saprfc.c
    packet-sapms.c
    packet-sapsnc.c
)

set(DISSECTOR_SUPPORT_SRC
	sapdecompress.cpp
	vpa105CsObjInt.cpp
	vpa106cslzc.cpp
	vpa107cslzh.cpp
	vpa108csulzh.cpp
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
)

add_library(sap ${LINK_MODE_MODULE}
	${PLUGIN_FILES}
)
set_target_properties(sap PROPERTIES PREFIX "")
set_target_properties(sap PROPERTIES LINK_FLAGS "${WS_LINK_FLAGS}")

target_link_libraries(sap epan)

install(TARGETS sap
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION} NAMELINK_SKIP
	RUNTIME DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/@CPACK_PACKAGE_NAME@/plugins/${CPACK_PACKAGE_VERSION}
)

