# Locate the Wireshark library.
#
# This file is meant to be copied into projects that want to use Wireshark.
# It will search for WiresharkConfig.cmake, which ships with Wireshark
# and will provide up-to-date buildsystem changes. Thus there should not be
# any need to update FindWiresharkVc.cmake again after you integrated it into
# your project.
#
# This module defines the following variables:
# Wireshark_FOUND
# Wireshark_VERSION_MAJOR
# Wireshark_VERSION_MINOR
# Wireshark_VERSION_PATCH
# Wireshark_VERSION
# Wireshark_VERSION_STRING
# Wireshark_INSTALL_DIR
# Wireshark_PLUGIN_INSTALL_DIR
# Wireshark_LIB_DIR
# Wireshark_LIBRARY
# Wireshark_INCLUDE_DIR
# Wireshark_CMAKE_MODULES_DIR

find_package(Wireshark ${Wireshark_FIND_VERSION} QUIET NO_MODULE PATHS $ENV{HOME} /opt/Wireshark)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Wireshark CONFIG_MODE)

MESSAGE(STATUS "Wireshark_FOUND: ${Wireshark_FOUND}")
MESSAGE(STATUS "Wireshark_VERSION_MAJOR: ${Wireshark_VERSION_MAJOR}")
MESSAGE(STATUS "Wireshark_VERSION_MINOR: ${Wireshark_VERSION_MINOR}")
MESSAGE(STATUS "Wireshark_VERSION_PATCH: ${Wireshark_VERSION_PATCH}")
MESSAGE(STATUS "Wireshark_VERSION: ${Wireshark_VERSION}")
MESSAGE(STATUS "Wireshark_VERSION_STRING: ${Wireshark_VERSION_STRING}")
MESSAGE(STATUS "Wireshark_INSTALL_DIR: ${Wireshark_INSTALL_DIR}")
MESSAGE(STATUS "Wireshark_PLUGIN_INSTALL_DIR: ${Wireshark_PLUGIN_INSTALL_DIR}")
MESSAGE(STATUS "Wireshark_LIB_DIR: ${Wireshark_LIB_DIR}")
MESSAGE(STATUS "Wireshark_LIBRARY: ${Wireshark_LIBRARY}")
MESSAGE(STATUS "Wireshark_INCLUDE_DIR: ${Wireshark_INCLUDE_DIR}")
MESSAGE(STATUS "Wireshark_CMAKE_MODULES_DIR: ${Wireshark_CMAKE_MODULES_DIR}")