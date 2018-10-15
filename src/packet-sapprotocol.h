/*
# ===========
# SAP Dissector Plugin for Wireshark
#
# Copyright (C) 2012-2018 by Martin Gallo, SecureAuth Corporation
#
# The plugin was designed and developed by Martin Gallo from
# SecureAuth Corporation's Labs team.
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
*/

#ifndef __PACKET_SAPPROTOCOL_H__
#define __PACKET_SAPPROTOCOL_H__

#include <epan/packet.h>

extern void
dissect_sap_protocol_payload(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, guint16 sport, guint16 dport);

#endif /* __PACKET_SAPPROTOCOL_H__ */
