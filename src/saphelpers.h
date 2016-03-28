/*
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
*/

#ifndef __PACKET_SAPHELPERS_H__
#define __PACKET_SAPHELPERS_H__

#include <epan/packet.h>

gboolean
check_length(packet_info *pinfo, proto_tree *tree, guint32 expected, guint32 real, const char *name_string);

guint8
add_item_value_uint8(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, const char *text);

guint16
add_item_value_uint16(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, const char *text);

guint32
add_item_value_uint32(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, const char *text);

void
add_item_value_string(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, guint32 length, const char *text, int show_in_tree);

guint32
add_item_value_stringz(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, const char *text, int show_in_tree);

void
add_item_value_hexstring(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, guint32 length, const char *text);

#endif  /* __PACKET_SAPHELPERS_H__ */
