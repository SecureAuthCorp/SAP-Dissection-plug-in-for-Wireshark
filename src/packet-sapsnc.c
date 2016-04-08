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

#include "config.h"

#include <epan/packet.h>


static int proto_sapsnc = -1;

/* SNC Frame */
static int hf_sapsnc_frame = -1;
static int hf_sapsnc_eye_catcher = -1;
static int hf_sapsnc_token_length = -1;
static int hf_sapsnc_data_length = -1;
static int hf_sapsnc_flags = -1;
static int hf_sapsnc_extflags = -1;
static int hf_sapsnc_token = -1;
static int hf_sapsnc_data = -1;

static gint ett_sapsnc = -1;

/* Protocol handle */
static dissector_handle_t sapsnc_handle;

void proto_reg_handoff_sapsnc(void);


static void
dissect_sapsnc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, ", SAPSNC");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	if (tree) { /* we are being asked for details */

		guint32 offset = 0;
		proto_item *sapsnc = NULL, *sapsnc_frame = NULL;
		proto_tree *sapsnc_tree = NULL, *sapsnc_frame_tree = NULL;

		/* Add the main SNC subtree */
		sapsnc = proto_tree_add_item(tree, proto_sapsnc, tvb, offset, -1, ENC_NA);
		sapsnc_tree = proto_item_add_subtree(sapsnc, ett_sapsnc);

		/* Add the SNC Frame subtree */
		sapsnc_frame = proto_tree_add_item(sapsnc_tree, hf_sapsnc_frame, tvb, offset, -1, ENC_NA);
		sapsnc_frame_tree = proto_item_add_subtree(sapsnc_frame, ett_sapsnc);

		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_eye_catcher, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
		offset+=4; /* First 4 bytes (Flags ?) */
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_token_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_data_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
		offset+=2; /* 2 Bytes */
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_flags, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_extflags, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;

	}
}

void
proto_register_sapsnc(void)
{
	static hf_register_info hf[] = {
		/* SNC Frame */
		{ &hf_sapsnc_frame,
			{ "SNC Frame", "sapsnc.frame", FT_NONE, BASE_NONE, NULL, 0x0, "SAP SNC Frame", HFILL }},
		{ &hf_sapsnc_eye_catcher,
			{ "SNC Eye Catcher", "sapsnc.eyecatcher", FT_STRING, BASE_NONE, NULL, 0x0, "SAP SNC Eye Catcher", HFILL }},
		{ &hf_sapsnc_token_length,
			{ "SNC Token length", "sapsnc.frame.tokenlength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP SNC Token Length", HFILL }},
		{ &hf_sapsnc_data_length,
			{ "SNC Data length", "sapsnc.frame.datalength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP SNC Data Length", HFILL }},
		{ &hf_sapsnc_flags,
			{ "SNC Flags", "sapsnc.frame.flags", FT_UINT16, BASE_HEX, NULL, 0x0, "SAP SNC Flags", HFILL }},
		{ &hf_sapsnc_extflags,
			{ "SNC Flags", "sapsnc.frame.extflags", FT_UINT32, BASE_HEX, NULL, 0x0, "SAP SNC Ext Flags", HFILL }},
		{ &hf_sapsnc_token,
			{ "SNC Token", "sapsnc.frame.token", FT_NONE, BASE_NONE, NULL, 0x0, "SAP SNC Token", HFILL }},
		{ &hf_sapsnc_data,
			{ "SNC Data", "sapsnc.frame.data", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP SNC Data", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sapsnc
	};

	/* Register the protocol */
	proto_sapsnc = proto_register_protocol("SAP SNC Protocol", "SAPSNC", "sapsnc");

	proto_register_field_array(proto_sapsnc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("sapsnc", dissect_sapsnc, proto_sapsnc);

}


/**
 * Register Hand off for the SAP SNC Protocol
 */
void
proto_reg_handoff_sapsnc(void)
{
	static gboolean initialized = FALSE;

	if (!initialized) {
		sapsnc_handle = create_dissector_handle(dissect_sapsnc, proto_sapsnc);
		initialized = TRUE;
	}

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
