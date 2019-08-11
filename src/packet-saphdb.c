/*
# ===========
# SAP Dissector Plugin for Wireshark
#
# SECUREAUTH LABS. Copyright (C) 2019 SecureAuth Corporation. All rights reserved.
#
# The plugin was designed and developed by Martin Gallo from
# SecureAuth Labs team.
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
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>


/* Define default ports */
#define SAPHDB_PORT_RANGE "30013-39913,30015-39915"


static int proto_saphdb = -1;

/* SAP HDB Message Header items */
static int hf_saphdb_message_header = -1;
static int hf_saphdb_message_header_sessionid = -1;
static int hf_saphdb_message_header_packetcount = -1;
static int hf_saphdb_message_header_varpartlength = -1;
static int hf_saphdb_message_header_varpartsize = -1;
static int hf_saphdb_message_header_noofsegm = -1;
static int hf_saphdb_message_header_packetoptions = -1;
static int hf_saphdb_message_header_compressionvarpartlength = -1;


static gint ett_saphdb = -1;


/* Global port preference */
static range_t *global_saphdb_port_range;


/* Protocol handle */
static dissector_handle_t saphdb_handle;

void proto_reg_handoff_saphdb(void);


static int
dissect_saphdb_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint32 offset)
{
	guint32 length = 0;

	return length;
}


static int
dissect_saphdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPHDB");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

  /* we are being asked for details and the length is sufficient at least for the header */
	if (tree && tvb_reported_length(tvb) >= 32) {

		guint16 noofsegm = 0, segm = 0;  // This should be gint16
		guint32 offset = 0;
		guint32 varpartlength = 0, varpartsize = 0;  // This should be gint32
		proto_item *ti = NULL, *saphdb_message_header = NULL;
		proto_tree *saphdb_tree = NULL, *saphdb_message_header_tree = NULL;

		/* Add the main saphdb subtree */
		ti = proto_tree_add_item(tree, proto_saphdb, tvb, 0, -1, ENC_NA);
		saphdb_tree = proto_item_add_subtree(ti, ett_saphdb);

		/* Add the Message Header subtree */
		saphdb_message_header = proto_tree_add_item(saphdb_tree, hf_saphdb_message_header, tvb, offset, 32, ENC_NA);
		saphdb_message_header_tree = proto_item_add_subtree(saphdb_message_header, ett_saphdb);

		/* Add the Message Header fields */
		proto_tree_add_item(saphdb_message_header_tree, hf_saphdb_message_header_sessionid, tvb, offset, 8, ENC_LITTLE_ENDIAN); offset += 8;
		proto_tree_add_item(saphdb_message_header_tree, hf_saphdb_message_header_packetcount, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
		varpartlength = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(saphdb_message_header_tree, hf_saphdb_message_header_varpartlength, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
		proto_tree_add_item(saphdb_message_header_tree, hf_saphdb_message_header_varpartsize, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
		noofsegm = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(saphdb_message_header_tree, hf_saphdb_message_header_noofsegm, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
		proto_tree_add_item(saphdb_message_header_tree, hf_saphdb_message_header_packetoptions, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1;
		offset += 1;  /* Reserved1 field */
		proto_tree_add_item(saphdb_message_header_tree, hf_saphdb_message_header_compressionvarpartlength, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
		offset += 4;  /* Reserved2 field */

		if (tvb_reported_length_remaining(tvb, offset) != varpartlength) {
			/* TODO: Expert report as the length is incorrect */
			varpartlength = tvb_reported_length_remaining(tvb, offset);
		}

		/* Iterate over the segments and dissect them */
		for (segm = 0; segm < noofsegm && tvb_reported_length_remaining(tvb, offset) >= 13; segm++) {
			guint32 segm_length = 0;

			segm_length = dissect_saphdb_segment(tvb, pinfo, tree, NULL, offset);

			offset += segm_length;
		}

	}

	return tvb_reported_length(tvb);
}

void
proto_register_saphdb(void)
{
	static hf_register_info hf[] = {
		/* Message Header items */
		{ &hf_saphdb_message_header,
			{ "Message Header", "saphdb.message_header", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Message Header", HFILL }},
		{ &hf_saphdb_message_header_sessionid,
			{ "Session ID", "saphdb.message_header.sessionid", FT_INT64, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Session ID", HFILL }},
		{ &hf_saphdb_message_header_packetcount,
			{ "Packet Count", "saphdb.message_header.packetcount", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Packet Count", HFILL }},
		{ &hf_saphdb_message_header_varpartlength,
			{ "Var Part Length", "saphdb.message_header.varpartlength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Var Part Length", HFILL }},
		{ &hf_saphdb_message_header_varpartsize,
			{ "Var Part Size", "saphdb.message_header.varpartsize", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Var Part Size", HFILL }},
		{ &hf_saphdb_message_header_noofsegm,
			{ "Number of Segments", "saphdb.message_header.noofsegm", FT_INT16, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Number of Segments", HFILL }},
		{ &hf_saphdb_message_header_packetoptions,
			{ "Packet Options", "saphdb.message_header.packetoptions", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Packet Options", HFILL }},
		{ &hf_saphdb_message_header_compressionvarpartlength,
			{ "Compression Var Part Length", "saphdb.message_header.compressionvarpartlength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Compression Var Part Length", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_saphdb
	};

	module_t *saphdb_module;

	/* Register the protocol */
	proto_saphdb = proto_register_protocol("SAP HANA SQL Command Network Protocol", "SAPHDB", "saphdb");

	register_dissector("saphdb", dissect_saphdb, proto_saphdb);

	proto_register_field_array(proto_saphdb, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the preferences */
	saphdb_module = prefs_register_protocol(proto_saphdb, proto_reg_handoff_saphdb);

	range_convert_str(wmem_epan_scope(), &global_saphdb_port_range, SAPHDB_PORT_RANGE, MAX_TCP_PORT);
	prefs_register_range_preference(saphdb_module, "tcp_ports", "SAP HANA SQL Command Network Protocol port numbers", "Port numbers used for SAP HANA SQL Command Network Protocol (default " SAPHDB_PORT_RANGE ")", &global_saphdb_port_range, MAX_TCP_PORT);

}

/**
 * Helpers for dealing with the port range
 */
static void range_delete_callback (guint32 port, gpointer ptr _U_)
{
	dissector_delete_uint("tcp.port", port, saphdb_handle);
}

static void range_add_callback (guint32 port, gpointer ptr _U_)
{
	dissector_add_uint("tcp.port", port, saphdb_handle);
}

/**
 * Register Hand off for the SAP HDB Protocol
 */
void
proto_reg_handoff_saphdb(void)
{
	static range_t *saphdb_port_range;
	static gboolean initialized = FALSE;

	if (!initialized) {
		saphdb_handle = create_dissector_handle(dissect_saphdb, proto_saphdb);
		initialized = TRUE;
	} else {
		range_foreach(saphdb_port_range, range_delete_callback, NULL);
		wmem_free(wmem_epan_scope(), saphdb_port_range);
	}

	saphdb_port_range = range_copy(wmem_epan_scope(), global_saphdb_port_range);
	range_foreach(saphdb_port_range, range_add_callback, NULL);
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
