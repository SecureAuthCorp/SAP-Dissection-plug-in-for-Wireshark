/*
# SAP Dissector Plugin for Wireshark
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
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
# Author:
#   Martin Gallo (@martingalloar) from SecureAuth's Innovation Labs team.
#
*/

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-sapprotocol.h"


/* SAP SNC Frame Type */
static const value_string sapsnc_frame_type_vals[] = {
    { 0x00, "REVERSE_REQ" },
    { 0x01, "INIT_REQ" },
    { 0x02, "INIT" },
    { 0x03, "INIT_ACK" },
    { 0x04, "ACCEPT" },
    { 0x05, "ACCEPT_ACK" },
    { 0x06, "ACCEPT_FAILED" },
    { 0x07, "DATA_OPEN" },
    { 0x08, "DATA_MIC/DATA_SIGNED" },
    { 0x09, "DATA_WRAP/DATA_SEALED" },
    { 0x0a, "SHUTDOWN" },
    { 0x0b, "SHUTDOWN_MSG" },
    { 0x0c, "REJECTED" },
    { 0x0d, "ERROR" },
    { 0x0e, "UNKNOWN" },
    { 0, NULL }
};

/* SNC Mech ID values */
static const value_string sapsnc_mech_id_vals[] = {
    { 0x00, "No security" },
    { 0x01, "Generic GSS-API v2 Mechanism" },
    { 0x02, "Kerberos 5/GSS-API v2" },
    { 0x03, "Secude 5 GSS-API v2" },
    { 0x04, "SAP's GSS-API v2 over NTLM(SSPI)" },
    { 0x05, "SPKM1 GSS-API v2 library" },
    { 0x06, "SPKM2 GSS-API v2 library" },
    { 0x07, "reserved ID" },
    { 0x08, "itsec" },
    { 0x09, "SDTI Connect Agent" },
    { 0x0a, "AccessMaster DCE" },
    { 0, NULL }
};

/* SNC Quality of protection values */
static const value_string sapsnc_qop_vals[] = {
    { 0x00, "INVALID" },
    { 0x01, "OPEN" },
    { 0x02, "INTEGRITY/SIGNED" },
    { 0x03, "PRIVACY/SEALED" },
    { 0x07, "MIN" },
    { 0x08, "DEFAULT" },
    { 0x09, "MAX" },
    { 0, NULL }
};


static int proto_sapsnc = -1;

/* SNC Frame */
static int hf_sapsnc_frame = -1;
static int hf_sapsnc_eye_catcher = -1;
static int hf_sapsnc_frame_type = -1;
static int hf_sapsnc_protocol_version = -1;
static int hf_sapsnc_header_length = -1;
static int hf_sapsnc_token_length = -1;
static int hf_sapsnc_data_length = -1;
static int hf_sapsnc_mech_id = -1;
static int hf_sapsnc_flags = -1;
static int hf_sapsnc_qop_min = -1;
static int hf_sapsnc_qop_max = -1;
static int hf_sapsnc_qop_use = -1;
static int hf_sapsnc_ext_flags = -1;
static int hf_sapsnc_ext_field_length = -1;
static int hf_sapsnc_ext_field = -1;
static int hf_sapsnc_token = -1;
static int hf_sapsnc_data = -1;

static gint ett_sapsnc = -1;

/* Expert info */
static expert_field ei_sapsnc_invalid_header_length = EI_INIT;

/* Protocol handle */
static dissector_handle_t sapsnc_handle;

void proto_reg_handoff_sapsnc(void);

/**
 * Dissect an SNC Frame. If data it's found for wrapped/signed frames, it
 * returns a new TVB buffer with the content. This function can be called
 * from any dissector that wants SNC frames to be decoded.
 */
tvbuff_t*
dissect_sapsnc_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
	tvbuff_t *next_tvb = NULL;

	if (tree) { /* we are being asked for details */

		guint8 frame_type = 0;
		guint16 header_length, ext_field_length = 0;
		guint32 token_length = 0, data_length = 0;
		proto_item *sapsnc_frame = NULL, *sapsnc_flags = NULL;
		proto_tree *sapsnc_frame_tree = NULL, *sapsnc_flags_tree = NULL;

		/* Add the SNC Frame subtree */
		sapsnc_frame = proto_tree_add_item(tree, hf_sapsnc_frame, tvb, offset, -1, ENC_NA);
		sapsnc_frame_tree = proto_item_add_subtree(sapsnc_frame, ett_sapsnc);

		/* Eye catcher */
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_eye_catcher, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;

		/* Frame type */
		frame_type = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;

		/* Protocol version */
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_protocol_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;

		/* Header length */
		header_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
		/* We subtracts the 10 bytes of the header already processed */
		header_length -= 10;

		/* Check the header length, it should be at least 24 bytes */
		if (header_length < 14){
			expert_add_info_format(pinfo, sapsnc_frame, &ei_sapsnc_invalid_header_length, "Invalid header length %d", header_length);
			header_length = 14;
		} else if (tvb_reported_length_remaining(tvb, offset) < header_length) {
			expert_add_info_format(pinfo, sapsnc_frame, &ei_sapsnc_invalid_header_length, "Invalid captured length %d", tvb_reported_length_remaining(tvb, offset));
			header_length = tvb_reported_length_remaining(tvb, offset);
		}
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_header_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2; header_length-=2;

		/* Token length */
		token_length = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_token_length, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4; header_length-=4;

		/* Data length */
		data_length = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_data_length, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4; header_length-=4;

		/* Mech ID */
		proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_mech_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2; header_length-=2;

		/* Build a tree for the flags */
		sapsnc_flags = proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_flags, tvb, offset, 2, ENC_NA);
		sapsnc_flags_tree = proto_item_add_subtree(sapsnc_flags, ett_sapsnc);

		offset+=1; header_length-=1; /* Unknown flags (1 byte) */
		/* Unknown flag (1 bit) */
		proto_tree_add_bits_item(sapsnc_flags_tree, hf_sapsnc_qop_min, tvb, offset*8 + 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(sapsnc_flags_tree, hf_sapsnc_qop_max, tvb, offset*8 + 3, 2, ENC_BIG_ENDIAN);
		proto_tree_add_bits_item(sapsnc_flags_tree, hf_sapsnc_qop_use, tvb, offset*8 + 5, 2, ENC_BIG_ENDIAN);
		/* Unknown flag (1 bit) */

		offset+=1; header_length-=1;

		/* If there's header remaining, we add the extra flags, length and fields */
		if (header_length >= 6 && tvb_offset_exists(tvb, offset + 6)) {
			/* Get the extra flags */
			proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_ext_flags, tvb, offset, 4, ENC_NA); offset+=4;

			/* Get the extra field length */
			ext_field_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
			proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_ext_field_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

			/* If the extra field length is valid extract those */
			if (ext_field_length > 0 && tvb_offset_exists(tvb, offset + ext_field_length)) {
				proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_ext_field, tvb, offset, ext_field_length, ENC_BIG_ENDIAN);
				offset+=ext_field_length;
			}
		}

		/* Token */
		if (token_length > 0 && tvb_offset_exists(tvb, offset + token_length)) {
			proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_token, tvb, offset, token_length, ENC_BIG_ENDIAN); offset+=token_length;
		}

		/* Data */
		if (data_length > 0 && tvb_offset_exists(tvb, offset + data_length)) {
			proto_tree_add_item(sapsnc_frame_tree, hf_sapsnc_data, tvb, offset, data_length, ENC_BIG_ENDIAN);

			/* If the frame contain data being wrapped or sealed, put it into a new tvb for
			   further dissection of the upper layer */
			if ((frame_type == 0x07) || (frame_type == 0x08)) {
			    next_tvb = tvb_new_subset_remaining(tvb, offset);
			}
			offset+=data_length;
		}
	}
	return next_tvb;
}

/**
 * Dissects SNC packets
 */
static int
dissect_sapsnc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, ", SAPSNC");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);
	/* Call the SNC frame dissection function */
	dissect_sapsnc_frame(tvb, pinfo, tree, 0);

	return tvb_reported_length(tvb);
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
		{ &hf_sapsnc_frame_type,
			{ "SNC Frame Type", "saprouter.frame.type", FT_UINT8, BASE_HEX, VALS(sapsnc_frame_type_vals), 0x0, "SAP SNC Frame Type", HFILL }},
		{ &hf_sapsnc_protocol_version,
			{ "SNC Protocol Version", "saprouter.frame.protocolversion", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP SNC Protocol Version", HFILL }},
		{ &hf_sapsnc_header_length,
			{ "SNC Header length", "sapsnc.frame.header_length", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP SNC Header Length", HFILL }},
		{ &hf_sapsnc_token_length,
			{ "SNC Token length", "sapsnc.frame.tokenlength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP SNC Token Length", HFILL }},
		{ &hf_sapsnc_data_length,
			{ "SNC Data length", "sapsnc.frame.datalength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP SNC Data Length", HFILL }},
		{ &hf_sapsnc_mech_id,
			{ "SNC Mech ID", "sapsnc.frame.mech_id", FT_UINT16, BASE_HEX, VALS(sapsnc_mech_id_vals), 0x0, "SAP SNC Mech ID", HFILL }},
		{ &hf_sapsnc_flags,
			{ "SNC Flags", "sapsnc.frame.flags", FT_UINT16, BASE_HEX, NULL, 0x0, "SAP SNC Flags", HFILL }},
		{ &hf_sapsnc_qop_min,
			{ "SNC QOP Min", "sapsnc.frame.qop_min", FT_UINT8, BASE_HEX, VALS(sapsnc_qop_vals), 0x0, "SAP SNC QOP Min", HFILL }},
		{ &hf_sapsnc_qop_max,
			{ "SNC QOP Max", "sapsnc.frame.qop_max", FT_UINT8, BASE_HEX, VALS(sapsnc_qop_vals), 0x0, "SAP SNC QOP Max", HFILL }},
		{ &hf_sapsnc_qop_use,
			{ "SNC QOP Use", "sapsnc.frame.qop_use", FT_UINT8, BASE_HEX, VALS(sapsnc_qop_vals), 0x0, "SAP SNC QOP Use", HFILL }},
		{ &hf_sapsnc_ext_flags,
			{ "SNC Ext Flags", "sapsnc.frame.ext_flags", FT_UINT32, BASE_HEX, NULL, 0x0, "SAP SNC Extensions Flags", HFILL }},
		{ &hf_sapsnc_ext_field_length,
			{ "SNC Ext Field length", "sapsnc.frame.ext_field_length", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP SNC Extensions Field length", HFILL }},
		{ &hf_sapsnc_ext_field,
			{ "SNC Ext Field", "sapsnc.frame.ext_field", FT_NONE, BASE_NONE, NULL, 0x0, "SAP SNC Extensions Field", HFILL }},
		{ &hf_sapsnc_token,
			{ "SNC Token", "sapsnc.frame.token", FT_NONE, BASE_NONE, NULL, 0x0, "SAP SNC Token", HFILL }},
		{ &hf_sapsnc_data,
			{ "SNC Data", "sapsnc.frame.data", FT_NONE, BASE_NONE, NULL, 0x0, "SAP SNC Data", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sapsnc
	};

    /* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_sapsnc_invalid_header_length, { "sapsnc.frame.header_length", PI_MALFORMED, PI_WARN, "Invalid header length", EXPFILL }},
	};

	expert_module_t* sapsnc_expert;

	/* Register the protocol */
	proto_sapsnc = proto_register_protocol("SAP SNC Protocol", "SAPSNC", "sapsnc");

	proto_register_field_array(proto_sapsnc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	sapsnc_expert = expert_register_protocol(proto_sapsnc);
	expert_register_field_array(sapsnc_expert, ei, array_length(ei));

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
