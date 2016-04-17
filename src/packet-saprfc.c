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
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

/* Common helpers for adding items */
#include "saphelpers.h"

/* SAP Decompression routine */
#include "sapdecompress.h"

/* Define default ports */
#define SAPRFC_PORT_RANGE "3300-3399"


/* SAP RFC Request Types field values */
static const value_string saprfc_reqtype_values[] = {
	{ 0x00, "GW_UNDEF_TYPE" },
	{ 0x01, "GW_CHECK_GATEWAY" },
	{ 0x02, "GW_CONNECT_GWWP" },
	{ 0x03, "GW_NORMAL_CLIENT" },
	{ 0x04, "GW_REMOTE_GATEWAY" },
	{ 0x05, "STOP_GATEWAY" },
	{ 0x06, "GW_LOCAL_R3" },
	{ 0x07, "GW_SEND_INTERNAL_ERROR" },
	{ 0x08, "GW_SEND_INFO" },
	{ 0x09, "GW_SEND_CMD" },
	{ 0x0a, "GW_WORKPROCESS_DIED" },
	{ 0x0b, "GW_REGISTER_TP" },
	{ 0x0c, "GW_UNREGISTER_TP" },
	{ 0x0d, "GW_CONNECT_DISP" },
	{ 0x0e, "GW_GET_NO_REGISTER_TP" },
	{ 0x0f, "GW_SAP_WP_CLIENT" },
	{ 0x10, "GW_CANCEL_REGISTER_TP" },
	{ 0x11, "REMOTE_GATEWAY" },
	{ 0x12, "GW_CONTAINER_RECEIVED" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC Monitor Command field values */
static const value_string saprfc_monitor_cmd_values[] = {
	{ 0x01, "NOOP" },
	{ 0x02, "DELETE_CONN" },
	{ 0x03, "CANCEL_CONN" },
	{ 0x04, "RST_SINGLE_ERR_CNT" },
	{ 0x05, "RST_ALL_ERR_CNT" },
	{ 0x06, "INCREASE_TRACE" },
	{ 0x07, "DECREASE_TRACE" },
	{ 0x08, "READ_SEC_INFO" },
	{ 0x09, "REFRESH_SEC_INFO" },
	{ 0x0a, "READ_GWSYS_TBL" },
	{ 0x0b, "READ_CONN_TBL" },
	{ 0x0c, "READ_PROC_TBL" },
	{ 0x0d, "READ_CONN_ATTR" },
	{ 0x0e, "READ_MEMORY" },
	{ 0x0f, "READ_REQ_BLK" },
	{ 0x10, "ACT_STATISTIC" },
	{ 0x11, "DEACT_STATISTIC" },
	{ 0x12, "READ_STATISTIC" },
	{ 0x13, "RESET_STATISTIC" },
	{ 0x14, "READ_PARAMETER" },
	{ 0x19, "DUMP_NIBUFFER" },
	{ 0x20, "RESET_NIBUFFER" },
	{ 0x21, "ACT_EXTPGM_TRACE" },
	{ 0x22, "DEACT_EXTPGM_TRACE" },
	{ 0x23, "ACT_CONN_TRACE" },
	{ 0x24, "DEACT_CONN_TRACE" },
	{ 0x25, "RESET_TRACE" },
	{ 0x26, "SUICIDE" },
	{ 0x27, "READ_SEC_INFO2" },
	{ 0x28, "CANCEL_REG_TP" },
	{ 0x29, "DUMP" },
	{ 0x2a, "READ_GWSYS_TBL2" },
	{ 0x2b, "CHANGE_PARAMETER" },
	{ 0x2c, "GET_CONN_PARTNER" },
	{ 0x2d, "DELETE_CLIENT" },
	{ 0x2e, "DELETE_REMGW" },
	{ 0x2f, "DISCONNECT" },
	{ 0x30, "ENABLE_RESTART" },
	{ 0x31, "DISABLE_RESTART" },
	{ 0x32, "NI_TRACE" },
	{ 0x33, "CLI_INFO" },
	{ 0x34, "GW_INFO" },
	{ 0x35, "CONVID_INFO" },
	{ 0x36, "GET_NO_REG_TP" },
	{ 0x37, "CV_INFO" },
	{ 0x38, "SO_KEEPALIVE" },
	{ 0x39, "READ_CONN_TBL2" },
	{ 0x40, "READ_GWSYS_TBL3" },
	{ 0x41, "RELOAD_ACL" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC APPC Header Request Type field values */
static const value_string saprfc_header_reqtype_values[] = {
	{ 0x00, "F_NO_REQUEST" },
	{ 0x01, "F_INITIALIZE_CONVERSATION" },
	{ 0x03, "F_ACCEPT_CONVERSATION" },
	{ 0x05, "F_ALLOCATE" },
	{ 0x07, "F_SEND_DATA" },
	{ 0x08, "F_ASEND_DATA" },
	{ 0x09, "F_RECEIVE" },
	{ 0x0a, "F_ARECEIVE" },
	{ 0x0b, "F_DEALLOCATE" },
	{ 0x0d, "F_SET_TP_NAME" },
	{ 0x0f, "F_SET_PARTNER_LU_NAME" },
	{ 0x11, "F_SET_SECURITY_PASSWORD" },
	{ 0x13, "F_SET_SECURITY_USER_ID" },
	{ 0x15, "F_SET_SECURITY_TYPE" },
	{ 0x17, "F_SET_CONVERSATION_TYPE" },
	{ 0x19, "F_EXTRACT_TP_NAME" },
	{ 0x1b, "F_FLUSH" },
	{ 0xc9, "F_SAP_ALLOCATE" },
	{ 0xca, "F_SAP_INIT" },
	{ 0xcb, "F_SAP_SEND" },
	{ 0xcc, "F_ASAP_SEND" },
	{ 0xcd, "F_SAP_SYNC" },
	{ 0xce, "F_SAP_PING" },
	{ 0xcf, "F_SAP_REGTP" },
	{ 0xd0, "F_SAP_UNREGTP" },
	{ 0xd1, "F_SAP_ACCPTP" },
	{ 0xd2, "F_SAP_UNACCPTP" },
	{ 0xd3, "F_SAP_CANCTP" },
	{ 0xd4, "F_SAP_SET_UID" },
	{ 0xd5, "F_SAP_CANCEL" },
	{ 0xd6, "F_SAP_CANCELED" },
	/* NULL */
	{ 0x00, NULL }
};


/* SAP RFC APPC Header Protocol field values */
static const value_string saprfc_header_protocol_values[] = {
	{ 0x00, "R2PR" },
	{ 0x01, "INT" },
	{ 0x02, "EXT" },
	{ 0x03, "CPIC" },
	{ 0x05, "NE" },
	{ 0x06, "REG" },
	{ 0x42, "CPIC" },
	{ 0x44, "EXT" },
	{ 0x45, "NE" },
	{ 0x48, "INT" },
	{ 0x61, "REG" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC APPC Header APPC Return Code field values */
static const value_string saprfc_header_appc_rc_values[] = {
	{ 0x00, "CM_OK" },
	{ 0x01, "CM_ALLOCATE_FAILURE_NO_RETRY" },
	{ 0x02, "CM_ALLOCATE_FAILURE_RETRY" },
	{ 0x03, "CM_CONVERSATION_TYPE_MISMATCH" },
	{ 0x06, "CM_SECURITY_NOT_VALID" },
	{ 0x08, "CM_SYNC_LVL_NOT_SUPPORTED_PGM" },
	{ 0x09, "CM_TPN_NOT_RECOGNIZED" },
	{ 0x0a, "CM_TP_NOT_AVAILABLE_NO_RETRY" },
	{ 0x0b, "CM_TP_NOT_AVAILABLE_RETRY" },
	{ 0x11, "CM_DEALLOCATED_ABEND" },
	{ 0x12, "CM_DEALLOCATED_NORMAL" },
	{ 0x13, "CM_PARAMETER_ERROR" },
	{ 0x14, "CM_PRODUCT_SPECIFIC_ERROR" },
	{ 0x15, "CM_PROGRAM_ERROR_NO_TRUNC" },
	{ 0x16, "CM_PROGRAM_ERROR_PURGING" },
	{ 0x17, "CM_PROGRAM_ERROR_TRUNC" },
	{ 0x18, "CM_PROGRAM_PARAMETER_CHECK" },
	{ 0x19, "CM_PROGRAM_STATE_CHECK" },
	{ 0x1a, "CM_RESOURCE_FAILURE_NO_RETRY" },
	{ 0x1b, "CM_RESOURCE_FAILURE_RETRY" },
	{ 0x1c, "CM_UNSUCCESSFUL" },
	{ 0x23, "CM_OPERATION_INCOMPLETE" },
	{ 0x24, "CM_SYSTEM_EVENT" },
	{ 0x2711, "CM_SAP_TIMEOUT_RETRY" },
	{ 0x2712, "CM_CANCEL_REQUEST" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP RFC APPC Header MCPIC Parameters Client Info values */
static const value_string saprfc_header_ncpic_parameters_client_info_values[] = {
	{ 0x00, "GW_NO_CLIENT_INFO" },
	{ 0x01, "GW_EXTERNAL_CLIENT" },
	{ 0x02, "GW_R3_CLIENT" },
	/* NULL */
	{ 0x00, NULL }
};


/* SAP RFC Accept Info Flag values */
#define SAPRFC_ACCEPT_INFO_EINFO						0x01
#define SAPRFC_ACCEPT_INFO_PING						0x02
#define SAPRFC_ACCEPT_INFO_SNC							0x04
#define SAPRFC_ACCEPT_INFO_CONN_EINFO					0x08
#define SAPRFC_ACCEPT_INFO_CODE_PAGE					0x10
#define SAPRFC_ACCEPT_INFO_NIPING						0x20
#define SAPRFC_ACCEPT_INFO_EXTINITOPT					0x40
#define SAPRFC_ACCEPT_INFO_GW_ACCEPT_DIST_TRACE		0x80

/* SAP RFC APPC Header Info Flags values */
#define SAPRFC_APPCHDR_INFO1_SYNC_CPIC_FUNCTION		0x01
#define SAPRFC_APPCHDR_INFO1_WITH_HOSTADDR				0x02
#define SAPRFC_APPCHDR_INFO1_WITH_GW_SAP_PARAMS_HDR	0x04
#define SAPRFC_APPCHDR_INFO1_CPIC_SYNC_REQ				0x08
#define SAPRFC_APPCHDR_INFO1_WITH_ERR_INFO				0x10
#define SAPRFC_APPCHDR_INFO1_DATA_WITH_TERM_OUTPUT		0x20
#define SAPRFC_APPCHDR_INFO1_DATA_WITH_TERM_INPUT		0x40
#define SAPRFC_APPCHDR_INFO1_R3_CPIC_LOGIN_WITH_TERM	0x80

#define SAPRFC_APPCHDR_INFO2_WITH_LONG_LU_NAME			0x01
#define SAPRFC_APPCHDR_INFO2_WITH_LONG_HOSTADDR		0x02
#define SAPRFC_APPCHDR_INFO2_GW_IMMEDIATE				0x04
#define SAPRFC_APPCHDR_INFO2_GW_SNC_ACTIVE				0x08
#define SAPRFC_APPCHDR_INFO2_GW_WAIT_LOOK_UP			0x10
#define SAPRFC_APPCHDR_INFO2_SNC_INIT_PHASE			0x20
#define SAPRFC_APPCHDR_INFO2_GW_STATELESS				0x40
#define SAPRFC_APPCHDR_INFO2_GW_NO_STATE_CHECK			0x80

#define SAPRFC_APPCHDR_INFO3_GW_WITH_CODE_PAGE 		0x01
#define SAPRFC_APPCHDR_INFO3_GW_ASYNC_RFC				0x02
#define SAPRFC_APPCHDR_INFO3_GW_CANCEL_HARD			0x04
#define SAPRFC_APPCHDR_INFO3_GW_CANCEL_SOFT			0x08
#define SAPRFC_APPCHDR_INFO3_GW_WITH_GUI_TIMEOUT		0x10
#define SAPRFC_APPCHDR_INFO3_GW_TERMIO_ERROR			0x20
#define SAPRFC_APPCHDR_INFO3_GW_EXTENDED_INIT_OPTIONS	0x40
#define SAPRFC_APPCHDR_INFO3_GW_DIST_TRACE				0x80

#define SAPRFC_APPCHDR_INFO4_GW_WITH_DBG_CTL 			0x01

/* SAP RFC APPC Header Request Type 2 Flags values */
#define SAPRFC_APPCHDR_REQTYPE2_F_V_INITIALIZE_CONVERSATION	0x01
#define SAPRFC_APPCHDR_REQTYPE2_F_V_ALLOCATE					0x02
#define SAPRFC_APPCHDR_REQTYPE2_F_V_SEND_DATA					0x04
#define SAPRFC_APPCHDR_REQTYPE2_F_V_RECEIVE					0x08
#define SAPRFC_APPCHDR_REQTYPE2_F_V_FLUSH						0x10


static int proto_saprfc = -1;

static int hf_saprfc_version = -1;
static int hf_saprfc_reqtype = -1;
static int hf_saprfc_address = -1;
static int hf_saprfc_service = -1;
static int hf_saprfc_codepage = -1;
static int hf_saprfc_lu = -1;
static int hf_saprfc_tp = -1;
static int hf_saprfc_conversation_id = -1;
static int hf_saprfc_appc_header_version = -1;
static int hf_saprfc_accept_info = -1;  /* (EINFO PING CONN_EINFO EXTINITOPT GW_ACCEPT_DIST_TRACE (0xCB)) */
static int hf_saprfc_accept_info_EINFO = -1;
static int hf_saprfc_accept_info_PING = -1;
static int hf_saprfc_accept_info_SNC = -1;
static int hf_saprfc_accept_info_CONN_EINFO = -1;
static int hf_saprfc_accept_info_CODE_PAGE = -1;
static int hf_saprfc_accept_info_NIPING = -1;
static int hf_saprfc_accept_info_EXTINITOPT = -1;
static int hf_saprfc_accept_info_GW_ACCEPT_DIST_TRACE = -1;
static int hf_saprfc_idx = -1;
static int hf_saprfc_address6 = -1;
static int hf_saprfc_rc = -1;
static int hf_saprfc_echo_data = -1;
static int hf_saprfc_filler = -1;

static int hf_saprfc_monitor_cmd = -1;

static int hf_saprfc_header = -1;
static int hf_saprfc_header_version = -1;
static int hf_saprfc_header_reqtype = -1;
static int hf_saprfc_header_protocol = -1;
static int hf_saprfc_header_mode = -1;
static int hf_saprfc_header_uid = -1;
static int hf_saprfc_header_gw_id = -1;
static int hf_saprfc_header_err_len = -1;
static int hf_saprfc_header_info2 = -1;
static int hf_saprfc_header_info2_WITH_LONG_LU_NAME = -1;
static int hf_saprfc_header_info2_WITH_LONG_HOSTADDR = -1;
static int hf_saprfc_header_info2_GW_IMMEDIATE = -1;
static int hf_saprfc_header_info2_GW_SNC_ACTIVE = -1;
static int hf_saprfc_header_info2_GW_WAIT_LOOK_UP = -1;
static int hf_saprfc_header_info2_SNC_INIT_PHASE = -1;
static int hf_saprfc_header_info2_GW_STATELESS = -1;
static int hf_saprfc_header_info2_GW_NO_STATE_CHECK = -1;
static int hf_saprfc_header_trace_level = -1;
static int hf_saprfc_header_time = -1;
static int hf_saprfc_header_info3 = -1;
static int hf_saprfc_header_info3_GW_WITH_CODE_PAGE = -1;
static int hf_saprfc_header_info3_GW_ASYNC_RFC = -1;
static int hf_saprfc_header_info3_GW_CANCEL_HARD = -1;
static int hf_saprfc_header_info3_GW_CANCEL_SOFT = -1;
static int hf_saprfc_header_info3_GW_WITH_GUI_TIMEOUT = -1;
static int hf_saprfc_header_info3_GW_TERMIO_ERROR = -1;
static int hf_saprfc_header_info3_GW_EXTENDED_INIT_OPTIONS = -1;
static int hf_saprfc_header_info3_GW_DIST_TRACE = -1;
static int hf_saprfc_header_timeout = -1;
static int hf_saprfc_header_info4 = -1;
static int hf_saprfc_header_info4_GW_WITH_DBG_CTL = -1;
static int hf_saprfc_header_sequence_no = -1;
static int hf_saprfc_header_sap_params_len = -1;
static int hf_saprfc_header_info = -1;
static int hf_saprfc_header_info_SYNC_CPIC_FUNCTION = -1;
static int hf_saprfc_header_info_WITH_HOSTADDR	= -1;
static int hf_saprfc_header_info_WITH_GW_SAP_PARAMS_HDR = -1;
static int hf_saprfc_header_info_CPIC_SYNC_REQ = -1;
static int hf_saprfc_header_info_WITH_ERR_INFO = -1;
static int hf_saprfc_header_info_DATA_WITH_TERM_OUTPUT = -1;
static int hf_saprfc_header_info_DATA_WITH_TERM_INPUT = -1;
static int hf_saprfc_header_info_R3_CPIC_LOGIN_WITH_TERM = -1;
static int hf_saprfc_header_reqtype2 = -1;
static int hf_saprfc_header_reqtype2_F_V_INITIALIZE_CONVERSATION = -1;
static int hf_saprfc_header_reqtype2_F_V_ALLOCATE = -1;
static int hf_saprfc_header_reqtype2_F_V_SEND_DATA = -1;
static int hf_saprfc_header_reqtype2_F_V_RECEIVE = -1;
static int hf_saprfc_header_reqtype2_F_V_FLUSH = -1;
static int hf_saprfc_header_appc_rc = -1;
static int hf_saprfc_header_sap_rc = -1;  /* TODO: Add SAP Return values */
static int hf_saprfc_header_conversation_id = -1;
static int hf_saprfc_header_ncpic_parameters = -1;
static int hf_saprfc_header_ncpic_parameters_sdest = -1;
static int hf_saprfc_header_ncpic_parameters_lu = -1;
static int hf_saprfc_header_ncpic_parameters_tp = -1;
static int hf_saprfc_header_ncpic_parameters_ctype = -1;
static int hf_saprfc_header_ncpic_parameters_client_info = -1;
static int hf_saprfc_header_ncpic_parameters_lu_name = -1;
static int hf_saprfc_header_ncpic_parameters_lu_name_length = -1;
static int hf_saprfc_header_ncpic_parameters_host_address = -1;
static int hf_saprfc_header_ncpic_parameters_security_password = -1;
static int hf_saprfc_header_ncpic_parameters_security_password_length = -1;

static int hf_saprfc_header_comm_idx = -1;
static int hf_saprfc_header_conn_idx = -1;

static int hf_saprfc_rfcheader = -1;

static int hf_saprfc_ucheader = -1;
static int hf_saprfc_ucheader_codepage = -1;
static int hf_saprfc_ucheader_ce = -1;
static int hf_saprfc_ucheader_et = -1;
static int hf_saprfc_ucheader_cs = -1;
static int hf_saprfc_ucheader_returncode = -1;

static int hf_saprfc_item = -1;
static int hf_saprfc_item_id1 = -1;
static int hf_saprfc_item_id2 = -1;
static int hf_saprfc_item_id3 = -1;
static int hf_saprfc_item_id4 = -1;
static int hf_saprfc_item_length = -1;
static int hf_saprfc_item_value = -1;

static int hf_saprfc_table = -1;
static int hf_saprfc_table_length = -1;
static int hf_saprfc_table_compress_header = -1;
static int hf_saprfc_table_uncomplength = -1;
static int hf_saprfc_table_algorithm = -1;
static int hf_saprfc_table_magic = -1;
static int hf_saprfc_table_special = -1;
static int hf_saprfc_table_return_code = -1;
static int hf_saprfc_table_content = -1;

static int hf_saprfc_payload = -1;


/* TODO: Add CPIC error codes (http://service.sap.com/sap/support/notes/63347) */
/* TODO: Add RFC logon error codes (http://service.sap.com/sap/support/notes/320991) */

static gint ett_saprfc = -1;

/* Expert info */
static expert_field ei_saprfc_invalid_decompresssion = EI_INIT;
static expert_field ei_saprfc_invalid_decompress_length = EI_INIT;
static expert_field ei_saprfc_unknown_item = EI_INIT;


/* Global decompress preference */
static gboolean global_saprfc_decompress = TRUE;

/* Global table reassembling preference */
static gboolean global_saprfc_table_reassembly = TRUE;

/* Global port preference */
static range_t *global_saprfc_port_range;

/* Global highlight preference */
static gboolean global_saprfc_highlight_items = TRUE;

/* Protocol handles for both external and internal dissectors */
static dissector_handle_t saprfc_handle;
static dissector_handle_t saprfcinternal_handle;


void proto_reg_handoff_saprfc(void);


static void
dissect_saprfc_tables_compressed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	guint8 *decompressed_buffer;
	guint32 reported_length = 0, uncompress_length = 0, offset = 0, initial_offset = 0;

	proto_item *compression_header = NULL, *rl = NULL;
	proto_tree *compression_header_tree = NULL;

	tvbuff_t *next_tvb = NULL;

	/* Skip the first 8 bytes */
	initial_offset = offset = 8;

	/* Add the compression header subtree */
	compression_header = proto_tree_add_item(tree, hf_saprfc_table_compress_header, tvb, offset, 8, ENC_NA);
	compression_header_tree = proto_item_add_subtree(compression_header, ett_saprfc);

	/* Add the uncompressed length */
	reported_length = tvb_get_letohl(tvb, offset);
	rl = proto_tree_add_uint(compression_header_tree, hf_saprfc_table_uncomplength, tvb, offset, 4, reported_length); offset+=4;
	proto_item_append_text(compression_header, ", Uncompressed Len: %u", reported_length);

	/* Add the algorithm */
	proto_tree_add_item(compression_header_tree, hf_saprfc_table_algorithm, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	/* Add the magic bytes */
	proto_tree_add_item(compression_header_tree, hf_saprfc_table_magic, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	/* Add the max bits */
	proto_tree_add_item(compression_header_tree, hf_saprfc_table_special, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	if (global_saprfc_decompress == TRUE){
		int rt = 0;

		/* Allocate the buffer only in the scope of current packet, using the
		 * reported length */
		decompressed_buffer = (guint8 *)wmem_alloc0(wmem_packet_scope(), reported_length);
		if (!decompressed_buffer){
			return;
		}

		uncompress_length = reported_length;

		/* Decompress the payload */
		rt = decompress_packet(tvb_get_ptr(tvb, initial_offset, -1),
				tvb_captured_length_remaining(tvb, initial_offset),
				decompressed_buffer,
				&uncompress_length);

		/* Check the return code and add a expert info warning if an error
		 * occurred. The dissector continues trying to add the payload,
		 * however the returned size should be 0.  */
		if (rt < 0){
			expert_add_info_format(pinfo, compression_header, &ei_saprfc_invalid_decompresssion, "Decompression of payload failed with return code %d (%s)", rt, val_to_str(rt, decompress_return_code_vals, "Unknown"));
		}

		/* Check the length returned for the compression routine. If differs
		 * with the reported, use the actual one and add an expert info
		 * warning. */
		if (uncompress_length != reported_length){
			expert_add_info_format(pinfo, rl, &ei_saprfc_invalid_decompress_length, "The uncompressed payload length (%d) differs with the reported length (%d)", uncompress_length, reported_length);
		}

		/* TODO: Add the return code to the tree */

		if (uncompress_length != 0){
			/* Now re-setup the tvb buffer to have the new data */
			next_tvb = tvb_new_real_data(decompressed_buffer, uncompress_length, uncompress_length);
			tvb_set_child_real_data_tvbuff(tvb, next_tvb);
			add_new_data_source(pinfo, next_tvb, "Uncompressed Table Data");

			/* Add the payload subtree using the new tvb*/
			proto_tree_add_item(tree, hf_saprfc_table_content, next_tvb, 0, -1, ENC_NA);
		}

	} else {
		/* Add the payload subtree */
		proto_tree_add_item(tree, hf_saprfc_table_content, tvb, offset, -1, ENC_NA);
	}

	/* TODO: Dissect saprfc_payload */
}

static void
dissect_saprfc_tables(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint16 item_length){

	guint8 *reassemble_buffer = NULL;
	guint32 reassemble_length = 0, reassemble_offset = 0, next_item = 0, initial_offset = offset;

	proto_item *table = NULL;
	proto_tree *table_tree = NULL;
	tvbuff_t *compressed_tvb = NULL;

	/* Get the reassemble length */
	reassemble_length = tvb_get_ntohl(tvb, offset + 4);
	if (item_length > (reassemble_length - reassemble_offset)){
		item_length = reassemble_length - reassemble_offset;
	}

	/* Allocate the buffer only in the scope of current packet */
	reassemble_buffer = (guint8 *)wmem_alloc(wmem_packet_scope(), reassemble_length);
	if (!reassemble_buffer){
		return;
	}

	/* Perform the reassemble */
	while (tvb_offset_exists(tvb, offset + item_length) && (reassemble_offset <= reassemble_length)){
		tvb_memcpy(tvb, reassemble_buffer + reassemble_offset, offset, item_length);
		offset += item_length; reassemble_offset += item_length;

		/* If the table content continues, get the length and advance the offset */
		next_item = tvb_get_ntohl(tvb, offset); offset+=4;
		if (next_item == 0x03050305){
			item_length = tvb_get_ntohs(tvb, offset); offset+=2;

			if (item_length > (reassemble_length - reassemble_offset)){
				item_length = reassemble_length - reassemble_offset;
			}

		/* If the table content doesn't continue, we've completed */
		} else {
			break;
		}
	}

	/* Now re-setup the tvb buffer to have the new data */
	compressed_tvb = tvb_new_real_data(reassemble_buffer, reassemble_length, reassemble_offset);
	tvb_set_child_real_data_tvbuff(tvb, compressed_tvb);
	add_new_data_source(pinfo, compressed_tvb, "Compressed Table Data");

	/* Add the Table subtree */
	table = proto_tree_add_item(tree, hf_saprfc_table, tvb, initial_offset, offset - initial_offset, ENC_NA);
	table_tree = proto_item_add_subtree(table, ett_saprfc);

	/* Now uncompress the table content */
	dissect_saprfc_tables_compressed(compressed_tvb, pinfo, table_tree);

}

static void
dissect_saprfc_item(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *item_value_tree, guint32 offset, guint8 item_id1, guint8 item_id2, guint8 item_id3, guint8 item_id4, guint16 item_length){

	if (item_id1==0x00 && item_id2==0x0b && item_id3==0x01 && item_id4==0x02){
		add_item_value_string(tvb, item, item_value_tree, hf_saprfc_item_value, offset, item_length, "Dispatch call to", 1); offset+=item_length;

	} else if (item_id1==0x02 && item_id2==0x03 && item_id3==0x02 && item_id4==0x01){
		add_item_value_string(tvb, item, item_value_tree, hf_saprfc_item_value, offset, item_length, "Parameter Name", 1); offset+=item_length;

	} else if (item_id1==0x02 && item_id2==0x05 && item_id3==0x02 && item_id4==0x05){
		add_item_value_string(tvb, item, item_value_tree, hf_saprfc_item_value, offset, item_length, "Parameter Name", 1); offset+=item_length;

	} else if (item_id1==0x02 && item_id2==0x05 && item_id3==0x02 && item_id4==0x01){
		add_item_value_string(tvb, item, item_value_tree, hf_saprfc_item_value, offset, item_length, "Parameter Name", 1); offset+=item_length;

	} else if (item_id1==0x02 && item_id2==0x03 && item_id3==0x03 && item_id4==0x01){
		add_item_value_string(tvb, item, item_value_tree, hf_saprfc_item_value, offset, item_length, "Tables Name", 1); offset+=item_length;

	} else if (item_id1==0x02 && item_id2==0x13 && item_id3==0x03 && item_id4==0x01){
		add_item_value_string(tvb, item, item_value_tree, hf_saprfc_item_value, offset, item_length, "Tables Name", 1); offset+=item_length;

	} else if (item_id1==0x03 && item_id2==0x01 && item_id3==0x03 && item_id4==0x02){
		check_length(pinfo, item_value_tree, 8, item_length, "Table length");
		add_item_value_uint32(tvb, item, item_value_tree, hf_saprfc_item_value, offset, "Fill Length"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_saprfc_item_value, offset, "Width Length"); offset+=4;

	} else if (item_id1==0x03 && item_id2==0x02 && item_id3==0x03 && item_id4==0x05){
		offset += 4;  /* Skip the first 4 bytes */
		proto_tree_add_item(item_value_tree, hf_saprfc_table_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4;
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Table Content (first)");
		proto_item_append_text(item, ", Table Content (first)"); offset+=item_length;

	} else if (item_id1==0x03 && item_id2==0x05 && item_id3==0x03 && item_id4==0x05){
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Table Content");
		proto_item_append_text(item, ", Table Content"); offset+=item_length;

	} else if (item_id1==0x03 && item_id2==0x05 && item_id3==0x03 && item_id4==0x06){
		proto_tree_add_none_format(item_value_tree, hf_saprfc_item_value, tvb, offset, item_length, "Table Content (last)");
		proto_item_append_text(item, ", Table Content (last)"); offset+=item_length;

	} else if (item_id1==0x03 && item_id2==0x06 && item_id3==0x03 && item_id4==0x01){
		add_item_value_string(tvb, item, item_value_tree, hf_saprfc_item_value, offset, item_length, "Tables Name", 1); offset+=item_length;

	} else if (item_id1==0x05 && item_id2==0x01 && item_id3==0x01 && item_id4==0x36){
		add_item_value_uint8(tvb, item, item_value_tree, hf_saprfc_item_value, offset, "#"); offset+=1;
		add_item_value_hexstring(tvb, item, item_value_tree, hf_saprfc_item_value, offset, 16, "Root-id"); offset+=16;
		add_item_value_hexstring(tvb, item, item_value_tree, hf_saprfc_item_value, offset, 16, "Conn-id"); offset+=16;
		add_item_value_uint32(tvb, item, item_value_tree, hf_saprfc_item_value, offset, "#"); offset+=4;

	} else {
		/* If the preference is set, report the item as unknown in the expert info */
		if (global_saprfc_highlight_items){
			expert_add_info_format(pinfo, item, &ei_saprfc_unknown_item, "The RFC item has a unknown type that is not dissected (%d %d %d %d)", item_id1, item_id2, item_id3, item_id4);
		}
	}
}

static void
dissect_saprfc_payload(tvbuff_t *tvb, packet_info *info, proto_tree *tree, proto_tree *parent_tree, guint32 offset){

	guint8 item_id1, item_id2, item_id3, item_id4;
	guint16 item_length, item_value_length;

	proto_item *item = NULL, *item_value = NULL;
	proto_tree *item_tree = NULL, *item_value_tree = NULL;

	while (tvb_offset_exists(tvb, offset)){
		item_id1 = item_id2 = item_id3 = item_id4 = 0;
		item_length = item_value_length = 0;

		/* Add the item subtree. We start with a item's length of 1, as we don't have yet the real size of the item */
		item = proto_tree_add_item(tree, hf_saprfc_item, tvb, offset, 1, ENC_NA);
		item_tree = proto_item_add_subtree(item, ett_saprfc);

		/* Get the first identifier */
		item_id1 = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(item_tree, hf_saprfc_item_id1, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1; item_length+=1;
		proto_item_append_text(item, ": (0x%.2x)", item_id1);

		/* Check if it's an End of message */
		if (item_id1==0x0c){
			item_value_length = 0;

		/* Otherwise follow dissection */
		} else {

			item_id2 = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(item_tree, hf_saprfc_item_id2, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1; item_length+=1;
			proto_item_append_text(item, ", (0x%.2x)", item_id2);

			if ((item_id1!=0xff) && (item_id2!=0xff)) {

				item_id3 = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(item_tree, hf_saprfc_item_id3, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1; item_length+=1;
				proto_item_append_text(item, ", (0x%.2x)", item_id3);

				item_id4 = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(item_tree, hf_saprfc_item_id4, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1; item_length+=1;
				proto_item_append_text(item, ", (0x%.2x)", item_id4);

				item_value_length = tvb_get_ntohs(tvb, offset);
				proto_tree_add_item(item_tree, hf_saprfc_item_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2; item_length+=2;
				proto_item_append_text(item, ", Length=%d", item_value_length);
			}
		}

		/* Now we have the real length of the item, set the proper size */
		item_length += item_value_length;
		proto_item_set_len(item, item_length);

		/* If the item has content dissect it */
		if (item_value_length>0){
			item_value = proto_tree_add_item(item_tree, hf_saprfc_item_value, tvb, offset, item_value_length, ENC_NA);
			item_value_tree = proto_item_add_subtree(item_value, ett_saprfc);
			dissect_saprfc_item(tvb, info, item, item_value_tree, offset, item_id1, item_id2, item_id3, item_id4, item_value_length);
		}

		/* Also send the tables items for reassembling */
		if (global_saprfc_table_reassembly && item_id1==0x03 && item_id2==0x02 && item_id3==0x03 && item_id4==0x05){
			dissect_saprfc_tables(tvb, info, parent_tree, offset, item_value_length);
		}

		offset+= item_value_length;
	}

}


static void
dissect_saprfc_rfcheader(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset){
	proto_item *header_unicode = NULL, *payload = NULL;
	proto_tree *header_unicode_tree = NULL, *payload_tree = NULL;

	if (tree){

		/* Add the RFC header subtree */
		/* TODO: We're not parsing the header yet. Adding this to avoid a
		compiler warning:

		header = proto_tree_add_item(tree, hf_saprfc_rfcheader, tvb, offset, 28, ENC_NA);
		header_tree = proto_item_add_subtree(header, ett_saprfc);
		*/
		offset += 28;

		/* Add the unicode header subtree */
		header_unicode = proto_tree_add_item(tree, hf_saprfc_ucheader, tvb, offset, 11, ENC_NA);
		header_unicode_tree = proto_item_add_subtree(header_unicode, ett_saprfc);

		proto_tree_add_none_format(header_unicode_tree, hf_saprfc_ucheader_codepage, tvb, offset, 4, "Code Page: %s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, 4)); offset+=4;
		proto_tree_add_item(header_unicode_tree, hf_saprfc_ucheader_ce, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(header_unicode_tree, hf_saprfc_ucheader_et, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(header_unicode_tree, hf_saprfc_ucheader_cs, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(header_unicode_tree, hf_saprfc_ucheader_returncode, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;

		/* Check the payload length */
		if (tvb_captured_length_remaining(tvb, offset) > 0){
			/* Add the payload subtree */
			payload = proto_tree_add_item(tree, hf_saprfc_payload, tvb, offset, -1, ENC_NA);
			payload_tree = proto_item_add_subtree(payload, ett_saprfc);

			/* Dissect the payload */
			dissect_saprfc_payload(tvb, pinfo, payload_tree, tree, offset);
		}

	}
}


static void
dissect_saprfc_monitor_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 version _U_, guint32 offset){
	guint8 opcode;

	opcode = tvb_get_guint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, ", Command=%s", val_to_str(opcode, saprfc_monitor_cmd_values, "Unknown"));

	if (tree){
		proto_tree_add_item(tree, hf_saprfc_monitor_cmd, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_item_append_text(tree, ", Command=%s", val_to_str(opcode, saprfc_monitor_cmd_values, "Unknown"));
	}

	switch (opcode){

	};

}


static void
dissect_saprfc_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset){
	guint8 version = 0, reqtype = 0;
	proto_item *header = NULL, *info = NULL, *info2 = NULL, *info3 = NULL, *info4 = NULL, *reqtype2 = NULL, *params = NULL;
	proto_tree *header_tree = NULL, *info_tree = NULL, *info2_tree = NULL, *info3_tree = NULL, *info4_tree = NULL, *reqtype2_tree = NULL, *params_tree;

	version = tvb_get_guint8(tvb, offset);
	reqtype = tvb_get_guint8(tvb, offset + 1);

	col_append_fstr(pinfo->cinfo, COL_INFO, "APPC Version=%d, Request Type=%s", version, val_to_str(reqtype, saprfc_header_reqtype_values, "Unknown"));

	if (tree){
		/* Add the APPC header subtree */
		header = proto_tree_add_item(tree, hf_saprfc_header, tvb, offset, 28, ENC_NA);
		header_tree = proto_item_add_subtree(header, ett_saprfc);

		proto_item_append_text(header, ", Version=%d, Request Type=%s", version, val_to_str(reqtype, saprfc_header_reqtype_values, "Unknown"));

		proto_tree_add_item(header_tree, hf_saprfc_header_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(header_tree, hf_saprfc_header_reqtype, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(header_tree, hf_saprfc_header_protocol, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(header_tree, hf_saprfc_header_mode, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(header_tree, hf_saprfc_header_uid, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
		proto_tree_add_item(header_tree, hf_saprfc_header_gw_id, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
		proto_tree_add_item(header_tree, hf_saprfc_header_err_len, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

		info2 = proto_tree_add_item(header_tree, hf_saprfc_header_info2, tvb, offset, 1, ENC_BIG_ENDIAN);
		info2_tree = proto_item_add_subtree(info2, ett_saprfc);
		proto_tree_add_item(info2_tree, hf_saprfc_header_info2_WITH_LONG_LU_NAME, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info2_tree, hf_saprfc_header_info2_WITH_LONG_HOSTADDR, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_IMMEDIATE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_SNC_ACTIVE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_WAIT_LOOK_UP, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info2_tree, hf_saprfc_header_info2_SNC_INIT_PHASE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_STATELESS, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info2_tree, hf_saprfc_header_info2_GW_NO_STATE_CHECK, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;

		proto_tree_add_item(header_tree, hf_saprfc_header_trace_level, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(header_tree, hf_saprfc_header_time, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;

		info3 = proto_tree_add_item(header_tree, hf_saprfc_header_info3, tvb, offset, 1, ENC_BIG_ENDIAN);
		info3_tree = proto_item_add_subtree(info3, ett_saprfc);
		proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_WITH_CODE_PAGE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_ASYNC_RFC, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_CANCEL_HARD, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_CANCEL_SOFT, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_WITH_GUI_TIMEOUT, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_TERMIO_ERROR, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_EXTENDED_INIT_OPTIONS, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info3_tree, hf_saprfc_header_info3_GW_DIST_TRACE, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;

		proto_tree_add_item(header_tree, hf_saprfc_header_timeout, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;

		info4 = proto_tree_add_item(header_tree, hf_saprfc_header_info4, tvb, offset, 1, ENC_BIG_ENDIAN);
		info4_tree = proto_item_add_subtree(info4, ett_saprfc);
		proto_tree_add_item(info4_tree, hf_saprfc_header_info4_GW_WITH_DBG_CTL, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;

		proto_tree_add_item(header_tree, hf_saprfc_header_sequence_no, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
		proto_tree_add_item(header_tree, hf_saprfc_header_sap_params_len, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
		offset+=2;  /* Skip 2 bytes here */

		info = proto_tree_add_item(header_tree, hf_saprfc_header_info, tvb, offset, 1, ENC_BIG_ENDIAN);
		info_tree = proto_item_add_subtree(info, ett_saprfc);
		proto_tree_add_item(info_tree, hf_saprfc_header_info_SYNC_CPIC_FUNCTION, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info_tree, hf_saprfc_header_info_WITH_HOSTADDR, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info_tree, hf_saprfc_header_info_WITH_GW_SAP_PARAMS_HDR, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info_tree, hf_saprfc_header_info_CPIC_SYNC_REQ, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info_tree, hf_saprfc_header_info_WITH_ERR_INFO, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info_tree, hf_saprfc_header_info_DATA_WITH_TERM_OUTPUT, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info_tree, hf_saprfc_header_info_DATA_WITH_TERM_INPUT, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(info_tree, hf_saprfc_header_info_R3_CPIC_LOGIN_WITH_TERM, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;

		reqtype2 = proto_tree_add_item(header_tree, hf_saprfc_header_reqtype2, tvb, offset, 1, ENC_BIG_ENDIAN);
		reqtype2_tree = proto_item_add_subtree(reqtype2, ett_saprfc);
		proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_INITIALIZE_CONVERSATION, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_ALLOCATE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_SEND_DATA, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_RECEIVE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(reqtype2_tree, hf_saprfc_header_reqtype2_F_V_FLUSH, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1;

		proto_tree_add_item(header_tree, hf_saprfc_header_appc_rc, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
		proto_tree_add_item(header_tree, hf_saprfc_header_sap_rc, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
		proto_tree_add_item(header_tree, hf_saprfc_header_conversation_id, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;

		/* Dissect the NCPIC Parameters according to the request type */
		params = proto_tree_add_item(header_tree, hf_saprfc_header_ncpic_parameters, tvb, offset, 28, ENC_NA);
		params_tree = proto_item_add_subtree(params, ett_saprfc);
		switch (reqtype){
			case 0x01:{		/* F_INITIALIZE_CONVERSATION */
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_sdest, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_lu, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_tp, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_ctype, tvb, offset, 1, ENC_ASCII|ENC_NA); offset+=1;
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_client_info, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
				offset += 2; /* Sum remaining bytes */
				break;
			}
			case 0x0f:{		/* F_SET_PARTNER_LU_NAME */
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_lu_name, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_lu_name_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_host_address, tvb, offset, 16, ENC_NA); offset+=16;
				break;
			}
			case 0x17:{		/* F_SET_SECURITY_TYPE */
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_security_password, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
				proto_tree_add_item(params_tree, hf_saprfc_header_ncpic_parameters_security_password_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
				offset += 16; /* Sum remaining bytes */
				break;
			}
			default:{
				offset+=28;
			}
		};

		proto_tree_add_item(header_tree, hf_saprfc_header_comm_idx, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
		proto_tree_add_item(header_tree, hf_saprfc_header_conn_idx, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	}
}

static void
dissect_saprfc_internal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	proto_item *saprfc = NULL;
	proto_tree *saprfc_tree = NULL;

	if (tree) { /* we are being asked for details */

		/* Add the main saprfc subtree */
		saprfc = proto_tree_add_item(tree, proto_saprfc, tvb, 0, -1, ENC_NA);
		saprfc_tree = proto_item_add_subtree(saprfc, ett_saprfc);

	}

	dissect_saprfc_rfcheader(tvb, pinfo, saprfc_tree, offset);

}

static void
dissect_saprfc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 offset = 0;
	guint8 version = 0, req_type = 0;
	proto_item *saprfc = NULL, *accept_info = NULL;
	proto_tree *saprfc_tree = NULL, *accept_info_tree = NULL;

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPRFC");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	/* Get version and request type values */
	version = tvb_get_guint8(tvb, offset);
	req_type = tvb_get_guint8(tvb, offset + 1);

	/* Check if the message is valid or it is an APPC header */
	/* TODO: We need to find a way of performing this check, as Wireshark is
	 * state-less seems to be difficult to keep track of the requests/responses.
	 */
	if (version > 0x03){
		if (tree){
			/* Add the main saprfc subtree */
			saprfc = proto_tree_add_item(tree, proto_saprfc, tvb, 0, -1, ENC_NA);
			saprfc_tree = proto_item_add_subtree(saprfc, ett_saprfc);
		}
		dissect_saprfc_header(tvb, pinfo, saprfc_tree, offset);
		return;
	}

	col_append_fstr(pinfo->cinfo, COL_INFO, "Version=%d, Request Type=%s", version, val_to_str(req_type, saprfc_reqtype_values, "Unknown"));

	if (tree) { /* we are being asked for details */

		/* Add the main saprfc subtree */
		saprfc = proto_tree_add_item(tree, proto_saprfc, tvb, 0, -1, ENC_NA);
		saprfc_tree = proto_item_add_subtree(saprfc, ett_saprfc);

		/* Dissect common fields */
		proto_tree_add_item(saprfc_tree, hf_saprfc_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_tree_add_item(saprfc_tree, hf_saprfc_reqtype, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
		proto_item_append_text(saprfc_tree, ", Version=%d, Request Type=%s", version, val_to_str(req_type, saprfc_reqtype_values, "Unknown"));

	}

	/* Dissect the remaining based on the version and request type */
	switch (req_type){

		case 0x03:		/* GW_NORMAL_CLIENT */
		case 0x0b:{		/* GW_REGISTER_TP */
			proto_tree_add_item(saprfc_tree, hf_saprfc_address, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
			offset+=4;  /* Skip 4 bytes here */
			proto_tree_add_item(saprfc_tree, hf_saprfc_service, tvb, offset, 10, ENC_ASCII|ENC_NA); offset+=10;
			proto_tree_add_item(saprfc_tree, hf_saprfc_codepage, tvb, offset, 4, ENC_ASCII|ENC_NA); offset+=4;
			offset+=6;  /* Skip 6 bytes here */
			proto_tree_add_item(saprfc_tree, hf_saprfc_lu, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
			proto_tree_add_item(saprfc_tree, hf_saprfc_tp, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
			proto_tree_add_item(saprfc_tree, hf_saprfc_conversation_id, tvb, offset, 8, ENC_ASCII|ENC_NA); offset+=8;
			proto_tree_add_item(saprfc_tree, hf_saprfc_appc_header_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;

			accept_info = proto_tree_add_item(saprfc_tree, hf_saprfc_accept_info, tvb, offset, 1, ENC_BIG_ENDIAN);
			accept_info_tree = proto_item_add_subtree(accept_info, ett_saprfc);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_EINFO, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_PING, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_SNC, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_CONN_EINFO, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_CODE_PAGE, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_NIPING, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_EXTINITOPT, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(accept_info_tree, hf_saprfc_accept_info_GW_ACCEPT_DIST_TRACE, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset+=1;

			proto_tree_add_item(saprfc_tree, hf_saprfc_idx, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;

			if (version == 0x03){
				proto_tree_add_item(saprfc_tree, hf_saprfc_address6, tvb, offset, 16, ENC_NA); offset+=16;
			}

			proto_tree_add_item(saprfc_tree, hf_saprfc_rc, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
			proto_tree_add_item(saprfc_tree, hf_saprfc_echo_data, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
			proto_tree_add_item(saprfc_tree, hf_saprfc_filler, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;
			break;
		}
		case 0x09:{		/* GW_SEND_CMD */
			dissect_saprfc_monitor_cmd(tvb, pinfo, saprfc_tree, version, 2);
			break;
		}
	};

}

void
proto_register_saprfc(void)
{
	static hf_register_info hf[] = {
		{ &hf_saprfc_version,
			{ "Version", "saprfc.version", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Version", HFILL }},
		{ &hf_saprfc_reqtype,
			{ "Request Type", "saprfc.reqtype", FT_UINT8, BASE_HEX, VALS(saprfc_reqtype_values), 0x0, "SAP RFC Request Type", HFILL }},
		{ &hf_saprfc_address,
			{ "IPv4 Address", "saprfc.addres", FT_IPv4, BASE_NONE, NULL, 0x0, "SAP RFC IPv4 Address", HFILL }},
		{ &hf_saprfc_service,
			{ "Service", "saprfc.service", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC Service", HFILL }},
		{ &hf_saprfc_codepage,
			{ "Codepage", "saprfc.codepage", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC Codepage", HFILL }},
		{ &hf_saprfc_lu,
			{ "LU", "saprfc.lu", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC LU", HFILL }},
		{ &hf_saprfc_tp,
			{ "TP", "saprfc.tp", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC TP", HFILL }},
		{ &hf_saprfc_conversation_id,
			{ "Conversation ID", "saprfc.conversation_id", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC Conversation ID", HFILL }},
		{ &hf_saprfc_appc_header_version,
			{ "APPC Header Version", "saprfc.appc_hd_version", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Version", HFILL }},
		{ &hf_saprfc_accept_info,
			{ "Accept Info Flags", "saprfc.accept_info", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Accept Info Flags", HFILL }},
		{ &hf_saprfc_accept_info_EINFO,
			{ "Accept Info Flag EINFO", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_EINFO, "SAP RFC Accept Info Flag EINFO", HFILL }},
		{ &hf_saprfc_accept_info_PING,
			{ "Accept Info Flag PING", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_PING, "SAP RFC Accept Info Flag PING", HFILL }},
		{ &hf_saprfc_accept_info_SNC,
			{ "Accept Info Flag SNC", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_SNC, "SAP RFC Accept Info Flag SNC", HFILL }},
		{ &hf_saprfc_accept_info_CONN_EINFO,
			{ "Accept Info Flag CONN_EINFO", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_CONN_EINFO, "SAP RFC Accept Info Flag CONN_EINFO", HFILL }},
		{ &hf_saprfc_accept_info_CODE_PAGE,
			{ "Accept Info Flag CODE_PAGE", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_CODE_PAGE, "SAP RFC Accept Info Flag CODE_PAGE", HFILL }},
		{ &hf_saprfc_accept_info_NIPING,
			{ "Accept Info Flag NIPING", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_NIPING, "SAP RFC Accept Info Flag NIPING", HFILL }},
		{ &hf_saprfc_accept_info_EXTINITOPT,
			{ "Accept Info Flag EXTINITOPT", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_EXTINITOPT, "SAP RFC Accept Info Flag EXTINITOPT", HFILL }},
		{ &hf_saprfc_accept_info_GW_ACCEPT_DIST_TRACE,
			{ "Accept Info Flag GW_ACCEPT_DIST_TRACE", "saprfc.accept_info.EINFO", FT_BOOLEAN, 8, NULL, SAPRFC_ACCEPT_INFO_GW_ACCEPT_DIST_TRACE, "SAP RFC Accept Info Flag GW_ACCEPT_DIST_TRACE", HFILL }},
		{ &hf_saprfc_idx,
			{ "Index", "saprfc.index", FT_INT16, BASE_DEC, NULL, 0x0, "SAP RFC Index", HFILL }},
		{ &hf_saprfc_address6,
			{ "IPv6 Address", "saprfc.addres6", FT_IPv6, BASE_NONE, NULL, 0x0, "SAP RFC IPv6 Address", HFILL }},
		{ &hf_saprfc_rc,
			{ "Return Code", "saprfc.rc", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC Return Code", HFILL }},
		{ &hf_saprfc_echo_data,
			{ "Echo Data", "saprfc.echo_data", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Echo Data", HFILL }},
		{ &hf_saprfc_filler,
			{ "Filler", "saprfc.filler", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Echo Data", HFILL }},

		/* Monitor Commands*/
		{ &hf_saprfc_monitor_cmd,
			{ "Command", "saprfc.monitor_cmd", FT_UINT8, BASE_DEC, VALS(saprfc_monitor_cmd_values), 0x0, "SAP RFC Monitor Command", HFILL }},

		/* APPC Header */
		{ &hf_saprfc_header,
			{ "APPC Header", "saprfc.appcheader", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header", HFILL }},
		{ &hf_saprfc_header_version,
			{ "Version", "saprfc.appcheader.version", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Version", HFILL }},
		{ &hf_saprfc_header_reqtype,
			{ "Request Type", "saprfc.appcheader.reqtype", FT_UINT8, BASE_HEX, VALS(saprfc_header_reqtype_values), 0x0, "SAP RFC APPC Header Request Type", HFILL }},
		{ &hf_saprfc_header_protocol,
			{ "Protocol", "saprfc.appcheader.protocol", FT_UINT8, BASE_HEX, VALS(saprfc_header_protocol_values), 0x0, "SAP RFC APPC Header Protocol", HFILL }},
		{ &hf_saprfc_header_mode,
			{ "Mode", "saprfc.appcheader.mode", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Mode", HFILL }},
		{ &hf_saprfc_header_uid,
			{ "UID", "saprfc.appcheader.uid", FT_INT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header UID", HFILL }},
		{ &hf_saprfc_header_gw_id,
			{ "Gateway ID", "saprfc.appcheader.gw_id", FT_UINT16, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Gateway ID", HFILL }},
		{ &hf_saprfc_header_err_len,
			{ "Error Length", "saprfc.appcheader.err_len", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Error Length", HFILL }},
		{ &hf_saprfc_header_info2,
			{ "Info 2", "saprfc.appcheader.info2", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Info 2", HFILL }},
		{ &hf_saprfc_header_info2_WITH_LONG_LU_NAME,
			{ "Info 2 Flag WITH_LONG_LU_NAME", "saprfc.info2.WITH_LONG_LU_NAME", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_WITH_LONG_LU_NAME, "SAP RFC Info 2 Flag WITH_LONG_LU_NAME", HFILL }},
		{ &hf_saprfc_header_info2_WITH_LONG_HOSTADDR,
			{ "Info 2 Flag WITH_LONG_HOSTADDR", "saprfc.info2.WITH_LONG_HOSTADDR", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_WITH_LONG_HOSTADDR, "SAP RFC Info 2 Flag WITH_LONG_HOSTADDR", HFILL }},
		{ &hf_saprfc_header_info2_GW_IMMEDIATE,
			{ "Info 2 Flag GW_IMMEDIATE", "saprfc.info2.GW_IMMEDIATE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_IMMEDIATE, "SAP RFC Info 2 Flag GW_IMMEDIATE", HFILL }},
		{ &hf_saprfc_header_info2_GW_SNC_ACTIVE,
			{ "Info 2 Flag GW_SNC_ACTIVE", "saprfc.info2.GW_SNC_ACTIVE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_SNC_ACTIVE, "SAP RFC Info 2 Flag GW_SNC_ACTIVE", HFILL }},
		{ &hf_saprfc_header_info2_GW_WAIT_LOOK_UP,
			{ "Info 2 Flag GW_WAIT_LOOK_UP", "saprfc.info2.GW_WAIT_LOOK_UP", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_WAIT_LOOK_UP, "SAP RFC Info 2 Flag GW_WAIT_LOOK_UP", HFILL }},
		{ &hf_saprfc_header_info2_SNC_INIT_PHASE,
			{ "Info 2 Flag SNC_INIT_PHASE", "saprfc.info2.SNC_INIT_PHASE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_SNC_INIT_PHASE, "SAP RFC Info 2 Flag SNC_INIT_PHASE", HFILL }},
		{ &hf_saprfc_header_info2_GW_STATELESS,
			{ "Info 2 Flag GW_STATELESS", "saprfc.info2.GW_STATELESS", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_STATELESS, "SAP RFC Info 2 Flag GW_STATELESS", HFILL }},
		{ &hf_saprfc_header_info2_GW_NO_STATE_CHECK,
			{ "Info 2 Flag GW_NO_STATE_CHECK", "saprfc.info2.GW_NO_STATE_CHECK", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO2_GW_NO_STATE_CHECK, "SAP RFC Info 2 Flag GW_NO_STATE_CHECK", HFILL }},
		{ &hf_saprfc_header_trace_level,
			{ "Trace Level", "saprfc.appcheader.trace_level", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Trace Level", HFILL }},
		{ &hf_saprfc_header_time,
			{ "Time", "saprfc.appcheader.time", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Time", HFILL }},
		{ &hf_saprfc_header_info3,
			{ "Info 3", "saprfc.appcheader.info3", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Info 3", HFILL }},
		{ &hf_saprfc_header_info3_GW_WITH_CODE_PAGE,
			{ "Info 3 Flag GW_WITH_CODE_PAGE", "saprfc.appcheader.info3.GW_WITH_CODE_PAGE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_WITH_CODE_PAGE, "SAP RFC APPC Header Info 3 Flag GW_WITH_CODE_PAGE", HFILL }},
		{ &hf_saprfc_header_info3_GW_ASYNC_RFC,
			{ "Info 3 Flag GW_ASYNC_RFC", "saprfc.appcheader.info3.GW_ASYNC_RFC", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_ASYNC_RFC, "SAP RFC APPC Header Info 3 Flag GW_ASYNC_RFC", HFILL }},
		{ &hf_saprfc_header_info3_GW_CANCEL_HARD,
			{ "Info 3 Flag GW_CANCEL_HARD", "saprfc.appcheader.info3.GW_CANCEL_HARD", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_CANCEL_HARD, "SAP RFC APPC Header Info 3 Flag GW_CANCEL_HARD", HFILL }},
		{ &hf_saprfc_header_info3_GW_CANCEL_SOFT,
			{ "Info 3 Flag GW_CANCEL_SOFT", "saprfc.appcheader.info3.GW_CANCEL_SOFT", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_CANCEL_SOFT, "SAP RFC APPC Header Info 3 Flag GW_CANCEL_SOFT", HFILL }},
		{ &hf_saprfc_header_info3_GW_WITH_GUI_TIMEOUT,
			{ "Info 3 Flag GW_WITH_GUI_TIMEOUT", "saprfc.appcheader.info3.GW_WITH_GUI_TIMEOUT", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_WITH_GUI_TIMEOUT, "SAP RFC APPC Header Info 3 Flag GW_WITH_GUI_TIMEOUT", HFILL }},
		{ &hf_saprfc_header_info3_GW_TERMIO_ERROR,
			{ "Info 3 Flag GW_TERMIO_ERROR", "saprfc.appcheader.info3.GW_TERMIO_ERROR", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_TERMIO_ERROR, "SAP RFC APPC Header Info 3 Flag GW_TERMIO_ERROR", HFILL }},
		{ &hf_saprfc_header_info3_GW_EXTENDED_INIT_OPTIONS,
			{ "Info 3 Flag GW_EXTENDED_INIT_OPTIONS", "saprfc.appcheader.info3.GW_EXTENDED_INIT_OPTIONS", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_EXTENDED_INIT_OPTIONS, "SAP RFC APPC Header Info 3 Flag GW_EXTENDED_INIT_OPTIONS", HFILL }},
		{ &hf_saprfc_header_info3_GW_DIST_TRACE,
			{ "Info 3 Flag GW_DIST_TRACE", "saprfc.appcheader.info3.GW_DIST_TRACE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO3_GW_DIST_TRACE, "SAP RFC APPC Header Info 3 Flag GW_DIST_TRACE", HFILL }},
		{ &hf_saprfc_header_timeout,
			{ "Timeout", "saprfc.appcheader.timeout", FT_INT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Timeout", HFILL }},
		{ &hf_saprfc_header_info4,
			{ "Info 4", "saprfc.appcheader.info4", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Info 4", HFILL }},
		{ &hf_saprfc_header_info4_GW_WITH_DBG_CTL,
			{ "Info 4 Flag GW_WITH_DBG_CTL", "saprfc.appcheader.info4.GW_WITH_DBG_CTL", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO4_GW_WITH_DBG_CTL, "SAP RFC APPC Header Info 4 Flag GW_WITH_DBG_CTL", HFILL }},
		{ &hf_saprfc_header_sequence_no,
			{ "Sequence No", "saprfc.appcheader.sequence_no", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Sequence No", HFILL }},
		{ &hf_saprfc_header_sap_params_len,
			{ "SAP Parameters Length", "saprfc.appcheader.sap_params_len", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header SAP Parameters Length", HFILL }},
		{ &hf_saprfc_header_info,
			{ "Info Flags", "saprfc.appcheader.info", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Info Flags", HFILL }},
		{ &hf_saprfc_header_info_SYNC_CPIC_FUNCTION,
			{ "Info Flag SYNC_CPIC_FUNCTION", "saprfc.appcheader.info.SYNC_CPIC_FUNCTION", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_SYNC_CPIC_FUNCTION, "SAP RFC APPC Header Info Flag SYNC_CPIC_FUNCTION", HFILL }},
		{ &hf_saprfc_header_info_WITH_HOSTADDR,
			{ "Info Flag WITH_HOSTADDR", "saprfc.appcheader.info.WITH_HOSTADDR", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_WITH_HOSTADDR, "SAP RFC APPC Header Info Flag WITH_HOSTADDR", HFILL }},
		{ &hf_saprfc_header_info_WITH_GW_SAP_PARAMS_HDR,
			{ "Info Flag WITH_GW_SAP_PARAMS_HDR", "saprfc.appcheader.info.WITH_GW_SAP_PARAMS_HDR", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_WITH_GW_SAP_PARAMS_HDR, "SAP RFC APPC Header Info Flag WITH_GW_SAP_PARAMS_HDR", HFILL }},
		{ &hf_saprfc_header_info_CPIC_SYNC_REQ,
			{ "Info Flag CPIC_SYNC_REQ", "saprfc.appcheader.info.CPIC_SYNC_REQ", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_CPIC_SYNC_REQ, "SAP RFC APPC Header Info Flag CPIC_SYNC_REQ", HFILL }},
		{ &hf_saprfc_header_info_WITH_ERR_INFO,
			{ "Info Flag WITH_ERR_INFO", "saprfc.appcheader.info.WITH_ERR_INFO", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_WITH_ERR_INFO, "SAP RFC APPC Header Info Flag WITH_ERR_INFO", HFILL }},
		{ &hf_saprfc_header_info_DATA_WITH_TERM_OUTPUT,
			{ "Info Flag DATA_WITH_TERM_OUTPUT", "saprfc.appcheader.info.DATA_WITH_TERM_OUTPUT", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_DATA_WITH_TERM_OUTPUT, "SAP RFC APPC Header Info Flag DATA_WITH_TERM_OUTPUT", HFILL }},
		{ &hf_saprfc_header_info_DATA_WITH_TERM_INPUT,
			{ "Info Flag DATA_WITH_TERM_INPUT", "saprfc.appcheader.info.DATA_WITH_TERM_INPUT", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_DATA_WITH_TERM_INPUT, "SAP RFC APPC Header Info Flag DATA_WITH_TERM_INPUT", HFILL }},
		{ &hf_saprfc_header_info_R3_CPIC_LOGIN_WITH_TERM,
			{ "Info Flag R3_CPIC_LOGIN_WITH_TERM", "saprfc.appcheader.info.R3_CPIC_LOGIN_WITH_TERM", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_INFO1_R3_CPIC_LOGIN_WITH_TERM, "SAP RFC APPC Header Info Flag R3_CPIC_LOGIN_WITH_TERM", HFILL }},
		{ &hf_saprfc_header_reqtype2,
			{ "Request Type 2 Flags", "saprfc.appcheader.reqtype2", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC APPC Header Request Type 2", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_INITIALIZE_CONVERSATION,
			{ "Request Type 2 Flag F_V_INITIALIZE_CONVERSATION", "saprfc.appcheader.reqtype2.F_V_INITIALIZE_CONVERSATION", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_INITIALIZE_CONVERSATION, "SAP RFC Request Type 2 Flag F_V_INITIALIZE_CONVERSATION", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_ALLOCATE,
			{ "Request Type 2 Flag F_V_ALLOCATE", "saprfc.appcheader.reqtype2.F_V_ALLOCATE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_ALLOCATE, "SAP RFC Request Type 2 Flag F_V_ALLOCATE", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_SEND_DATA,
			{ "Request Type 2 Flag F_V_SEND_DATA", "saprfc.appcheader.reqtype2.F_V_SEND_DATA", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_SEND_DATA, "SAP RFC Request Type 2 Flag F_V_SEND_DATA", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_RECEIVE,
			{ "Request Type 2 Flag F_V_RECEIVE", "saprfc.appcheader.reqtype2.F_V_RECEIVE", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_RECEIVE, "SAP RFC Request Type 2 Flag F_V_RECEIVE", HFILL }},
		{ &hf_saprfc_header_reqtype2_F_V_FLUSH,
			{ "Request Type 2 Flag F_V_FLUSH", "saprfc.appcheader.reqtype2.F_V_FLUSH", FT_BOOLEAN, 8, NULL, SAPRFC_APPCHDR_REQTYPE2_F_V_FLUSH, "SAP RFC Request Type 2 Flag F_V_FLUSH", HFILL }},
		{ &hf_saprfc_header_appc_rc,
			{ "APPC Return Code", "saprfc.appcheader.appc_rc", FT_INT32, BASE_DEC, VALS(saprfc_header_appc_rc_values), 0x0, "SAP RFC APPC Header APPC Return Code", HFILL }},
		{ &hf_saprfc_header_sap_rc,
			{ "SAP Return Code", "saprfc.appcheader.sap_rc", FT_INT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header SAP Return Code", HFILL }},
		{ &hf_saprfc_header_conversation_id,
			{ "Conversation ID", "saprfc.appcheader.conversation_id", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header Conversation ID", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters,
			{ "NCPIC Parameters", "saprfc.appcheader.ncpic_parameters", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_sdest,
			{ "SDest", "saprfc.appcheader.ncpic_parameters.sdest", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters SDest", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_lu,
			{ "LU", "saprfc.appcheader.ncpic_parameters.lu", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters LU", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_tp,
			{ "TP", "saprfc.appcheader.ncpic_parameters.tp", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters TP", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_ctype,
			{ "CType", "saprfc.appcheader.ncpic_parameters.ctype", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters CType", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_client_info,
			{ "Client Info", "saprfc.appcheader.ncpic_parameters.client_info", FT_UINT8, BASE_HEX, VALS(saprfc_header_ncpic_parameters_client_info_values), 0x0, "SAP RFC APPC Header NCPIC Parameters Client Info", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_lu_name,
			{ "LU Name", "saprfc.appcheader.ncpic_parameters.lu_name", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters LU Name", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_lu_name_length,
			{ "LU Name Length", "saprfc.appcheader.ncpic_parameters.lu_name_length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters LU Name Length", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_host_address,
			{ "Host Address", "saprfc.appcheader.ncpic_parameters.host_address", FT_IPv6, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters Host Address", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_security_password,
			{ "Security Password", "saprfc.appcheader.ncpic_parameters.security_password", FT_STRING, BASE_NONE, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters Security Password", HFILL }},
		{ &hf_saprfc_header_ncpic_parameters_security_password_length,
			{ "Security Password Length", "saprfc.appcheader.ncpic_parameters.security_password_length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header NCPIC Parameters Security Password Length", HFILL }},

		{ &hf_saprfc_header_comm_idx,
			{ "Comm Index", "saprfc.appcheader.comm_idx", FT_INT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Comm Index", HFILL }},
		{ &hf_saprfc_header_conn_idx,
			{ "Conn Index", "saprfc.appcheader.conn_idx", FT_INT16, BASE_DEC, NULL, 0x0, "SAP RFC APPC Header Conn Index", HFILL }},

		/* RFC Header */
		{ &hf_saprfc_rfcheader,
			{ "RFC Header", "saprfc.rfcheader", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Header", HFILL }},

		/* RFC Unicode Header */
		{ &hf_saprfc_ucheader,
			{ "Unicode Header", "saprfc.ucheader", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Unicode Header", HFILL }},
		{ &hf_saprfc_ucheader_codepage,
			{ "Code Page", "saprfc.ucheader.codepage", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Unicode Header Code Page", HFILL }},
		{ &hf_saprfc_ucheader_ce,
			{ "CE", "saprfc.ucheader.ce", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Unicode Header CE", HFILL }},
		{ &hf_saprfc_ucheader_et,
			{ "ET", "saprfc.ucheader.et", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Unicode Header ET", HFILL }},
		{ &hf_saprfc_ucheader_cs,
			{ "CS", "saprfc.ucheader.cs", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP RFC Unicode Header CS", HFILL }},
		{ &hf_saprfc_ucheader_returncode,
			{ "Return Code", "saprfc.ucheader.returncode", FT_UINT32, BASE_HEX, NULL, 0x0, "SAP RFC Unicode Header Return Code", HFILL }},

		/* Payload */
		{ &hf_saprfc_payload,
			{ "Message", "saprfc.message", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Message", HFILL }},

		/* Item fields */
		{ &hf_saprfc_item,
			{ "Item", "saprfc.item", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Item", HFILL }},
		{ &hf_saprfc_item_id1,
			{ "ID1", "saprfc.item.id1", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Item ID 1", HFILL }},
		{ &hf_saprfc_item_id2,
			{ "ID2", "saprfc.item.id2", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Item ID 2", HFILL }},
		{ &hf_saprfc_item_id3,
			{ "ID3", "saprfc.item.id3", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Item ID 3", HFILL }},
		{ &hf_saprfc_item_id4,
			{ "ID4", "saprfc.item.id4", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Item ID 4", HFILL }},
		{ &hf_saprfc_item_length,
			{ "Length", "saprfc.item.length", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP RFC Item Length", HFILL }},
		{ &hf_saprfc_item_value,
			{ "Value", "saprfc.item.value", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Item Value", HFILL }},

		/* Table content */
		{ &hf_saprfc_table,
			{ "Table", "saprfc.table", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table", HFILL }},
		{ &hf_saprfc_table_length,
			{ "Table Content Length", "saprfc.table.length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC Table Content Length", HFILL }},
		{ &hf_saprfc_table_compress_header,
			{ "Compression Header", "saprfc.table.compression", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Compression Header", HFILL }},
		{ &hf_saprfc_table_uncomplength,
			{ "Uncompressed Length", "saprfc.table.compression.uncomplength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP RFC Table Uncompressed Length", HFILL }},
		{ &hf_saprfc_table_algorithm,
			{ "Compression Algorithm", "saprfc.table.compression.algorithm", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Table Compression Algorithm", HFILL }},
		{ &hf_saprfc_table_magic,
			{ "Magic Bytes", "saprfc.table.compression.magic", FT_UINT16, BASE_HEX, NULL, 0x0, "SAP RFC Table Compression Magic Bytes", HFILL }},
		{ &hf_saprfc_table_special,
			{ "Special", "saprfc.table.compression.special", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP RFC Table Special", HFILL }},
		{ &hf_saprfc_table_return_code,
			{ "Decompress Return Code", "saprfc.table.compression.returncode", FT_UINT8, BASE_DEC, VALS(decompress_return_code_vals), 0x0, "SAP RFC Decompression routine return code", HFILL }},
		{ &hf_saprfc_table_content,
			{ "Content", "saprfc.table.content", FT_NONE, BASE_NONE, NULL, 0x0, "SAP RFC Table Content", HFILL }},

	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_saprfc
	};

	/* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_saprfc_invalid_decompresssion, { "saprfc.table.compression.failed", PI_MALFORMED, PI_WARN, "Decompression of payload failed", EXPFILL }},
		{ &ei_saprfc_invalid_decompress_length, { "saprfc.table.compression.uncomplength.invalid", PI_MALFORMED, PI_WARN, "The uncompressed payload length differs with the reported length", EXPFILL }},
		{ &ei_saprfc_unknown_item, { "saprfc.item.unknown", PI_UNDECODED, PI_WARN, "The RFC item has a unknown type that is not dissected", EXPFILL }},
	};

	module_t *saprfc_module;
	expert_module_t* saprfc_expert;

	/* Register the protocol */
	proto_saprfc = proto_register_protocol("SAP RFC Protocol", "SAPRFC", "saprfc");

	proto_register_field_array(proto_saprfc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	saprfc_expert = expert_register_protocol(proto_saprfc);
	expert_register_field_array(saprfc_expert, ei, array_length(ei));

	register_dissector("saprfc", dissect_saprfc, proto_saprfc);
	register_dissector("saprfcinternal", dissect_saprfc_internal, proto_saprfc);

	/* Register the preferences */
	saprfc_module = prefs_register_protocol(proto_saprfc, proto_reg_handoff_saprfc);

	range_convert_str(&global_saprfc_port_range, SAPRFC_PORT_RANGE, MAX_TCP_PORT);
	prefs_register_range_preference(saprfc_module, "tcp_ports", "SAP RFC Protocol TCP port numbers", "Port numbers used for SAP RFC Protocol (default " SAPRFC_PORT_RANGE ")", &global_saprfc_port_range, MAX_TCP_PORT);

	prefs_register_bool_preference(saprfc_module, "decompress", "Decompress SAP RFC Protocol message payloads", "Whether the SAP RFC Protocol dissector should decompress message's payloads.", &global_saprfc_decompress);

	prefs_register_bool_preference(saprfc_module, "table_reassembly", "Reassemble SAP RFC table content", "Whether the SAP RFC Protocol dissector should reassemble table content included in payloads.", &global_saprfc_table_reassembly);

	prefs_register_bool_preference(saprfc_module, "highlight_unknown_items", "Highlight unknown SAP RFC Items", "Whether the SAP RFC Protocol dissector should highlight unknown RFC items (migth be noise and generate a lot of expert warnings)", &global_saprfc_highlight_items);
}

/**
 * Helpers for dealing with the port range
 */
static void range_delete_callback (guint32 port)
{
	dissector_delete_uint("sapni.port", port, saprfc_handle);
}

static void range_add_callback (guint32 port)
{
	dissector_add_uint("sapni.port", port, saprfc_handle);
}

/**
 * Register Hand off for the SAP RFC Protocol
 */
void
proto_reg_handoff_saprfc(void)
{
	static range_t *saprfc_port_range;
	static gboolean initialized = FALSE;

	if (!initialized) {
		saprfc_handle = create_dissector_handle(dissect_saprfc, proto_saprfc);
		saprfcinternal_handle = create_dissector_handle(dissect_saprfc_internal, proto_saprfc);
		initialized = TRUE;
	} else {
		range_foreach(saprfc_port_range, range_delete_callback);
		g_free(saprfc_port_range);
	}

	saprfc_port_range = range_copy(global_saprfc_port_range);
	range_foreach(saprfc_port_range, range_add_callback);
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
