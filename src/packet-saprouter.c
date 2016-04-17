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

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>

#include "packet-sapprotocol.h"


/* Define default ports */
#define SAPROUTER_PORT_RANGE "3298-3299"

/*
 * Length of the frame header
 */
#define SAPROUTER_HEADER_LEN	8

/*
 * Offsets of header fields
 */
#define SAPROUTER_ROUTE_LENGTH_OFFSET	16
#define SAPROUTER_ROUTE_OFFSET_OFFSET	20

/* SAP Router Eye Catcher strings */
#define SAPROUTER_TYPE_ROUTE_STRING	"NI_ROUTE"
#define SAPROUTER_TYPE_ROUTE_ACCEPT	"NI_PONG"
#define SAPROUTER_TYPE_ERR_STRING	"NI_RTERR"
#define SAPROUTER_TYPE_ADMIN_STRING	"ROUTER_ADM"

/* SAP Router Talk Modes */
static const value_string saprouter_talk_mode_vals[] = {
	{ 0, "NI_MSG_IO" },
	{ 1, "NI_RAW_IO" },
	{ 2, "NI_ROUT_IO" },
	/* NULL */
	{ 0, NULL},
};

/* SAP Router Operation values */
static const value_string saprouter_opcode_vals[] = {
	{ 0, "Error information" },
	{ 1, "Version Request" },
	{ 2, "Version Response" },
	{ 5, "Send Handle (5)" },		/* TODO: Check this opcodes */
	{ 6, "Send Handle (6)" },		/* TODO: Check this opcodes */
	{ 8, "Send Handle (8)" },		/* TODO: Check this opcodes */
	{ 70, "SNC request" },			/* TODO: Check this opcodes NiSncOpcode: NISNC_REQ */
	{ 71, "SNC handshake complete" },	/* TODO: Check this opcodes NiSncOpcode: NISNC_ACK */
	/* NULL */
	{ 0, NULL}
};

/* SAP Router Return Code values (as per SAP Note 63342 http://service.sap.com/sap/support/notes/63342) */
static const value_string saprouter_return_code_vals[] = {
	{ -1, "NI-internal error (NIEINTERN)" },
	{ -2, "Host name unknown (NIEHOST_UNKNOWN)" },
	{ -3, "Service unknown (NIESERV_UNKNOWN)" },
	{ -4, "Service already used (NIESERV_USED)" },
	{ -5, "Time limit reached (NIETIMEOUT)" },
	{ -6, "Connection to partner broken (NIECONN_BROKEN)" },
	{ -7, "Data range too small (NIETOO_SMALL)" },
	{ -8, "Invalid parameters (NIEINVAL)" },
	{ -9, "Wake-Up (without data) (NIEWAKEUP)" },
	{-10, "Connection setup failed (NIECONN_REFUSED)" },
	{-11, "PING/PONG signal received (NIEPING)" },
	{-12, "Connection to partner via NiRouter not yet set up (NIECONN_PENDING)" },
	{-13, "Invalid version (NIEVERSION)" },
	{-14, "Local hostname cannot be found (NIEMYHOSTNAME)" },
	{-15, "No free port in range (NIENOFREEPORT)" },
	{-16, "Local hostname invalid (NIEMYHOST_VERIFY)" },
	{-17, "Error in the SNC shift in the saprouter ==> (NIESNC_FAILURE)" },
	{-18, "Opcode received (NIEOPCODE)" },
	{-19, "queue limit reached, next package not accepted (NIEQUE_FULL)" },
	{-20, "Requested package too large (NIETOO_BIG)" },
	{-90, "Host name unknown (NIEROUT_HOST_UNKNOWN)" },
	{-91, "Service unknown (NIEROUT_SERV_UNKNOWN)" },
	{-92, "Connection setup failed (NIEROUT_CONN_REFUSED)" },
	{-93, "NI-internal errors (NIEROUT_INTERN)" },
	{-94, "Connect from source to destination not allowed (NIEROUT_PERM_DENIED)" },
	{-95, "Connection terminated (NIEROUT_CONN_BROKEN)" },
	{-96, "Invalid client version (NIEROUT_VERSION)" },
	{-97, "Connection cancelled by administrator (NIEROUT_CANCELED)" },
	{-98, "saprouter shutdown (NIEROUT_SHUTDOWN)" },
	{-99, "Information request refused (NIEROUT_INFO_DENIED)" },
	{-100, "Max. number of clients reached (NIEROUT_OVERFLOW)" },
	{-101, "Talkmode not allowed (NIEROUT_MODE_DENIED)" },
	{-102, "Client not available (NIEROUT_NOCLIENT)" },
	{-103, "Error in external library (NIEROUT_EXTERN)" },
	{-104, "Error in the SNC shift (NIEROUT_SNC_FAILURE)" },
	/* NULL */
	{ 0, NULL}
};


/* SAP Router Admin Command values */
static const value_string saprouter_admin_command_vals[] = {
	{ 2, "Information Request" },
	{ 3, "New Route Table Request" },
	{ 4, "Toggle Trace Request" },
	{ 5, "Stop Request" },
	{ 6, "Cancel Route Request" },
	{ 7, "Dump Buffers Request" },
	{ 8, "Flush Buffers Request" },
	{ 9, "Soft Shutdown Request" },
	{ 10, "Set Trace Peer" },
	{ 11, "Clear Trace Peer" },
	{ 12, "Trace Connection" },
	{ 13, "Trace Connection" },
	{ 14, "Hide Error Information Request" },
	/* NULL */
	{ 0, NULL}
};


static int proto_saprouter = -1;

/* General fields */
static int hf_saprouter_type = -1;
static int hf_saprouter_ni_version = -1;

/* Route information */
static int hf_saprouter_route_version = -1;
static int hf_saprouter_entries = -1;
static int hf_saprouter_talk_mode = -1;
static int hf_saprouter_rest_nodes = -1;
static int hf_saprouter_route_length = -1;
static int hf_saprouter_route_offset = -1;
static int hf_saprouter_route = -1;
static int hf_saprouter_route_string = -1;

/* Route strings */
static int hf_saprouter_route_string_hostname = -1;
static int hf_saprouter_route_string_service = -1;
static int hf_saprouter_route_string_password = -1;


/* Error Information/Control Messages */
static int hf_saprouter_opcode = -1;
static int hf_saprouter_return_code = -1;
static int hf_saprouter_unknown = -1;

/* Error Information Messages */
static int hf_saprouter_error_length = -1;
static int hf_saprouter_error_string = -1;
static int hf_saprouter_error_eyecatcher = -1;
static int hf_saprouter_error_counter = -1;
static int hf_saprouter_error_error = -1;
static int hf_saprouter_error_return_code= -1;
static int hf_saprouter_error_component = -1;
static int hf_saprouter_error_release = -1;
static int hf_saprouter_error_version = -1;
static int hf_saprouter_error_module = -1;
static int hf_saprouter_error_line = -1;
static int hf_saprouter_error_detail= -1;
static int hf_saprouter_error_time = -1;
static int hf_saprouter_error_system_call = -1;
static int hf_saprouter_error_errorno = -1;
static int hf_saprouter_error_errorno_text = -1;
static int hf_saprouter_error_error_count = -1;
static int hf_saprouter_error_location= -1;
static int hf_saprouter_error_unknown= -1;  /* TODO: Unknown fields */

/* Control Messages */
static int hf_saprouter_control_length = -1;
static int hf_saprouter_control_string = -1;

/* Admin Messages */
static int hf_saprouter_admin_command = -1;
static int hf_saprouter_admin_password = -1;
static int hf_saprouter_admin_client_count_short = -1;
static int hf_saprouter_admin_client_count_int = -1;
static int hf_saprouter_admin_client_ids = -1;
static int hf_saprouter_admin_client_id = -1;
static int hf_saprouter_admin_address_mask = -1;

static gint ett_saprouter = -1;

/* Expert info */
static expert_field ei_saprouter_route_password_found = EI_INIT;
static expert_field ei_saprouter_route_invalid_length = EI_INIT;
static expert_field ei_saprouter_info_password_found = EI_INIT;
static expert_field ei_saprouter_invalid_client_ids = EI_INIT;

/* Global port preference */
static range_t *global_saprouter_port_range;


/* Global SNC dissection preference */
static gboolean global_saprouter_snc_dissection = TRUE;

/* Protocol handle */
static dissector_handle_t saprouter_handle;

/* Session state information being tracked in a SAP Router conversation */
typedef struct saprouter_session_state {
	gboolean route_information;
	gboolean route_accepted;
	guchar *src_hostname;		/* Source hostname (first entry in the route string) */
	guint32 src_port;		/* Source port number */
	guchar *src_password;		/* Source password XXX: Check if possible */
	guchar *dest_hostname;		/* Destination hostname (last entry in the route string) */
	guint32 dest_port;		/* Destination port number */
	guchar *dest_password;		/* Destination password */
} saprouter_session_state;

/*
 *
 */
void proto_reg_handoff_saprouter(void);

static guint32
dissect_serviceport(guchar *port){
	guint32 portnumber = 0;

	if (g_ascii_isdigit(port[0])){
		portnumber = (guint32)strtoul(port, NULL, 10);
	} else if ((strlen(port)>5) && g_str_has_prefix(port, "sapdp")){
		portnumber = 3200 + (guint32)strtoul(port+5, NULL, 10);
	} else if ((strlen(port)>5) && g_str_has_prefix(port, "sapgw")){
		portnumber = 3300 + (guint32)strtoul(port+5, NULL, 10);
	} else if ((strlen(port)>5) && g_str_has_prefix(port, "sapms")){
		portnumber = 3600 + (guint32)strtoul(port+5, NULL, 10);
	}
	return (portnumber);
}

static void
dissect_routestring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, saprouter_session_state *session_state){
	int hop = 1;
	guint32 len, route_offset, int_port = 0;
	guchar *hostname = NULL, *port = NULL, *password = NULL;
	proto_item *route_hop = NULL, *route_password = NULL;
	proto_tree *route_hop_tree = NULL;

	while (tvb_offset_exists(tvb, offset)){
		route_offset = offset; hostname = port = password = NULL;

		/* Create the subtree for this route hop */
		if (tree){
			route_hop = proto_tree_add_item(tree, hf_saprouter_route_string, tvb, offset, 0, ENC_NA);
			route_hop_tree = proto_item_add_subtree(route_hop, ett_saprouter);
			proto_item_append_text(route_hop, ", nro %d", hop);
		}

		/* Dissect the hostname string */
		len = tvb_strsize(tvb, offset);
		hostname = tvb_get_string_enc(wmem_file_scope(), tvb, offset, len - 1, ENC_ASCII);
		if (tree){
			proto_tree_add_item(route_hop_tree, hf_saprouter_route_string_hostname, tvb, offset, len, ENC_ASCII|ENC_NA);
		}
		offset += len;

		/* Dissect the port string */
		len = tvb_strsize(tvb, offset);
		port = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len - 1, ENC_ASCII);
		if (tree){
			proto_tree_add_item(route_hop_tree, hf_saprouter_route_string_service, tvb, offset, len, ENC_ASCII|ENC_NA);
		}
		offset += len;

		/* Dissect the password string */
		len = tvb_strsize(tvb, offset);
		password = tvb_get_string_enc(wmem_file_scope(), tvb, offset, len - 1, ENC_ASCII);
		if (tree){
			route_password = proto_tree_add_item(route_hop_tree, hf_saprouter_route_string_password, tvb, offset, len, ENC_ASCII|ENC_NA);

			/* If a password was found, add a expert warning in the security category */
			if (len > 1){
				expert_add_info(pinfo, route_password, &ei_saprouter_route_password_found);
			}
		}
		offset += len;

		/* Adjust the size of the route hop item now that we know the size */
		if (tree){
			proto_item_set_len(route_hop, offset - route_offset);
		}

		/* Get the service port in numeric format */
		int_port = dissect_serviceport(port);

		/* Add the first hostname/port as source in the conversation state*/
		if ((hop==1) && session_state){
			session_state->src_hostname = hostname;
			session_state->src_port = int_port;
			session_state->src_password = password;
		}
		hop++;
	}

	/* Add the last hostname/port as destination */
	if ((hop!=1) && session_state){
		session_state->dest_hostname = hostname;
		session_state->dest_port = int_port;
		session_state->dest_password = password;
	}
	/* Save the status of the conversation state */
	if (session_state){
		session_state->route_information = TRUE;
		session_state->route_accepted = FALSE;
	}
}

static void
dissect_errorstring(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
	guint32 len;

	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_eyecatcher, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_counter, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_error, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_return_code, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_component, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_release, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_version, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_module, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_line, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_detail, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_time, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_system_call, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_errorno, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_errorno_text, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_error_count, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_location, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;

	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_unknown, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_unknown, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_unknown, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_unknown, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;

	len = tvb_strsize(tvb, offset);
	proto_tree_add_item(tree, hf_saprouter_error_eyecatcher, tvb, offset, len, ENC_ASCII|ENC_NA); offset += len;
}


static void
dissect_saprouter_snc_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset){

	tvbuff_t *next_tvb = NULL;
	dissector_handle_t snc_handle;

	/* Call the SNC dissector */
	if (global_saprouter_snc_dissection == TRUE){
		snc_handle = find_dissector("sapsnc");
		if (snc_handle){
			/* Set the column to not writable so the SNC dissector doesn't override the Diag info */
			col_set_writable(pinfo->cinfo, FALSE);
			/* Create a new tvb buffer and call the dissector */
			next_tvb = tvb_new_subset(tvb, offset, -1, -1);
			call_dissector(snc_handle, next_tvb, pinfo, tree);
		}
	}

}


static void
dissect_saprouter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 opcode = 0;
	guint32 offset = 0, eyecatcher_length = 0;
	conversation_t *conversation = NULL;
	saprouter_session_state *session_state = NULL;
	proto_item *ti = NULL, *ri = NULL, *ei = NULL, *ci = NULL, *admin_password = NULL;
	proto_tree *saprouter_tree = NULL, *route_tree = NULL, *text_tree = NULL, *clients_tree = NULL;

	/* Search for a conversation */
	conversation = find_or_create_conversation(pinfo);
	session_state = (saprouter_session_state *)conversation_get_proto_data(conversation, proto_saprouter);
	if (!session_state){
		session_state = (saprouter_session_state *)wmem_alloc(wmem_file_scope(), sizeof(saprouter_session_state));
		if (session_state){
			session_state->route_information = FALSE;
			session_state->route_accepted = FALSE;
			session_state->src_hostname = NULL; session_state->src_port = 0; session_state->src_password = NULL;
			session_state->dest_hostname = NULL; session_state->dest_port = 0; session_state->dest_password = NULL;
			conversation_add_proto_data(conversation, proto_saprouter, session_state);
		}
	}

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPROUTER");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	/* Add the main SAP Router subtree */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_saprouter, tvb, offset, -1, ENC_NA);
		saprouter_tree = proto_item_add_subtree(ti, ett_saprouter);
	}

	/* Get the 'eye catcher' length */
	eyecatcher_length = tvb_strsize(tvb, offset);

	/* Admin Message Type */
	if (tvb_strneql(tvb, offset, SAPROUTER_TYPE_ADMIN_STRING, eyecatcher_length) == 0){
		col_set_str(pinfo->cinfo, COL_INFO, "Admin Message");

		proto_tree_add_item(saprouter_tree, hf_saprouter_type, tvb, offset, eyecatcher_length, ENC_ASCII|ENC_NA); offset += eyecatcher_length;
		proto_item_append_text(ti, ", Admin Message");

		proto_tree_add_item(saprouter_tree, hf_saprouter_ni_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

		opcode = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(saprouter_tree, hf_saprouter_admin_command, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

		switch (opcode){
			case 2:{  /* Info request */
				offset+=2; /* Skip 2 bytes */
				/* Check if a password was supplied */
				if (tvb_offset_exists(tvb, offset) && (tvb_strsize(tvb, offset) > 0)){
					admin_password = proto_tree_add_item(saprouter_tree, hf_saprouter_admin_password, tvb, offset, tvb_strsize(tvb, offset), ENC_ASCII|ENC_NA);
					expert_add_info(pinfo, admin_password, &ei_saprouter_info_password_found);
				}
				break;
			}
			case 10:  /* Set Peer Trace */
			case 11:{ /* Clear Peer Trace */
				proto_tree_add_item(saprouter_tree, hf_saprouter_admin_address_mask, tvb, offset, 32, ENC_ASCII|ENC_NA); offset+=32;
				break;
			}
			case 6:  /* Cancel Route request */
			case 12: /* Trace Connection */
			case 13: /* Trace Connection */
			{
				guint16 client_count = 0, client_count_actual = 0;

				/* Retrieve the client count first */
				if (opcode == 6){
					offset+=2; /* Skip 2 bytes for Cancel Route request*/
					client_count = tvb_get_ntohs(tvb, offset);
					proto_tree_add_item(saprouter_tree, hf_saprouter_admin_client_count_short, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
				} else {
					client_count = tvb_get_ntohl(tvb, offset);
					proto_tree_add_item(saprouter_tree, hf_saprouter_admin_client_count_int, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
				}

				/* Parse the list of client IDs */
				ci = proto_tree_add_item(saprouter_tree, hf_saprouter_admin_client_ids, tvb, offset, 4*client_count, ENC_NA);
				clients_tree = proto_item_add_subtree(ci, ett_saprouter);
				while (tvb_offset_exists(tvb, offset) && tvb_captured_length_remaining(tvb, offset)>=4){
					proto_tree_add_item(clients_tree, hf_saprouter_admin_client_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
					client_count_actual+=1;
				}

				/* Check if the actual count of IDs differes from the reported number */
				if ((client_count_actual != client_count) || tvb_captured_length_remaining(tvb, offset)>0){
					expert_add_info(pinfo, clients_tree, &ei_saprouter_invalid_client_ids);
				}

				break;
			}
			default: {
				offset+=2; /* Skip 2 bytes */
				break;
			}
		}

	/* Route Message Type */
	} else if (tvb_strneql(tvb, offset, SAPROUTER_TYPE_ROUTE_STRING, eyecatcher_length) == 0){
		guint32 route_length = 0, route_offset = 0;

		col_set_str(pinfo->cinfo, COL_INFO, "Route Message");

		/* Get the route length/offset */
		route_length = tvb_get_ntohl(tvb, offset + SAPROUTER_ROUTE_LENGTH_OFFSET);
		route_offset = offset + SAPROUTER_ROUTE_OFFSET_OFFSET + 4;

		if (tree){
			proto_tree_add_item(saprouter_tree, hf_saprouter_type, tvb, 0, eyecatcher_length, ENC_ASCII|ENC_NA); offset += eyecatcher_length;
			proto_item_append_text(ti, ", Route Message");
			/* Add the fields */
			proto_tree_add_item(saprouter_tree, hf_saprouter_route_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
			proto_tree_add_item(saprouter_tree, hf_saprouter_ni_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
			proto_tree_add_item(saprouter_tree, hf_saprouter_entries, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
			proto_tree_add_item(saprouter_tree, hf_saprouter_talk_mode, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=3; /* There're two unused bytes there */
			proto_tree_add_item(saprouter_tree, hf_saprouter_rest_nodes, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
			proto_tree_add_item(saprouter_tree, hf_saprouter_route_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
			proto_tree_add_item(saprouter_tree, hf_saprouter_route_offset, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
			/* Add the route tree */
			if ((guint32)tvb_captured_length_remaining(tvb, offset) != route_length){
				expert_add_info_format(pinfo, saprouter_tree, &ei_saprouter_route_invalid_length, "Route string length is invalid (remaining=%d, route_length=%d)", tvb_captured_length_remaining(tvb, offset), route_length);
				route_length = (guint32)tvb_captured_length_remaining(tvb, offset);
			}
			ri = proto_tree_add_item(saprouter_tree, hf_saprouter_route, tvb, offset, route_length, ENC_NA);
			route_tree = proto_item_add_subtree(ri, ett_saprouter);
		}

		/* Dissect the route string */
		dissect_routestring(tvb, pinfo, route_tree, route_offset, session_state);

		/* Add the route to the colinfo*/
		if (session_state && session_state->src_hostname){
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Source: Hostname=%s Service Port=%d", session_state->src_hostname, session_state->src_port);
			if (strlen(session_state->src_password)>0)
				col_append_fstr(pinfo->cinfo, COL_INFO, " Password=%s", session_state->src_password);
		}
		if (session_state && session_state->dest_hostname){
			col_append_fstr(pinfo->cinfo, COL_INFO, ", Destination: Hostname=%s Service Port=%d", session_state->dest_hostname, session_state->dest_port);
			if (strlen(session_state->dest_password)>0)
				col_append_fstr(pinfo->cinfo, COL_INFO, " Password=%s", session_state->dest_password);
		}

	/* Error Information/Control Message Type */
	} else if (tvb_strneql(tvb, offset, SAPROUTER_TYPE_ERR_STRING, eyecatcher_length) == 0){
		opcode = tvb_get_guint8(tvb, offset + 10);
		col_set_str(pinfo->cinfo, COL_INFO, (opcode==0)? "Error Information" : "Control Message");

		if (tree){
			guint32 text_length = 0;

			proto_item_append_text(ti, (opcode==0)? ", Error Information" : ", Control Message");
			/* Add the fields */
			proto_tree_add_item(saprouter_tree, hf_saprouter_type, tvb, offset, eyecatcher_length, ENC_ASCII|ENC_NA); offset += eyecatcher_length;
			proto_tree_add_item(saprouter_tree, hf_saprouter_ni_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
			proto_tree_add_item(saprouter_tree, hf_saprouter_opcode, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=2; /* There's a unused byte there */
			proto_tree_add_item(saprouter_tree, hf_saprouter_return_code, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;

			text_length = tvb_get_ntohl(tvb, offset);
			/* Error Information Message */
			if (opcode == 0){
				proto_tree_add_item(saprouter_tree, hf_saprouter_error_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
				if ((text_length > 0) && tvb_offset_exists(tvb, offset+text_length)){
					/* Add the error string tree */
					ei = proto_tree_add_item(saprouter_tree, hf_saprouter_error_string, tvb, offset, text_length, ENC_NA);
					text_tree = proto_item_add_subtree(ei, ett_saprouter);
					dissect_errorstring(tvb, text_tree, offset);
					offset += text_length;
				}

			/* Control Message */
			} else {
				proto_tree_add_item(saprouter_tree, hf_saprouter_control_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;
				if ((text_length >0) && tvb_offset_exists(tvb, offset+text_length)){
					/* Add the control string tree */
					proto_tree_add_item(saprouter_tree, hf_saprouter_control_string, tvb, offset, text_length, ENC_ASCII|ENC_NA);
					offset += text_length;
				}

				/* Dissect the SNC Frame for SNC opcodes */
				if (opcode == 70 || opcode == 71){
					dissect_saprouter_snc_frame(tvb, pinfo, tree, offset);
				}

			}
			proto_tree_add_item(saprouter_tree, hf_saprouter_unknown, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;

		}

	/* Route Acceptance (NI_PONG) Message Type */
	} else if (tvb_strneql(tvb, offset, SAPROUTER_TYPE_ROUTE_ACCEPT, eyecatcher_length) == 0){
		/* Route information available */
		if (session_state && session_state->route_information){
			session_state->route_accepted = TRUE;
			col_add_fstr(pinfo->cinfo, COL_INFO, "Route from %s:%d to %s:%d accepted ", session_state->src_hostname, session_state->src_port, session_state->dest_hostname, session_state->dest_port);
			if (tree){
				proto_item_append_text(ti, ", Route from %s:%d to %s:%d accepted ", session_state->src_hostname, session_state->src_port, session_state->dest_hostname, session_state->dest_port);
			}
		}

	/* Uknown Message Type */
	} else {
		/* Route information available */
		if (session_state && session_state->route_information){

			/* TODO: Add a link to the packet were the route was requested
			 * (like TCP reassembled packets).
			 */
			/* Route accepted */
			if (session_state->route_accepted){

				col_add_fstr(pinfo->cinfo, COL_INFO, "Message routed from %s:%d to %s:%d ", session_state->src_hostname, session_state->src_port, session_state->dest_hostname, session_state->dest_port);
				if (tree){
					proto_item_append_text(ti, ", Message routed from %s:%d to %s:%d ", session_state->src_hostname, session_state->src_port, session_state->dest_hostname, session_state->dest_port);
				}

			/* Route not accepted but some information available */
			} else {
				col_add_fstr(pinfo->cinfo, COL_INFO, "Message routed to unknown destination");
				if (tree){
					proto_item_append_text(ti, ", Message routed to unknown destination");
				}
			}

			/* Call the dissector in the NI protocol subdissectors table
			 * according to the route destination port number. */
			dissect_sap_protocol_payload(tvb, offset, pinfo, tree, 0, session_state->dest_port);

		} else {
			/* No route information available */
			col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown message or message routed to unknown destination");
			if (tree){
				proto_item_append_text(ti, ", Unknown message or message routed to unknown destination");
			}
		}
	}
}

void
proto_register_saprouter(void)
{
	static hf_register_info hf[] = {
		{ &hf_saprouter_type,
			{ "Type", "saprouter.type", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Type", HFILL }},
		/* NI Route messages */
		{ &hf_saprouter_route_version,
			{ "Route version", "saprouter.version", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Router Version", HFILL }},
		{ &hf_saprouter_ni_version,
			{ "NI version", "saprouter.niversion", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Router NI Version", HFILL }},
		{ &hf_saprouter_entries,
			{ "Entries", "saprouter.entries", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Router Total number of entries", HFILL }},
		{ &hf_saprouter_talk_mode,
			{ "Talk Mode", "saprouter.talkmode", FT_UINT8, BASE_DEC, VALS(saprouter_talk_mode_vals), 0x0, "SAP Router Talk Mode", HFILL }},
		{ &hf_saprouter_rest_nodes,
			{ "Remaining Hops", "saprouter.restnodes", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Router Remaining Hops", HFILL }},
		{ &hf_saprouter_route_length,
			{ "Route String Length", "saprouter.routelength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Router Route String Length", HFILL }},
		{ &hf_saprouter_route_offset,
			{ "Route String Offset", "saprouter.routeoffset", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Router Route String Offset", HFILL }},
		{ &hf_saprouter_route,
			{ "Route String", "saprouter.routestring", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Router Route", HFILL }},
		{ &hf_saprouter_route_string,
			{ "Route Hop", "saprouter.routestring", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Router Route Hop", HFILL }},
		{ &hf_saprouter_route_string_hostname,
			{ "Hostname", "saprouter.routestring.hostname", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Route Hop Hostname", HFILL }},
		{ &hf_saprouter_route_string_service,
			{ "Service", "saprouter.routestring.service", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Route Hop Service", HFILL }},
		{ &hf_saprouter_route_string_password,
			{ "Password", "saprouter.routestring.password", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Route Hop Password", HFILL }},

		/* NI error information / Control messages */
		{ &hf_saprouter_opcode,
			{ "Operation Code", "saprouter.opcode", FT_UINT8, BASE_DEC, VALS(saprouter_opcode_vals), 0x0, "SAP Router Operation Code", HFILL }},
		{ &hf_saprouter_return_code,
			{ "Return Code", "saprouter.returncode", FT_INT32, BASE_DEC, VALS(saprouter_return_code_vals), 0x0, "SAP Router Return Code", HFILL }},
		{ &hf_saprouter_unknown,
			{ "Unknown field", "saprouter.unknown", FT_INT32, BASE_DEC, NULL, 0x0, "SAP Router Unknown field", HFILL }},

		/* NI Error Information messages */
		{ &hf_saprouter_error_length,
			{ "Error Information Text Length", "saprouter.errorlength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Router Error Information Text length", HFILL }},
		{ &hf_saprouter_error_string,
			{ "Error Information Text", "saprouter.errortext", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Router Error Information Text", HFILL }},
		{ &hf_saprouter_error_eyecatcher,
			{ "Eyecatcher", "saprouter.errortext.eyecatcher", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Eyecatcher", HFILL }},
		{ &hf_saprouter_error_counter,
			{ "Counter", "saprouter.errortext.counter", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Counter", HFILL }},
		{ &hf_saprouter_error_error,
			{ "Error", "saprouter.errortext.error", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Error", HFILL }},
		{ &hf_saprouter_error_return_code,
			{ "Return code", "saprouter.errortext.returncode", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Return Code", HFILL }},
		{ &hf_saprouter_error_component,
			{ "Component", "saprouter.errortext.component", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Component", HFILL }},
		{ &hf_saprouter_error_release,
			{ "Release", "saprouter.errortext.release", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Release", HFILL }},
		{ &hf_saprouter_error_version,
			{ "Version", "saprouter.errortext.version", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Version", HFILL }},
		{ &hf_saprouter_error_module,
			{ "Module", "saprouter.errortext.module", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Module", HFILL }},
		{ &hf_saprouter_error_line,
			{ "Line", "saprouter.errortext.line", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Line", HFILL }},
		{ &hf_saprouter_error_detail,
			{ "Detail", "saprouter.errortext.detail", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Detail", HFILL }},
		{ &hf_saprouter_error_time,
			{ "Time", "saprouter.errortext.time", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Time", HFILL }},
		{ &hf_saprouter_error_system_call,
			{ "System Call", "saprouter.errortext.system_call", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information System Call", HFILL }},
		{ &hf_saprouter_error_errorno,
			{ "Error Number", "saprouter.errortext.errorno", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Error Number", HFILL }},
		{ &hf_saprouter_error_errorno_text,
			{ "Error Number Text", "saprouter.errortext.errorno_text", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Error Number Text", HFILL }},
		{ &hf_saprouter_error_location,
			{ "Location", "saprouter.errortext.location", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Location", HFILL }},
		{ &hf_saprouter_error_error_count,
			{ "Error Count", "saprouter.errortext.error_count", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Error Count", HFILL }},
		{ &hf_saprouter_error_unknown,
			{ "Unknown field", "saprouter.errortext.unknown", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Error Information Unknown field", HFILL }},

		/* Control messages */
		{ &hf_saprouter_control_length,
			{ "Control Text Length", "saprouter.controllength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Router Control Text length", HFILL }},
		{ &hf_saprouter_control_string,
			{ "Control Text", "saprouter.controltext", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Control Text", HFILL }},

		/* Router Admin messages */
		{ &hf_saprouter_admin_command,
			{ "Admin Command", "saprouter.command", FT_UINT8, BASE_DEC, VALS(saprouter_admin_command_vals), 0x0, "SAP Router Admin Command", HFILL }},
		{ &hf_saprouter_admin_password,
			{ "Admin Command Info Password", "saprouter.password", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Admin Info Password", HFILL }},
		{ &hf_saprouter_admin_client_count_short,
			{ "Admin Command Client Count", "saprouter.client_count", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP Router Admin Client Count", HFILL }},
		{ &hf_saprouter_admin_client_count_int,
			{ "Admin Command Client Count", "saprouter.client_count", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Router Admin Client Count", HFILL }},
		{ &hf_saprouter_admin_client_ids,
			{ "Admin Command Client IDs", "saprouter.client_ids", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Router Admin Client IDs", HFILL }},
		{ &hf_saprouter_admin_client_id,
			{ "Admin Command Client ID", "saprouter.client_id", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Router Admin Client ID", HFILL }},
		{ &hf_saprouter_admin_address_mask,
			{ "Admin Command Address Mask", "saprouter.address_mask", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Router Admin Address Mask", HFILL }},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_saprouter
	};

	/* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_saprouter_route_password_found, { "saprouter.routestring.password", PI_SECURITY, PI_WARN, "Route password found", EXPFILL }},
		{ &ei_saprouter_info_password_found, { "saprouter.password", PI_SECURITY, PI_WARN, "Info password found", EXPFILL }},
		{ &ei_saprouter_route_invalid_length, { "saprouter.routestring.routelength.invalid", PI_MALFORMED, PI_WARN, "The route string length is invalid", EXPFILL }},
		{ &ei_saprouter_invalid_client_ids, { "saprouter.client_ids.invalid", PI_MALFORMED, PI_WARN, "Client IDs list is malformed", EXPFILL }},
	};

	module_t *saprouter_module;
	expert_module_t* saprouter_expert;

	/* Register the protocol */
	proto_saprouter = proto_register_protocol("SAP Router Protocol", "SAPROUTER", "saprouter");

	proto_register_field_array(proto_saprouter, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	saprouter_expert = expert_register_protocol(proto_saprouter);
	expert_register_field_array(saprouter_expert, ei, array_length(ei));

	register_dissector("saprouter", dissect_saprouter, proto_saprouter);

	/* Register the preferences */
	saprouter_module = prefs_register_protocol(proto_saprouter, proto_reg_handoff_saprouter);

	range_convert_str(&global_saprouter_port_range, SAPROUTER_PORT_RANGE, MAX_TCP_PORT);
	prefs_register_range_preference(saprouter_module, "tcp_ports", "SAP Router Protocol TCP port numbers", "Port numbers used for SAP Router Protocol (default " SAPROUTER_PORT_RANGE ")", &global_saprouter_port_range, MAX_TCP_PORT);

	prefs_register_bool_preference(saprouter_module, "snc_dissection", "Dissect SAP SNC frames", "Whether the SAP Router Protocol dissector should call the SAP SNC dissector for SNC frames", &global_saprouter_snc_dissection);

}


/**
 * Helpers for dealing with the port range
 */
static void range_delete_callback (guint32 port)
{
	dissector_delete_uint("sapni.port", port, saprouter_handle);
}

static void range_add_callback (guint32 port)
{
	dissector_add_uint("sapni.port", port, saprouter_handle);
}


void
proto_reg_handoff_saprouter(void)
{
	static gboolean initialized = FALSE;
	static range_t *saprouter_port_range;

	if (!initialized) {
		saprouter_handle = create_dissector_handle(dissect_saprouter, proto_saprouter);
		initialized = TRUE;
	} else {
		range_foreach(saprouter_port_range, range_delete_callback);
		g_free(saprouter_port_range);
	}

	saprouter_port_range = range_copy(global_saprouter_port_range);
	range_foreach(saprouter_port_range, range_add_callback);

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
