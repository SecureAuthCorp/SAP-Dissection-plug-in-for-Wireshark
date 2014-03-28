/*
## ===========
## SAP Dissector Plugin for Wireshark
##
## Copyright (C) 2014 Core Security Technologies
##
## The plugin was designed and developed by Martin Gallo from the Security
## Consulting Services team of Core Security Technologies.
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##==============
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/conversation.h>


/* Enqueue Server Type values */
static const value_string hf_sapenqueue_type_vals[] = {
	{  0, "SYNC_REQUEST" },
	{  1, "ASYNC_REQUEST" },
	{  2, "RESPONSE" },
};


/* Enqueue Server Destination values */
static const value_string hf_sapenqueue_dest_vals[] = {
	{  1, "SYNC_ENQUEUE" },
	{  2, "ASYNC_ENQUEUE" },
	{  3, "SERVER_ADMIN" },
	{  5, "STAT_QUERY" },
	{  6, "CONECTION_ADMIN" },
	{  7, "ENQ_TO_REP" },
	{  8, "REP_TO_ENQ" },
	{  0, NULL },
};


/* Enqueue Server Admin Opcode values */
static const value_string hf_sapenqueue_server_admin_opcode_vals[] = {
    {  1, "EnAdmDummyRequest" },
    {  2, "EnAdmShutdownRequest" },
    {  4, "EnAdmGetReplInfoRequest" },
    {  6, "EnAdmTraceRequest" },
	{  0, NULL },
};


/* Enqueue Server Connection Admin Opcode values */
static const value_string hf_sapenqueue_conn_admin_opcode_vals[] = {
	{  0, "Loopback packet" },
	{  1, "Parameter Request" },
	{  2, "Parameter Response" },
	{  3, "Shutdown Read" },
	{  4, "Shutdown Write" },
	{  5, "Shutdown Both" },
	{  6, "Keepalive" },
};


/* Enqueue Server Connection Admin Parameter values */
static const value_string hf_sapenqueue_conn_admin_param_vals[] = {
	{  0, "ENCPARAM_RECV_LEN" },
	{  1, "ENCPARAM_SEND_LEN" },
	{  2, "ENCPARAM_MSG_TYPE" },
	{  3, "ENCPARAM_SET_NAME" },
	{  4, "ENCPARAM_SET_NOSUPP" },
	{  5, "ENCPARAM_SET_VERSION" },
	{  6, "ENCPARAM_SET_UCSUPPORT" },
};

static int proto_sapenqueue = -1;

static int hf_sapenqueue_magic = -1;
static int hf_sapenqueue_id = -1;
static int hf_sapenqueue_length = -1;
static int hf_sapenqueue_length_frag = -1;
static int hf_sapenqueue_dest = -1;
static int hf_sapenqueue_conn_admin_opcode = -1;
static int hf_sapenqueue_more_frags = -1;
static int hf_sapenqueue_type = -1;

static int hf_sapenqueue_server_admin = -1;
static int hf_sapenqueue_server_admin_eyecatcher = -1;
static int hf_sapenqueue_server_admin_version = -1;
static int hf_sapenqueue_server_admin_flag = -1;
static int hf_sapenqueue_server_admin_length = -1;
static int hf_sapenqueue_server_admin_opcode = -1;
static int hf_sapenqueue_server_admin_flags = -1;
static int hf_sapenqueue_server_admin_rc = -1;
static int hf_sapenqueue_server_admin_value = -1;

static int hf_sapenqueue_server_admin_trace_request = -1;

static int hf_sapenqueue_conn_admin = -1;
static int hf_sapenqueue_conn_admin_params_count = -1;
static int hf_sapenqueue_conn_admin_params = -1;
static int hf_sapenqueue_conn_admin_param = -1;
static int hf_sapenqueue_conn_admin_param_id = -1;
static int hf_sapenqueue_conn_admin_param_len = -1;
static int hf_sapenqueue_conn_admin_param_value = -1;
static int hf_sapenqueue_conn_admin_param_name = -1;

static gint ett_sapenqueue = -1;

/* Protocol handle */
static dissector_handle_t sapenqueue_handle;


/*
 *
 */
void proto_reg_handoff_sapenqueue(void);


static void
dissect_sapenqueue_server_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset){
	guint8 opcode = 0;
	proto_item *server_admin = NULL;
	proto_tree *server_admin_tree = NULL;

	server_admin = proto_tree_add_item(tree, hf_sapenqueue_server_admin, tvb, offset, -1, FALSE);
	server_admin_tree = proto_item_add_subtree(server_admin, ett_sapenqueue);

    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_eyecatcher, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_version, tvb, offset, 1, FALSE); offset += 1;
    offset += 3;  /* Unknown bytes */
    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_eyecatcher, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_flag, tvb, offset, 1, FALSE); offset += 1;
    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_length, tvb, offset, 4, FALSE); offset += 4;
    opcode = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_opcode, tvb, offset, 1, FALSE); offset += 1;
    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_flags, tvb, offset, 1, FALSE); offset += 1;
    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_rc, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_eyecatcher, tvb, offset, 4, FALSE); offset += 4;

    if (tvb_length_remaining(tvb, offset) > 0){
    	proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_value, tvb, offset, -1, FALSE);

    	switch(opcode){
    		case 0x06:{		/* EnAdmTraceRequest */
    			proto_item *trace_request = NULL;
    			proto_tree *trace_request_tree = NULL;

    			trace_request = proto_tree_add_item(server_admin_tree, hf_sapenqueue_server_admin_trace_request, tvb, offset, -1, FALSE);
    			trace_request_tree = proto_item_add_subtree(trace_request, ett_sapenqueue);

    			/* TODO: Dissect the trace request fields */
    			break;
    		}
    	}
    }

}


static void
dissect_sapenqueue_conn_admin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint8 opcode){
	proto_item *conn_admin = NULL;
	proto_tree *conn_admin_tree = NULL;

	conn_admin = proto_tree_add_item(tree, hf_sapenqueue_conn_admin, tvb, offset, -1, FALSE);
	conn_admin_tree = proto_item_add_subtree(conn_admin, ett_sapenqueue);

	switch (opcode){
		case 0x01:		/* Parameter Request */
		case 0x02:{		/* Parameter Response */
			guint8 length = 0, total_length = 0;
			guint32 count = 0, id = 0, name_length = 0;
			proto_item *params = NULL, *param = NULL;
			proto_tree *params_tree = NULL, *param_tree = NULL;

			count = tvb_get_ntohl(tvb, offset);
	        proto_tree_add_item(conn_admin_tree, hf_sapenqueue_conn_admin_params_count, tvb, offset, 4, FALSE); offset += 4;

	        params = proto_tree_add_item(conn_admin_tree, hf_sapenqueue_conn_admin_params, tvb, offset, 1, FALSE);
	        params_tree = proto_item_add_subtree(params, ett_sapenqueue);

	        while (count > 0 && tvb_offset_exists(tvb, offset)){
	        	/* As we don't have the right size yet, start with 1 byte */
	        	param = proto_tree_add_item(params_tree, hf_sapenqueue_conn_admin_param, tvb, offset, 1, FALSE);
	        	param_tree = proto_item_add_subtree(param, ett_sapenqueue);

	        	id = tvb_get_ntohl(tvb, offset);
	        	proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_id, tvb, offset, 4, FALSE); offset += 4;
	        	length = 4;

	        	if (id == 0x03){	/* Set Name parameter */
	        		name_length = tvb_strsize(tvb, offset);
					proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_name, tvb, offset, name_length, FALSE); offset += name_length;
					length += name_length;

				} else {
					if (id == 0x06){  /* Set Unicode Support Parameter */
						proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_len, tvb, offset, 4, FALSE); offset += 4;
						length += 4;
					}
					proto_tree_add_item(param_tree, hf_sapenqueue_conn_admin_param_value, tvb, offset, 4, FALSE); offset += 4;
					length += 4;
	        	}

	        	/* Set the right size for the parameter tree */
	        	proto_item_set_len(param, length);

	        	count -= 1;
	        	total_length += length;
	        }

	        proto_item_set_len(params, total_length);

			break;
		}
	}

}


static void
dissect_sapenqueue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 dest = 0, type = 0, opcode = 0;
	guint32 offset = 4;
	proto_item *ti = NULL;
	proto_tree *sapenqueue_tree = NULL;

	/* If the packet has less than 20 bytes we can be sure that is not an
	 * Enqueue server packet.
	 */
	if (tvb_length(tvb) < 20){
		return;
	}

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPENQUEUE");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	dest = tvb_get_guint8(tvb, offset + 16);
    col_append_fstr(pinfo->cinfo, COL_INFO, "Dest=%s", val_to_str(dest, hf_sapenqueue_dest_vals, "Unknown"));

	opcode = tvb_get_guint8(tvb, offset + 17);
	type = tvb_get_guint8(tvb, offset + 19);
    col_append_fstr(pinfo->cinfo, COL_INFO, ",Type=%s", val_to_str(type, hf_sapenqueue_type_vals, "Unknown"));

    if (dest == 0x06){
    	col_append_fstr(pinfo->cinfo, COL_INFO, ",Opcode=%s", val_to_str(opcode, hf_sapenqueue_conn_admin_opcode_vals, "Unknown"));
    }


	if (tree){ /* we are being asked for details */

		/* Add the main sapenqueue subtree */
		ti = proto_tree_add_item(tree, proto_sapenqueue, tvb, 0, -1, FALSE);
		sapenqueue_tree = proto_item_add_subtree(ti, ett_sapenqueue);

        proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_magic, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_id, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_length, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_length_frag, tvb, offset, 4, FALSE); offset += 4;
        proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_dest, tvb, offset, 1, FALSE); offset += 1;
        if (dest == 0x06){ // This field is only relevant if the destination is Connection Admin
        	proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_conn_admin_opcode, tvb, offset, 1, FALSE);
		}
        offset += 1;
        proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_more_frags, tvb, offset, 1, FALSE); offset += 1;
        proto_tree_add_item(sapenqueue_tree, hf_sapenqueue_type, tvb, offset, 1, FALSE); offset += 1;

    	switch (dest){
    		case 0x03:{		/* Server Admin */
    			dissect_sapenqueue_server_admin(tvb, pinfo, sapenqueue_tree, offset);
    			break;
    		}
    		case 0x06:{		/* Connection Admin */
    			dissect_sapenqueue_conn_admin(tvb, pinfo, sapenqueue_tree, offset, opcode);
    			break;
    		}
    	}
	}

}


static gboolean
dissect_sapenqueue_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data){
    conversation_t *conversation = NULL;

	/* If the first 4 bytes are the magic bytes, we can guess that the
	 * packet is a Enqueue server packet.
	 */
	if (tvb_get_ntohl(tvb, 0) != 0xabcde123){
		return (FALSE);
	}

	/* From now on this conversation is dissected as SAP Enqueue traffic */
	conversation = find_or_create_conversation(pinfo);
	conversation_set_dissector(conversation, sapenqueue_handle);

	/* Now dissect the packet */
	dissect_sapenqueue(tvb, pinfo, tree);

	return (TRUE);
}


void
proto_register_sapenqueue(void)
{
    static hf_register_info hf[] = {
		/* General Header fields */
		{ &hf_sapenqueue_magic,
			{ "Magic Bytes", "sapenque.magic", FT_BYTES, BASE_NONE, NULL, 0x0, "SAP Enqueue Magic Bytes", HFILL }},
		{ &hf_sapenqueue_id,
			{ "ID", "sapenque.id", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Enqueue ID", HFILL }},
		{ &hf_sapenqueue_length,
			{ "Length", "sapenque.length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Enqueue Length", HFILL }},
		{ &hf_sapenqueue_length_frag,
			{ "Fragment Length", "sapenque.fragment_length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Enqueue Fragment Length", HFILL }},
		{ &hf_sapenqueue_dest,
			{ "Destination", "sapenque.destination", FT_UINT8, BASE_DEC, hf_sapenqueue_dest_vals, 0x0, "SAP Enqueue Destination", HFILL }},
		{ &hf_sapenqueue_conn_admin_opcode,
			{ "Opcode", "sapenque.opcode", FT_UINT8, BASE_DEC, hf_sapenqueue_conn_admin_opcode_vals, 0x0, "SAP Enqueue Opcode", HFILL }},
		{ &hf_sapenqueue_more_frags,
			{ "More Fragments", "sapenque.more_frags", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Enqueue More Fragments", HFILL }},
		{ &hf_sapenqueue_type,
			{ "Type", "sapenque.type", FT_UINT8, BASE_DEC, hf_sapenqueue_type_vals, 0x0, "SAP Enqueue Type", HFILL }},

		/* Server Admin fields */
		{ &hf_sapenqueue_server_admin,
			{ "Server Admin", "sapenque.server_admin", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Enqueue Server Admin", HFILL }},
		{ &hf_sapenqueue_server_admin_eyecatcher,
			{ "Eye Catcher", "sapenque.server_admin.eyecatcher", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Enqueue Server Admin Eye Catcher", HFILL }},
		{ &hf_sapenqueue_server_admin_version,
			{ "Version", "sapenque.server_admin.version", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Enqueue Server Admin Version", HFILL }},
		{ &hf_sapenqueue_server_admin_flag,
			{ "Flag", "sapenque.server_admin.flag", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Enqueue Server Admin Flag", HFILL }},
		{ &hf_sapenqueue_server_admin_length,
			{ "Length", "sapenque.server_admin.length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Enqueue Server Admin Length", HFILL }},
		{ &hf_sapenqueue_server_admin_opcode,
			{ "Opcode", "sapenque.server_admin.opcode", FT_UINT8, BASE_DEC, hf_sapenqueue_server_admin_opcode_vals, 0x0, "SAP Enqueue Server Admin Opcode", HFILL }},
		{ &hf_sapenqueue_server_admin_flags,
			{ "Flags", "sapenque.server_admin.flags", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Enqueue Server Admin Flags", HFILL }},
		{ &hf_sapenqueue_server_admin_rc,
			{ "Return Code", "sapenque.server_admin.rc", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Enqueue Server Admin Return Code", HFILL }},
		{ &hf_sapenqueue_server_admin_value,
			{ "Value", "sapenque.server_admin.value", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Enqueue Server Admin Value", HFILL }},

		/* Trace Request fields */
		{ &hf_sapenqueue_server_admin_trace_request,
			{ "Trace Request", "sapenque.server_admin.trace", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Enqueue Server Admin Trace Request", HFILL }},

		/* Connection Admin fields */
		{ &hf_sapenqueue_conn_admin,
			{ "Connection Admin", "sapenque.conn_admin", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Enqueue Connection Admin", HFILL }},
		{ &hf_sapenqueue_conn_admin_params_count,
			{ "Parameters Count", "sapenque.conn_admin.params.count", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Enqueue Connection Admin Parameters Count", HFILL }},
		{ &hf_sapenqueue_conn_admin_params,
			{ "Parameters", "sapenque.conn_admin.params", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Enqueue Connection Admin Parameters", HFILL }},
		{ &hf_sapenqueue_conn_admin_param,
			{ "Parameter", "sapenque.conn_admin.params.param", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Enqueue Connection Admin Parameter", HFILL }},
		{ &hf_sapenqueue_conn_admin_param_id,
			{ "Parameter ID", "sapenque.conn_admin.params.param.id", FT_UINT32, BASE_DEC, hf_sapenqueue_conn_admin_param_vals, 0x0, "SAP Enqueue Connection Admin Parameter ID", HFILL }},
		{ &hf_sapenqueue_conn_admin_param_len,
			{ "Parameter Length", "sapenque.conn_admin.params.param.length", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Enqueue Connection Admin Parameter Length", HFILL }},
		{ &hf_sapenqueue_conn_admin_param_value,
			{ "Parameter Value", "sapenque.conn_admin.params.param.value", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Enqueue Connection Admin Parameter Value", HFILL }},
		{ &hf_sapenqueue_conn_admin_param_name,
			{ "Parameter Name", "sapenque.conn_admin.params.param.name", FT_STRINGZ, BASE_NONE, NULL, 0x0, "SAP Enqueue Connection Admin Parameter Name", HFILL }},

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_sapenqueue
    };

    /* Register the protocol */
    proto_sapenqueue = proto_register_protocol (
        "SAP Enqueue Protocol",    /* name       */
        "SAPENQUEUE",        /* short name */
        "sapenqueue"        /* abbrev     */
    );

    proto_register_field_array(proto_sapenqueue, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("sapenqueue", dissect_sapenqueue, proto_sapenqueue);

}


void
proto_reg_handoff_sapenqueue(void)
{
	sapenqueue_handle = create_dissector_handle(dissect_sapenqueue, proto_sapenqueue);

    /* Register the heuristic dissector. We need to use a heuristic dissector
     * here as the Enqueue Server uses the same port number that the Dispatcher
     * Service (32NN/tcp). */
    heur_dissector_add("sapni", dissect_sapenqueue_heur, proto_sapenqueue);

}
