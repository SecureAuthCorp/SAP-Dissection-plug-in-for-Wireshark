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


/* SAP HDB Segment Kind values */
static const value_string saphdb_segment_segmentkind_vals[] = {
	{ 0, "Invalid" },
	{ 1, "Request" },
	{ 2, "Reply" },
	{ 5, "Error" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP HDB Segment Message Type values */
static const value_string saphdb_segment_messagetype_vals[] = {
	{ 0, "NIL" },
	{ 2, "EXECUTEDIRECT" },
	{ 3, "PREPARE" },
	{ 4, "ABAPSTREAM" },
	{ 5, "XA_START" },
	{ 6, "XA_JOIN" },
	{ 7, "XA_COMMIT" },
	{ 13, "EXECUTE" },
	{ 16, "READLOB" },
	{ 17, "WRITELOB" },
	{ 18, "FINDLOB" },
	{ 25, "PING" },
	{ 65, "AUTHENTICATE" },
	{ 66, "CONNECT" },
	{ 67, "COMMIT" },
	{ 68, "ROLLBACK" },
	{ 69, "CLOSERESULTSET" },
	{ 70, "DROPSTATEMENTID" },
	{ 71, "FETCHNEXT" },
	{ 72, "FETCHABSOLUTE" },
	{ 73, "FETCHRELATIVE" },
	{ 74, "FETCHFIRST" },
	{ 75, "FETCHLAST" },
	{ 77, "DISCONNECT" },
	{ 78, "EXECUTEITAB" },
	{ 79, "FETCHNEXTITAB" },
	{ 80, "INSERTNEXTITAB" },
	{ 81, "BATCHPREPARE" },
	{ 82, "DBCONNECTINFO" },
	{ 83, "XOPEN_XASTART" },
	{ 84, "XOPEN_XAEND" },
	{ 85, "XOPEN_XAPREPARE" },
	{ 86, "XOPEN_XACOMMIT" },
	{ 87, "XOPEN_XAROLLBACK" },
	{ 88, "XOPEN_XARECOVER" },
	{ 89, "XOPEN_XAFORGET" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP HDB Segment Function Code values */
static const value_string saphdb_segment_functioncode_vals[] = {
	{ 0, "NIL" },
	{ 1, "DDL" },
	{ 2, "INSERT" },
	{ 3, "UPDATE" },
	{ 4, "DELETE" },
	{ 5, "SELECT" },
	{ 6, "SELECTFORUPDATE" },
	{ 7, "EXPLAIN" },
	{ 8, "DBPROCEDURECALL" },
	{ 9, "DBPROCEDURECALLWITHRESULT" },
	{ 10, "FETCH" },
	{ 11, "COMMIT" },
	{ 12, "ROLLBACK" },
	{ 13, "SAVEPOINT" },
	{ 14, "CONNECT" },
	{ 15, "WRITELOB" },
	{ 16, "READLOB" },
	{ 17, "PING" },
	{ 18, "DISCONNECT" },
	{ 19, "CLOSECURSOR" },
	{ 20, "FINDLOB" },
	{ 21, "ABAPSTREAM" },
	{ 22, "XASTART" },
	{ 23, "XAJOIN" },
	{ 24, "ITABWRITE" },
	{ 25, "XOPEN_XACONTROL" },
	{ 26, "XOPEN_XAPREPARE" },
	{ 27, "XOPEN_XARECOVER" },
	/* NULL */
	{ 0x00, NULL }
};


/* SAP HDB Part Kind values */
static const value_string saphdb_part_partkind_vals[] = {
	{ 0, "NIL" },
	{ 3, "COMMAND" },
	{ 5, "RESULTSET" },
	{ 6, "ERROR" },
	{ 10, "STATEMENTID" },
	{ 11, "TRANSACTIONID" },
	{ 12, "ROWSAFFECTED" },
	{ 13, "RESULTSETID" },
	{ 15, "TOPOLOGYINFORMATION" },
	{ 16, "TABLELOCATION" },
	{ 17, "READLOBREQUEST" },
	{ 18, "READLOBREPLY" },
	{ 25, "ABAPISTREAM" },
	{ 26, "ABAPOSTREAM" },
	{ 27, "COMMANDINFO" },
	{ 28, "WRITELOBREQUEST" },
	{ 29, "CLIENTCONTEXT" },
	{ 30, "WRITELOBREPLY" },
	{ 32, "PARAMETERS" },
	{ 33, "AUTHENTICATION" },
	{ 34, "SESSIONCONTEXT" },
	{ 35, "CLIENTID" },
	{ 38, "PROFILE" },
	{ 39, "STATEMENTCONTEXT" },
	{ 40, "PARTITIONINFORMATION" },
	{ 41, "OUTPUTPARAMETERS" },
	{ 42, "CONNECTOPTIONS" },
	{ 43, "COMMITOPTIONS" },
	{ 44, "FETCHOPTIONS" },
	{ 45, "FETCHSIZE" },
	{ 47, "PARAMETERMETADATA" },
	{ 48, "RESULTSETMETADATA" },
	{ 49, "FINDLOBREQUEST" },
	{ 50, "FINDLOBREPLY" },
	{ 51, "ITABSHM" },
	{ 53, "ITABCHUNKMETADATA" },
	{ 55, "ITABMETADATA" },
	{ 56, "ITABRESULTCHUNK" },
	{ 57, "CLIENTINFO" },
	{ 58, "STREAMDATA" },
	{ 59, "OSTREAMRESULT" },
	{ 60, "FDAREQUESTMETADATA" },
	{ 61, "FDAREPLYMETADATA" },
	{ 62, "BATCHPREPARE" },
	{ 63, "BATCHEXECUTE" },
	{ 64, "TRANSACTIONFLAGS" },
	{ 65, "ROWSLOTIMAGEPARAMMETADATA" },
	{ 66, "ROWSLOTIMAGERESULTSET" },
	{ 67, "DBCONNECTINFO" },
	{ 68, "LOBFLAGS" },
	{ 69, "RESULTSETOPTIONS" },
	{ 70, "XATRANSACTIONINFO" },
	{ 71, "SESSIONVARIABLE" },
	{ 72, "WORKLOADREPLAYCONTEXT" },
	{ 73, "SQLREPLYOTIONS" },
	/* NULL */
	{ 0x00, NULL }
};


static int proto_saphdb = -1;

/* SAP HDB Initialization items */
static int hf_saphdb_initialization_request = -1;
static int hf_saphdb_initialization_reply = -1;
static int hf_saphdb_initialization_reply_product_version_major = -1;
static int hf_saphdb_initialization_reply_product_version_minor = -1;
static int hf_saphdb_initialization_reply_protocol_version_major = -1;
static int hf_saphdb_initialization_reply_protocol_version_minor = -1;

/* SAP HDB Message Header items */
static int hf_saphdb_message_header = -1;
static int hf_saphdb_message_header_sessionid = -1;
static int hf_saphdb_message_header_packetcount = -1;
static int hf_saphdb_message_header_varpartlength = -1;
static int hf_saphdb_message_header_varpartsize = -1;
static int hf_saphdb_message_header_noofsegm = -1;
static int hf_saphdb_message_header_packetoptions = -1;
static int hf_saphdb_message_header_compressionvarpartlength = -1;
/* SAP HDB Message Buffer items */
static int hf_saphdb_message_buffer = -1;

/* SAP HDB Segment items */
static int hf_saphdb_segment = -1;
static int hf_saphdb_segment_segmentlength = -1;
static int hf_saphdb_segment_segmentofs = -1;
static int hf_saphdb_segment_noofparts = -1;
static int hf_saphdb_segment_segmentno = -1;
static int hf_saphdb_segment_segmentkind = -1;
static int hf_saphdb_segment_messagetype = -1;
static int hf_saphdb_segment_commit = -1;
static int hf_saphdb_segment_commandoptions = -1;
static int hf_saphdb_segment_functioncode = -1;
/* SAP HDB Segment Buffer items */
static int hf_saphdb_segment_buffer = -1;

/* SAP HDB Part items */
static int hf_saphdb_part = -1;
static int hf_saphdb_part_partkind = -1;
static int hf_saphdb_part_partattributes = -1;
static int hf_saphdb_part_argumentcount = -1;
static int hf_saphdb_part_bigargumentcount = -1;
static int hf_saphdb_part_bufferlength = -1;
static int hf_saphdb_part_buffersize = -1;
/* SAP HDB Part Buffer items */
static int hf_saphdb_part_buffer = -1;

/* SAP HDB Part Buffer AUTHENTICATE items */
static int hf_saphdb_part_authentication_field_count = -1;
static int hf_saphdb_part_authentication_field_length = -1;
static int hf_saphdb_part_authentication_field_value = -1;


static gint ett_saphdb = -1;


/* Global port preference */
static range_t *global_saphdb_port_range;


/* Protocol handle */
static dissector_handle_t saphdb_handle;

void proto_reg_handoff_saphdb(void);


static int
dissect_saphdb_part_buffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 length, guint8 partkind)
{
	guint8 field_short_length = 0;
	guint16 field_count = 0, field_length = 0;

	switch (partkind) {
		case 29:  // CLIENTCONTEXT

			
			offset += length;
			break;

		case 33:  // AUTHENTICATION

			/* Parse the field count */
			field_count = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tree, hf_saphdb_part_authentication_field_count, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length -= 2;

			for (guint16 field = 0; field < field_count; field++) {

				/* Parse the field length. If the first byte is 0xFF, the length is contained in the next 2 bytes */
				field_short_length = tvb_get_guint8(tvb, offset);
				if (field_short_length == 0xff) {
					offset += 1; length -= 1;
					field_length = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
					proto_tree_add_item(tree, hf_saphdb_part_authentication_field_length, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length -= 2;
				} else {
					proto_tree_add_item(tree, hf_saphdb_part_authentication_field_length, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length -= 1;
					field_length = field_short_length;
				}

				/* Add the field value */
				proto_tree_add_item(tree, hf_saphdb_part_authentication_field_value, tvb, offset, field_length, ENC_NA); offset += field_length; length -= field_length;

			}

			offset += length;
			break;

		default:
			offset += length;
	}

	return length;
}


static int
dissect_saphdb_part(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint32 offset, guint16 noofparts, guint16 nopart)
{
	guint8 partkind = 0;
	guint32 length = 0, bufferlength = 0;
	proto_item *part = NULL, *part_buffer = NULL;
	proto_tree *part_tree = NULL, *part_buffer_tree = NULL;

	/* Add the Part subtree */
	part = proto_tree_add_item(tree, hf_saphdb_part, tvb, offset, 16, ENC_NA);
	part_tree = proto_item_add_subtree(part, ett_saphdb);
	proto_item_append_text(part, " (%d/%d)", nopart, noofparts);

	/* Add the Part fields */
	partkind = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(part_tree, hf_saphdb_part_partkind, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;
	proto_tree_add_item(part_tree, hf_saphdb_part_partattributes, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;
	proto_tree_add_item(part_tree, hf_saphdb_part_argumentcount, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length += 2;
	proto_tree_add_item(part_tree, hf_saphdb_part_bigargumentcount, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;
	bufferlength = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(part_tree, hf_saphdb_part_bufferlength, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;
	proto_tree_add_item(part_tree, hf_saphdb_part_buffersize, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;

	/* Align the buffer length to 8 */
	if (bufferlength % 8 != 0) {
		bufferlength += 8 - bufferlength % 8;
	}

	if (tvb_reported_length_remaining(tvb, offset) < bufferlength) {
		/* TODO: Expert report as the part buffer length is invalid */
		bufferlength = tvb_reported_length_remaining(tvb, offset);
	}

  /* Add the part buffer tree and dissect it */
	part_buffer = proto_tree_add_item(part_tree, hf_saphdb_part_buffer, tvb, offset, bufferlength, ENC_NA);
	part_buffer_tree = proto_item_add_subtree(part_buffer, ett_saphdb);

	dissect_saphdb_part_buffer(tvb, pinfo, part_buffer_tree, offset, bufferlength, partkind);
	offset += bufferlength; length += bufferlength;

	/* Adjust the item tree length */
	proto_item_set_len(part_tree, length);

	return length;
}


static int
dissect_saphdb_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint32 offset, guint16 noofsegm, guint16 nosegment)
{
	guint8 segmentkind = 0;  // XXX: This should be a gint8
	guint16 noofparts = 0, segmentno = 0, nopart = 0;  // XXX: This should be a gint16
	guint32 length = 0, part_length = 0;
	guint32 segmentlength = 0;  // XXX: This should be a gint32
	proto_item *segment = NULL, *segment_buffer = NULL;
	proto_tree *segment_tree = NULL, *segment_buffer_tree = NULL;

	/* Add the Segment subtree */
	segment = proto_tree_add_item(tree, hf_saphdb_segment, tvb, offset, 13, ENC_NA);
	segment_tree = proto_item_add_subtree(segment, ett_saphdb);
	proto_item_append_text(segment, " (%d/%d)", nosegment, noofsegm);

	/* Add the Segment fields */
	segmentlength = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(segment_tree, hf_saphdb_segment_segmentlength, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;
	proto_tree_add_item(segment_tree, hf_saphdb_segment_segmentofs, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;
	noofparts = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(segment_tree, hf_saphdb_segment_noofparts, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length += 2;
	segmentno = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(segment_tree, hf_saphdb_segment_segmentno, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length += 2;
	segmentkind = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(segment_tree, hf_saphdb_segment_segmentkind, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;

	if (nosegment != segmentno) {
			/* TODO: Expert reporting as the segments are probably not ordered or are incorrect */
	}

	/* Add additional fields according to the segment kind*/
	switch (segmentkind) {
		case 1: /* Request */
			proto_tree_add_item(segment_tree, hf_saphdb_segment_messagetype, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;
			proto_tree_add_item(segment_tree, hf_saphdb_segment_commit, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;
			proto_tree_add_item(segment_tree, hf_saphdb_segment_commandoptions, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;
			offset += 8; length += 8; // Reserved1 field
			break;
		case 2: /* Reply */
			offset += 1; length += 1; // Reserved2 field
			proto_tree_add_item(segment_tree, hf_saphdb_segment_functioncode, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length += 2;
			offset += 8; length += 8; // Reserved3 field
			break;
		default: /* Error and other types */
			offset += 11; length += 11; // Reserved or unused fields
			break;
	}

	if (noofparts < 0) {
		/* TODO: Expert report as the number of parts is incorrect */
	}

	/* Add the Segment Buffer subtree */
	segment_buffer = proto_tree_add_item(segment_tree, hf_saphdb_segment_buffer, tvb, offset, segmentlength - length, ENC_NA);
	segment_buffer_tree = proto_item_add_subtree(segment_buffer, ett_saphdb);

	/* Iterate over the parts and dissect them */
	for (nopart = 1; nopart > 0 && nopart <= noofparts && tvb_reported_length_remaining(tvb, offset) >= 16; nopart++) {
		part_length = dissect_saphdb_part(tvb, pinfo, segment_buffer_tree, NULL, offset, noofparts, nopart);
		offset += part_length; length += part_length;
	}

	/* Adjust the item tree length */
	proto_item_set_len(segment_tree, length);

	return length;
}


static int
dissect_saphdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPHDB");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	/* we are being asked for details */
	if (tree && (tvb_reported_length(tvb) == 8 || tvb_reported_length(tvb) == 14 || tvb_reported_length(tvb) >= 32)) {

		guint32 offset = 0;
		proto_item *ti = NULL;
		proto_tree *saphdb_tree = NULL;

		/* Add the main saphdb subtree */
		ti = proto_tree_add_item(tree, proto_saphdb, tvb, offset, -1, ENC_NA);
		saphdb_tree = proto_item_add_subtree(ti, ett_saphdb);


		/* Initialization Request message */
		if (tvb_reported_length(tvb) == 14) {
			proto_tree_add_item(saphdb_tree, hf_saphdb_initialization_request, tvb, offset, 14, ENC_NA); offset += 14;

		/* Initialization Reply message */
		} else if (tvb_reported_length(tvb) == 8) {
			proto_item *initialization_reply = NULL;
			proto_tree *initialization_reply_tree = NULL;

			/* Add the Initialiation Reply subtree */
			initialization_reply = proto_tree_add_item(saphdb_tree, hf_saphdb_initialization_reply, tvb, offset, 8, ENC_NA);
			initialization_reply_tree = proto_item_add_subtree(initialization_reply, ett_saphdb);

			proto_tree_add_item(initialization_reply_tree, hf_saphdb_initialization_reply_product_version_major, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1;
			proto_tree_add_item(initialization_reply_tree, hf_saphdb_initialization_reply_product_version_minor, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
			proto_tree_add_item(initialization_reply_tree, hf_saphdb_initialization_reply_protocol_version_major, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1;
			proto_tree_add_item(initialization_reply_tree, hf_saphdb_initialization_reply_protocol_version_minor, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;

		/* All other message types */
		} else if (tvb_reported_length(tvb) >= 32) {

			guint16 noofsegm = 0, nosegment = 0;  // XXX: This should be gint16
			guint32 varpartlength = 0, varpartsize = 0;  // XXX: This should be gint32
			proto_item *message_header = NULL, *message_buffer = NULL;
			proto_tree *message_header_tree = NULL, *message_buffer_tree = NULL;

			/* Add the Message Header subtree */
			message_header = proto_tree_add_item(saphdb_tree, hf_saphdb_message_header, tvb, offset, 32, ENC_NA);
			message_header_tree = proto_item_add_subtree(message_header, ett_saphdb);

			/* Add the Message Header fields */
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_sessionid, tvb, offset, 8, ENC_LITTLE_ENDIAN); offset += 8;
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_packetcount, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
			varpartlength = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_varpartlength, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_varpartsize, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
			noofsegm = tvb_get_letohs(tvb, offset);
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_noofsegm, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_packetoptions, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1;
			offset += 1;  /* Reserved1 field */
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_compressionvarpartlength, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
			offset += 4;  /* Reserved2 field */

			if (tvb_reported_length_remaining(tvb, offset) != varpartlength) {
				/* TODO: Expert report as the length is incorrect */
				varpartlength = tvb_reported_length_remaining(tvb, offset);
			}
			if (noofsegm < 0) {
				/* TODO: Expert report as the number of segments is incorrect */
			}

			/* Add the Message Buffer subtree */
			message_buffer = proto_tree_add_item(saphdb_tree, hf_saphdb_message_buffer, tvb, offset, varpartlength, ENC_NA);
			message_buffer_tree = proto_item_add_subtree(message_buffer, ett_saphdb);

			/* Iterate over the segments and dissect them */
			for (nosegment = 1; noofsegm > 0 && nosegment <= noofsegm && tvb_reported_length_remaining(tvb, offset) >= 13; nosegment++) {
				offset += dissect_saphdb_segment(tvb, pinfo, message_buffer_tree, NULL, offset, noofsegm, nosegment);
			}

		}

	}

	return tvb_reported_length(tvb);
}

void
proto_register_saphdb(void)
{
	static hf_register_info hf[] = {
		/* Initialization items */
		{ &hf_saphdb_initialization_request,
			{ "Initialization Request", "saphdb.init_request", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Initialization Request", HFILL }},

		{ &hf_saphdb_initialization_reply,
			{ "Initialization Reply", "saphdb.init_reply", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Initialization Reply", HFILL }},
		{ &hf_saphdb_initialization_reply_product_version_major,
			{ "Product Version Major", "saphdb.init_reply.product_version.major", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Initialization Reply Product Version Major", HFILL }},
		{ &hf_saphdb_initialization_reply_product_version_minor,
			{ "Product Version Minor", "saphdb.init_reply.product_version.minor", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP HDB Initialization Reply Product Version Minor", HFILL }},
		{ &hf_saphdb_initialization_reply_protocol_version_major,
			{ "Protocol Version Major", "saphdb.init_reply.protocol_version.major", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Initialization Reply Protocol Version Major", HFILL }},
		{ &hf_saphdb_initialization_reply_protocol_version_minor,
			{ "Protocol Version Minor", "saphdb.init_reply.protocol_version.minor", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP HDB Initialization Reply Protocol Version Minor", HFILL }},

		/* Message Header items */
		{ &hf_saphdb_message_header,
			{ "Message Header", "saphdb.message_header", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Message Header", HFILL }},
		{ &hf_saphdb_message_header_sessionid,
			{ "Session ID", "saphdb.sessionid", FT_INT64, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Session ID", HFILL }},
		{ &hf_saphdb_message_header_packetcount,
			{ "Packet Count", "saphdb.packetcount", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Packet Count", HFILL }},
		{ &hf_saphdb_message_header_varpartlength,
			{ "Var Part Length", "saphdb.varpartlength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Var Part Length", HFILL }},
		{ &hf_saphdb_message_header_varpartsize,
			{ "Var Part Size", "saphdb.varpartsize", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Var Part Size", HFILL }},
		{ &hf_saphdb_message_header_noofsegm,
			{ "Number of Segments", "saphdb.noofsegm", FT_INT16, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Number of Segments", HFILL }},
		{ &hf_saphdb_message_header_packetoptions,
			{ "Packet Options", "saphdb.packetoptions", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Packet Options", HFILL }},
		{ &hf_saphdb_message_header_compressionvarpartlength,
			{ "Compression Var Part Length", "saphdb.compressionvarpartlength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Compression Var Part Length", HFILL }},

		/* Message Buffer items */
		{ &hf_saphdb_message_buffer,
			{ "Message Buffer", "saphdb.buffer", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Message Buffer", HFILL }},

		/* Segment items */
		{ &hf_saphdb_segment,
			{ "Segment", "saphdb.segment", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Segment", HFILL }},
		{ &hf_saphdb_segment_segmentlength,
			{ "Segment Length", "saphdb.segment.length", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Segment Length", HFILL }},
		{ &hf_saphdb_segment_segmentofs,
			{ "Segment Offset", "saphdb.segment.offset", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Segment Offset", HFILL }},
		{ &hf_saphdb_segment_noofparts,
			{ "Number of Parts", "saphdb.segment.noofparts", FT_INT16, BASE_DEC, NULL, 0x0, "SAP HDB Segment Number of Parts", HFILL }},
		{ &hf_saphdb_segment_segmentno,
			{ "Segment Number", "saphdb.segment.segmentno", FT_INT16, BASE_DEC, NULL, 0x0, "SAP HDB Segment Number", HFILL }},
		{ &hf_saphdb_segment_segmentkind,
			{ "Segment Kind", "saphdb.segment.kind", FT_INT8, BASE_DEC, VALS(saphdb_segment_segmentkind_vals), 0x0, "SAP HDB Segment Kind", HFILL }},
		{ &hf_saphdb_segment_messagetype,
			{ "Message Type", "saphdb.segment.messagetype", FT_INT8, BASE_DEC, VALS(saphdb_segment_messagetype_vals), 0x0, "SAP HDB Segment Message Type", HFILL }},
		{ &hf_saphdb_segment_commit,
			{ "Commit", "saphdb.segment.commit", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Segment Commit", HFILL }},
		{ &hf_saphdb_segment_commandoptions,
			{ "Command Options", "saphdb.segment.commandoptions", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Segment Command Options", HFILL }},
		{ &hf_saphdb_segment_functioncode,
			{ "Function Code", "saphdb.segment.functioncode", FT_INT16, BASE_DEC, VALS(saphdb_segment_functioncode_vals), 0x0, "SAP HDB Segment Function Code", HFILL }},

		/* Segment Buffer items */
		{ &hf_saphdb_segment_buffer,
			{ "Segment Buffer", "saphdb.segment.buffer", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Segment Buffer", HFILL }},

		/* Part items */
		{ &hf_saphdb_part,
			{ "Part", "saphdb.segment.part", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Part", HFILL }},
		{ &hf_saphdb_part_partkind,
			{ "Part Kind", "saphdb.segment.part.partkind", FT_INT8, BASE_DEC, VALS(saphdb_part_partkind_vals), 0x0, "SAP HDB Part Kind", HFILL }},
		{ &hf_saphdb_part_partattributes,
			{ "Part Attributes", "saphdb.segment.part.partattributes", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Part Attributes", HFILL }},
		{ &hf_saphdb_part_argumentcount,
			{ "Argument Count", "saphdb.segment.part.argumentcount", FT_INT16, BASE_DEC, NULL, 0x0, "SAP HDB Part Argument Count", HFILL }},
		{ &hf_saphdb_part_bigargumentcount,
			{ "Big Argument Count", "saphdb.segment.part.bigargumentcount", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Part Big Argument Count", HFILL }},
		{ &hf_saphdb_part_bufferlength,
			{ "Buffer Length", "saphdb.segment.part.bufferlength", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Part Buffer Length", HFILL }},
		{ &hf_saphdb_part_buffersize,
			{ "Buffer Size", "saphdb.segment.part.buffersize", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Part Buffer Size", HFILL }},

		/* Part Buffer items */
		{ &hf_saphdb_part_buffer,
			{ "Part Buffer", "saphdb.segment.part.buffer", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Part Buffer", HFILL }},

		/* Part Buffer AUTHENTICATION items */
		{ &hf_saphdb_part_authentication_field_count,
			{ "Field Count", "saphdb.segment.part.buffer.authentication.fieldcount", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP HDB AUTHENTICATION Field Count", HFILL }},
		{ &hf_saphdb_part_authentication_field_length,
			{ "Field Length", "saphdb.segment.part.buffer.authentication.fieldlength", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP HDB AUTHENTICATION Field Length", HFILL }},
		{ &hf_saphdb_part_authentication_field_value,
			{ "Field Value", "saphdb.segment.part.buffer.authentication.fieldvalue", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB AUTHENTICATION Field Value", HFILL }},
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
