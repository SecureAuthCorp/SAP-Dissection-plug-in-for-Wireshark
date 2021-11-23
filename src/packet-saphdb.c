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

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wsutil/wmem/wmem.h>

#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-tls.h>


/* Define default ports */
#define SAPHDB_PORT_RANGE "30013-39913,30015-39915"


/* SAP HDB Packet Options values */
static const value_string saphdb_message_header_packetoptions_vals[] = {
	{ 0, "Uncompressed" },
	{ 2, "Compressed" },
	/* NULL */
	{ 0x00, NULL }
};

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


/* SAP HDB Type values */
static const value_string saphdb_part_type_vals[] = {
	{ 0, "NULL" },
	{ 1, "TINYINT" },
	{ 2, "SMALLINT" },
	{ 3, "INT" },
	{ 4, "BIGINT" },
	{ 5, "DECIMAL" },
	{ 6, "REAL" },
	{ 7, "DOUBLE" },
	{ 8, "CHAR" },
	{ 9, "VARCHAR1" },
	{ 10, "NCHAR" },
	{ 11, "NVARCHAR" },
	{ 12, "BINARY" },
	{ 13, "VARBINARY" },
	{ 14, "DATE" },
	{ 15, "TIME" },
	{ 16, "TIMESTAMP" },
	{ 17, "TIME_TZ" },
	{ 18, "TIME_LTZ" },
	{ 19, "TIMESTAMP_TZ" },
	{ 20, "TIMESTAMP_LTZ" },
	{ 21, "INTERVAL_YM" },
	{ 22, "INTERVAL_DS" },
	{ 23, "ROWID" },
	{ 24, "UROWID" },
	{ 25, "CLOB" },
	{ 26, "NCLOB" },
	{ 27, "BLOB" },
	{ 28, "BOOLEAN" },
	{ 29, "STRING" },
	{ 30, "NSTRING" },
	{ 31, "LOCATOR" },
	{ 32, "NLOCATOR" },
	{ 33, "BSTRING" },
	{ 34, "DECIMAL_DIGIT_ARRAY" },
	{ 35, "VARCHAR2" },
	{ 36, "VARCHAR3" },
	{ 37, "NVARCHAR3" },
	{ 38, "VARBINARY3" },
	{ 39, "VARGROUP" },
	{ 40, "TINYINT_NOTNULL" },
	{ 41, "SMALLINT_NOTNULL" },
	{ 42, "INT_NOTNULL" },
	{ 43, "BIGINT_NOTNULL" },
	{ 44, "ARGUMENT" },
	{ 45, "TABLE" },
	{ 46, "CURSOR" },
	{ 47, "SMALLDECIMAL" },
	{ 48, "ABAPSTREAM" },
	{ 49, "ABAPSTRUCT" },
	{ 50, "ARRAY" },
	{ 51, "TEXT" },
	{ 52, "SHORTTEXT" },
	{ 53, "FIXEDSTRING" },
	{ 54, "FIXEDPOINTDECIMAL" },
	{ 55, "ALPHANUM" },
	{ 56, "TLOCATOR" },
	{ 61, "LONGDATE" },
	{ 62, "SECONDDATE" },
	{ 63, "DAYDATE" },
	{ 64, "SECONDTIME" },
	{ 65, "CSDATE" },
	{ 66, "CSTIME" },
	{ 71, "BLOB_DISK" },
	{ 72, "CLOB_DISK" },
	{ 73, "NCLOB_DISK" },
	{ 74, "GEOMETRY" },
	{ 75, "POINT" },
	{ 76, "FIXED16" },
	{ 77, "BLOB_HYBRID" },
	{ 78, "CLOB_HYBRID" },
	{ 79, "NCLOB_HYBRID" },
	{ 80, "POINTZ" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP HDB Error Level values */
static const value_string saphdb_error_level_vals[] = {
	{ 0, "WARNING" },
	{ 1, "ERROR" },
	{ 2, "FATALERROR" },
	/* NULL */
	{ 0x00, NULL }
};


/* Structure to define Option Parts */
typedef struct _option_part_definition {
    gint8       value;
    const gchar *identifier_strptr;
    gint8	    type;
} option_part_definition;


static const option_part_definition saphdb_part_connect_options_vals[] = {
	{ 1, "Connection ID", 3 },
	{ 2, "Complete Array Execution", 28 },
	{ 3, "Client Locale", 29 },
	{ 4, "Supports Large Bulk Operations", 28 },
	{ 5, "Distribution Enabled", 28 },
	{ 6, "Primary Connection ID", 0 },
	{ 7, "Primary Connection Host", 0 },
	{ 8, "Primary Connection Port", 0 },
	{ 9, "Complete Data Type Support", 0 },
	{ 10, "Large Number of Parameters Support", 28 },
	{ 11, "System ID", 29 },
	{ 12, "Data Format Version", 3 },
	{ 13, "ABAP VARCHAR Mode", 28 },
	{ 14, "Select for Update Supported", 28 },
	{ 15, "Client Distribution Mode", 3 },
	{ 16, "Engine Data Format Version", 3 },
	{ 17, "Distribution Protocol Version", 3 },
	{ 18, "Split Batch Commands", 28 },
	{ 19, "Use Transaction Flags Only", 28 },
	{ 20, "Row and Column Optimized Format", 28 },
	{ 21, "Ignore Unknown Parts", 3 },
	{ 22, "Table Output Parameter", 28 },
	{ 23, "Data Format Version 2", 3 },
	{ 24, "ITAB Parameter", 28 },
	{ 25, "Describe Table Output Parameter", 28 },
	{ 26, "Columnar Result Set", 0 },   /* This is BITVECTOR type ??? */
	{ 27, "Scrollable Result Set", 3 },
	{ 28, "Client Info NULL Value Supported", 28 },
	{ 29, "Associated Connection ID", 3 },
	{ 30, "Non-Transactional Prepare", 28 },
	{ 31, "Fast Data Access Enabled", 28 },
	{ 32, "OS User", 29 },
	{ 33, "Row Slot Image Result", 0 },   /* This is BITVECTOR type ??? */
	{ 34, "Endianness", 3 },
	{ 35, "Update Topology Anwhere", 28 },
	{ 36, "Enable Array Type", 28 },
	{ 37, "Implicit LOB Streaming", 28 },
	{ 38, "Cached View Property", 28 },
	{ 39, "X OpenXA Protocol Supported", 28 },
	{ 40, "Master Commit Redirection Supported", 28 },
	{ 41, "Active/Active Protocol Version", 3 },
	{ 42, "Active/Active Connection Origin Site", 3 },
	{ 43, "Query Timeout Supported", 28 },
	{ 44, "Full Version String", 29 },
	{ 45, "Database Name", 29 },
	{ 46, "Build Platform", 3 },
	{ 47, "Implicit XA Session Supported", 28 },
	{ 48, "Client Side Column Encryption Version", 3 },
	{ 49, "Compression Level And Flags", 3 },
	{ 50, "Client Side Re-Execution Supported", 28 },
	{ 51, "Client Reconnect Wait Timeout", 3 },
	{ 52, "Original Anchor Connection ID", 3 },
	{ 53, "Flag Set 1", 3 },
	{ 54, "Topology Network Group", 28 },
	{ 55, "IP Address", 29 },
	{ 56, "LRR Ping Time", 3 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_commit_options_vals[] = {
	{ 1, "Hold Cursors Over Commit", 28 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_fetch_options_vals[] = {
	{ 1, "Result Set Pos", 3 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_transaction_flags_vals[] = {
	{ 0, "Rolled Back", 28 },
	{ 1, "Commited", 28 },
	{ 2, "New Isolation Level", 3 },
	{ 3, "DDL Commit Mode Changed", 28 },
	{ 4, "Write Transaction Started", 28 },
	{ 5, "No Write Transaction Started", 28 },
	{ 6, "Session Closing Transaction Error", 28 },
	/* NULL */
	{ 0x00, NULL, 0x00}
};

static const option_part_definition saphdb_part_topology_info_vals[] = {
	{ 1, "Host Name", 29 },
	{ 2, "Host Port Number", 3 },
	{ 3, "Tenant Name", 29 },
	{ 4, "Load Factor", 7 },
	{ 5, "Site Volume ID", 3 },
	{ 6, "Is Master", 28 },
	{ 7, "Is Current Session", 28 },
	{ 8, "Service Type", 3 },
	{ 9, "Network Domain", 29 },
	{ 10, "Is Stand-By", 28 },
	{ 11, "All IP Addresses", 29 },
	{ 12, "All Host Names", 29 },
	{ 13, "Site Type", 3 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_command_info_vals[] = {
	{ 1, "Line Number", 3 },
	{ 2, "Source Module", 29 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_client_context_vals[] = {
	{ 1, "Client Version", 29 },
	{ 2, "Client Type", 29 },
	{ 3, "Application Name", 29 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_session_context_vals[] = {
	{ 1, "Primary Connection ID", 3 },
	{ 2, "Primary Host Name", 29 },
	{ 3, "Primary Host Port Number", 3 },
	{ 4, "Master Connection ID", 3 },
	{ 5, "Master Host Name", 29 },
	{ 6, "Master Host Port Number", 3 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_statement_context_vals[] = {
	{ 1, "Statement Sequence Info", 33 },
	{ 2, "Server Processing Time", 4 },
	{ 3, "Schema Name", 29 },
	{ 4, "Flag Set", 8 },
	{ 5, "Query Time Out", 4 },
	{ 6, "Client Reconnection Wait Timeout", 3 },
	{ 7, "Server CPU Time", 4 },
	{ 8, "Server Memory Usage", 4 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_dbconnect_info_flags_vals[] = {
	{ 1, "Database Name", 29 },
	{ 2, "Host", 29 },
	{ 3, "Port", 3 },
	{ 4, "Is Connected", 28 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
};

static const option_part_definition saphdb_part_lob_flags_vals[] = {
	{ 0, "Implicit Streaming", 28 },
	/* NULL */
	{ 0x00, NULL, 0x00 }
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
static int hf_saphdb_compressed_buffer = -1;

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

/* SAP HDB Part Buffer Option Part Data items */
static int hf_saphdb_part_option_row = -1;
static int hf_saphdb_part_option_argcount = -1;
static int hf_saphdb_part_option_name = -1;
static int hf_saphdb_part_option_type = -1;
static int hf_saphdb_part_option_length = -1;
static int hf_saphdb_part_option_value = -1;
static int hf_saphdb_part_option_value_bool = -1;
static int hf_saphdb_part_option_value_byte = -1;
static int hf_saphdb_part_option_value_short = -1;
static int hf_saphdb_part_option_value_int = -1;
static int hf_saphdb_part_option_value_bigint = -1;
static int hf_saphdb_part_option_value_string = -1;
static int hf_saphdb_part_option_value_double = -1;

/* SAP HDB Part Buffer COMMAND items */
static int hf_saphdb_part_command = -1;

/* SAP HDB Part Buffer ERROR items */
static int hf_saphdb_part_error_code = -1;
static int hf_saphdb_part_error_position = -1;
static int hf_saphdb_part_error_text_length = -1;
static int hf_saphdb_part_error_level = -1;
static int hf_saphdb_part_error_sqlstate = -1;
static int hf_saphdb_part_error_text = -1;

/* SAP HDB Part Buffer AUTHENTICATE items */
static int hf_saphdb_part_authentication_field_count = -1;
static int hf_saphdb_part_authentication_field_length = -1;
static int hf_saphdb_part_authentication_field_value = -1;

/* SAP HDB Part Buffer CLIENTID items */
static int hf_saphdb_part_clientid = -1;


static gint ett_saphdb = -1;


/* Global port preference */
static range_t *global_saphdb_port_range;


/* Expert info */
static expert_field ei_saphdb_compressed_unknown = EI_INIT;
static expert_field ei_saphdb_option_part_unknown = EI_INIT;
static expert_field ei_saphdb_part_buffer_length_invalid = EI_INIT;
static expert_field ei_saphdb_segments_incorrect_order = EI_INIT;
static expert_field ei_saphdb_segments_number_incorrect = EI_INIT;
static expert_field ei_saphdb_segment_length = EI_INIT;
static expert_field ei_saphdb_buffer_length = EI_INIT;
static expert_field ei_saphdb_parts_number_incorrect = EI_INIT;
static expert_field ei_saphdb_varpartlenght_incorrect = EI_INIT;


/* Global highlight preference */
static gboolean global_saphdb_highlight_items = TRUE;


/* Protocol handle */
static dissector_handle_t saphdb_handle;

static dissector_handle_t gssapi_handle;


void proto_reg_handoff_saphdb(void);


/* Option Part Value to Option Part Identifier */
const gchar *
opv_to_opi(const gint8 value, const option_part_definition *opd, const char *unknown_str)
{
	gint i = 0;
	if (opd) {
        while (opd[i].identifier_strptr) {
            if (opd[i].value == value) {
                return(opd[i].identifier_strptr);
            }
            i++;
        }
	}
	return unknown_str;
}

/* Option Part Value to Option Part Type */
gint8
opv_to_opt(const gint8 value, const option_part_definition *opd)
{
	gint i = 0;
	if (opd) {
        while (opd[i].identifier_strptr) {
            if (opd[i].value == value) {
                return(opd[i].type);
            }
            i++;
        }
	}
	return 0;
}

static int
dissect_saphdb_part_options_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gint16 argcount, guint8 partkind, const option_part_definition *definition)
{
	guint32 parsed_length = 0;

	while (argcount > 0 && tvb_reported_length_remaining(tvb, offset + parsed_length) > 2) {
		gint8 option_key = 0, option_type = 0;
		gint16 option_length = 0;
		gint8 option_value_byte = 0;
		proto_item *option_type_item = NULL;

		option_key = tvb_get_gint8(tvb, offset + parsed_length);
		proto_tree_add_int_format(tree, hf_saphdb_part_option_name, tvb, offset + parsed_length, 1, option_key,
				"Option Name: %s (%d)", opv_to_opi(option_key, definition, "Unknown"), option_key); parsed_length += 1;

		option_type = tvb_get_gint8(tvb, offset + parsed_length);
		option_type_item = proto_tree_add_item(tree, hf_saphdb_part_option_type, tvb, offset + parsed_length, 1, ENC_NA); parsed_length += 1;
		if (option_type != opv_to_opt(option_key, definition)) {
			if (global_saphdb_highlight_items){
				expert_add_info_format(pinfo, option_type_item, &ei_saphdb_option_part_unknown, "Option Type for key %d in part kind %d doesn't match! (expected %d, obtained %d)", option_key, partkind, opv_to_opt(option_key, definition), option_type);
			}
		}

		switch (option_type) {
			case 1:		// TINYINT
				proto_tree_add_item(tree, hf_saphdb_part_option_value_byte, tvb, offset + parsed_length, 1, ENC_NA); parsed_length += 1;
				break;
			case 2:		// SMALLINT
				proto_tree_add_item(tree, hf_saphdb_part_option_value_short, tvb, offset + parsed_length, 2, ENC_LITTLE_ENDIAN); parsed_length += 2;
				break;
			case 3:     // INT
				proto_tree_add_item(tree, hf_saphdb_part_option_value_int, tvb, offset + parsed_length, 4, ENC_LITTLE_ENDIAN); parsed_length += 4;
				break;
			case 4:     // BIGINT
				proto_tree_add_item(tree, hf_saphdb_part_option_value_bigint, tvb, offset + parsed_length, 8, ENC_LITTLE_ENDIAN); parsed_length += 8;
				break;
			case 7:     // DOUBLE
				proto_tree_add_item(tree, hf_saphdb_part_option_value_double, tvb, offset + parsed_length, 8, ENC_LITTLE_ENDIAN); parsed_length += 8;
				break;
			case 28:	// BOOLEAN
				option_value_byte = tvb_get_gint8(tvb, offset + parsed_length);
				proto_tree_add_boolean(tree, hf_saphdb_part_option_value_bool, tvb, offset + parsed_length, 1, option_value_byte); parsed_length += 1;
				break;
			case 29:     // STRING
			case 30:     // NSTRING
			case 33:     // BSTRING
				option_length = tvb_get_gint16(tvb, offset + parsed_length, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(tree, hf_saphdb_part_option_length, tvb, offset + parsed_length, 2, ENC_LITTLE_ENDIAN); parsed_length += 2;

				if (tvb_reported_length_remaining(tvb, offset + parsed_length) >= option_length) {
					if (option_type == 29) {
						/* TODO: This need to be CESU-8 decoded */
						proto_tree_add_item(tree, hf_saphdb_part_option_value_string, tvb, offset + parsed_length, option_length, ENC_UTF_8); parsed_length += option_length;
					} else if (option_type == 30) {
						proto_tree_add_item(tree, hf_saphdb_part_option_value_string, tvb, offset + parsed_length, option_length, ENC_UTF_8); parsed_length += option_length;
					} else if (option_type == 33) {
						/* This is binary data, not rendering it as a string */
						proto_tree_add_item(tree, hf_saphdb_part_option_value, tvb, offset + parsed_length, option_length, ENC_NA); parsed_length += option_length;
					}
				}
				break;
			default:     // Unknown type, we don't know the length nor how to parse it
				if (global_saphdb_highlight_items){
					expert_add_info_format(pinfo, option_type_item, &ei_saphdb_option_part_unknown, "Option Type %d length unknown", option_type);
				}
				break;
		}
		argcount--;
	}

	return parsed_length;
}

static int
dissect_saphdb_part_multi_line_options_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gint16 rowcount, guint8 partkind, const option_part_definition *definition)
{
	guint32 parsed_length = 0;

	/* In Multi-line Option Part, the part's argcount is the number of rows. For each row we need to parse the options. */
	while (rowcount > 0 && tvb_reported_length_remaining(tvb, offset + parsed_length) > 2) {
		gint16 argcount = 0;

		/* First we read the amount of arguments in this row */
		argcount = tvb_get_gint16(tvb, offset + parsed_length, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tree, hf_saphdb_part_option_argcount, tvb, offset + parsed_length, 2, ENC_LITTLE_ENDIAN); parsed_length += 2;

		/* Now parse the options in the row if there are*/
		if (argcount > 0) {
			parsed_length += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset + parsed_length, argcount, partkind, definition);
		}

		rowcount--;
	}

	return parsed_length;

}

void
dissect_saphdb_gss_authentication_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
	guint8 field_short_length = 0, commtype = 0;
	guint16 field_count = 0, field_length = 0;

	/* Parse the field count */
	field_count = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_saphdb_part_authentication_field_count, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;

	for (guint16 field = 0; field < field_count; field++) {

		/* Parse the field length. If the first byte is 0xFF, the length is contained in the next 2 bytes */
		field_short_length = tvb_get_guint8(tvb, offset);
		if (field_short_length == 0xff) {
			offset += 1;
			field_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_saphdb_part_authentication_field_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2;
		} else {
			proto_tree_add_item(tree, hf_saphdb_part_authentication_field_length, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1;
			field_length = field_short_length;
		}

		/* We try then to see if we're dealing with the commtype field (second field and with length 1)
		 * and extract it
		 */
		if ((field == 1) && (field_length == 1))
		{
			commtype = tvb_get_guint8(tvb, offset);
		}

		/* If this is the last value of a three field packet, and is one of the commtypes that carries an
		 * SPNEGO structure, we call the GSSAPI dissector. The Kerberos data is extracted in a new TVB.
		 */
		if (((commtype == 3) || (commtype == 6)) && (field_count == 3) && (field == 2)) {
			tvbuff_t *kerberos_tvb;
			kerberos_tvb = tvb_new_subset_length(tvb, offset, field_length);
			add_new_data_source(pinfo, kerberos_tvb, "Kerberos Data");
			call_dissector(gssapi_handle, kerberos_tvb, pinfo, tree);
		}
		else
		/* If not we add the field value in plain */
		{
			proto_tree_add_item(tree, hf_saphdb_part_authentication_field_value, tvb, offset, field_length, ENC_NA);
		}

		offset += field_length;
	}

}


static int
dissect_saphdb_part_authentication_fields(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset)
{
	guint8 field_short_length = 0;
	guint16 field_count = 0, field_length = 0;
	guint32 parsed_length = 0;

	proto_item *gss_item = NULL;
	proto_tree *gss_tree = NULL;

	gboolean is_gss = FALSE;

	/* Parse the field count */ /* TODO: Should this match with argcount? */
	field_count = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_saphdb_part_authentication_field_count, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; parsed_length += 2;

	for (guint16 field = 0; field < field_count; field++) {

		/* Parse the field length. If the first byte is 0xFF, the length is contained in the next 2 bytes */
		field_short_length = tvb_get_guint8(tvb, offset);
		if (field_short_length == 0xff) {
			offset += 1; parsed_length += 1;
			field_length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_saphdb_part_authentication_field_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2; parsed_length += 2;
		} else {
			proto_tree_add_item(tree, hf_saphdb_part_authentication_field_length, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; parsed_length += 1;
			field_length = field_short_length;
		}

		/* Add the field value */
		gss_item = proto_tree_add_item(tree, hf_saphdb_part_authentication_field_value, tvb, offset, field_length, ENC_NA);

		/* Check if this is a GSS field so we can parse the remaining fields */
		if ((((field_count == 2) && (field == 0)) || ((field_count == 3) && (field == 1))) &&
			(field_length == 3) && (tvb_strneql(tvb, offset, "GSS", 3) != -1)) {
			is_gss = TRUE;
		}

		/* If the method is GSS, and this is the last value, we add a new tree and parse the value */
		if (is_gss && field == field_count - 1) {
			proto_item_append_text(gss_item, ": GSS Token");
			gss_tree = proto_item_add_subtree(gss_item, ett_saphdb);
			dissect_saphdb_gss_authentication_fields(tvb, pinfo, gss_tree, offset);
		}

		offset += field_length; parsed_length += field_length;

	}

	return parsed_length;
}


static int
dissect_saphdb_part_buffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 length, gint16 argcount, guint8 partkind, proto_item *partkind_item)
{
	gint32 error_text_length = 0;

	switch (partkind) {
		case 3:   // COMMAND
			if ((length > 0) && ((guint32)tvb_reported_length_remaining(tvb, offset) >= length)) {
				proto_tree_add_item(tree, hf_saphdb_part_command, tvb, offset, length, ENC_NA); offset += length; length = 0;
			}
			break;
		case 6:   // ERROR
			proto_tree_add_item(tree, hf_saphdb_part_error_code, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length -= 4;
			proto_tree_add_item(tree, hf_saphdb_part_error_position, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length -= 4;
			proto_tree_add_item_ret_int(tree, hf_saphdb_part_error_text_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &error_text_length); offset += 4; length -= 4;
			proto_tree_add_item(tree, hf_saphdb_part_error_level, tvb, offset, 1, ENC_NA); offset += 1; length -= 1;
			proto_tree_add_item(tree, hf_saphdb_part_error_sqlstate, tvb, offset, 5, ENC_NA); offset += 5; length -= 5;

			if ((error_text_length > 0) && (tvb_reported_length_remaining(tvb, offset) >= error_text_length)) {
				proto_tree_add_item(tree, hf_saphdb_part_error_text, tvb, offset, error_text_length, ENC_NA); offset += error_text_length; length -= error_text_length;

				/* Align the error text length to 8 */
				if ((error_text_length % 8) != 0) {
					length += 8 - (error_text_length % 8);
				}
			}
			break;

		case 33:  // AUTHENTICATION
			offset += dissect_saphdb_part_authentication_fields(tvb, pinfo, tree, offset);
			break;

		case 35:   // CLIENTID
			if ((length > 0) && ((guint32)tvb_reported_length_remaining(tvb, offset) >= length)) {
				proto_tree_add_item(tree, hf_saphdb_part_clientid, tvb, offset, length, ENC_NA); offset += length; length = 0;
			}
			break;

		// Multi-line Option Parts
		case 15:  // TOPOLOGYINFORMATION
			offset += dissect_saphdb_part_multi_line_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_topology_info_vals);
			break;

		// Option Parts
		case 27:  // COMMANDINFO
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_command_info_vals);
			break;
		case 29:  // CLIENTCONTEXT
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_client_context_vals);
			break;
		case 34:  // SESSIONCONTEXT
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_session_context_vals);
			break;
		case 39:  // STATEMENTCONTEXT
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_statement_context_vals);
			break;
		case 42:  // CONNECTOPTIONS
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_connect_options_vals);
			break;
		case 43:  // COMMITOPTIONS
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_commit_options_vals);
			break;
		case 44:  // FETCHOPTIONS
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_fetch_options_vals);
			break;
		case 64:  // TRANSACTIONFLAGS
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_transaction_flags_vals);
			break;
		case 67:  // DBCONNECTINFO
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_dbconnect_info_flags_vals);
			break;
		case 68:  // LOBFLAGS
			offset += dissect_saphdb_part_options_data(tvb, pinfo, tree, offset, argcount, partkind, saphdb_part_lob_flags_vals);
			break;

		default:
			if (global_saphdb_highlight_items){
				expert_add_info_format(pinfo, partkind_item, &ei_saphdb_option_part_unknown, "Part Kind %d unknown", partkind);
			}
			offset += length;
			break;
	}

	return length;
}


static int
dissect_saphdb_part(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint32 offset, gint16 number_of_parts, guint16 part_number)
{
	gint8 partkind = 0;
	gint16 argcount = 0;
	gint32 bufferlength = 0;
	guint32 length = 0;
	proto_item *part_item = NULL, *partkind_item = NULL, *part_buffer_length_item = NULL, *part_buffer_item = NULL;
	proto_tree *part_tree = NULL, *part_buffer_tree = NULL;

	/* Add the Part subtree */
	part_item = proto_tree_add_item(tree, hf_saphdb_part, tvb, offset, 16, ENC_NA);
	part_tree = proto_item_add_subtree(part_item, ett_saphdb);
	proto_item_append_text(part_item, " (%d/%d)", part_number, number_of_parts);

	/* Add the Part fields */
	partkind = tvb_get_gint8(tvb, offset);
	proto_item_append_text(part_item, ", %s", val_to_str(partkind, saphdb_part_partkind_vals, "Unknown"));
	partkind_item = proto_tree_add_item(part_tree, hf_saphdb_part_partkind, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;
	proto_tree_add_item(part_tree, hf_saphdb_part_partattributes, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;
	argcount = tvb_get_gint16(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(part_tree, hf_saphdb_part_argumentcount, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length += 2;
	proto_tree_add_item(part_tree, hf_saphdb_part_bigargumentcount, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;
	part_buffer_length_item = proto_tree_add_item_ret_int(part_tree, hf_saphdb_part_bufferlength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &bufferlength); offset += 4; length += 4;
	proto_tree_add_item(part_tree, hf_saphdb_part_buffersize, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;

	/* Check the length */
	if (bufferlength < 0) {
		expert_add_info_format(pinfo, part_buffer_length_item, &ei_saphdb_buffer_length, "Part Buffer length %d is invalid", bufferlength);
	}

	/* Align the buffer length to 8 */
	if (bufferlength % 8 != 0) {
		bufferlength += 8 - bufferlength % 8;
	}

	/* Adjust the length */
	if (bufferlength < 0 || tvb_reported_length_remaining(tvb, offset) < bufferlength) {
		bufferlength = tvb_reported_length_remaining(tvb, offset);
	}

    /* Add the part buffer tree and dissect it */
	if (argcount > 0) {
		part_buffer_item = proto_tree_add_item(part_tree, hf_saphdb_part_buffer, tvb, offset, bufferlength, ENC_NA);
		part_buffer_tree = proto_item_add_subtree(part_buffer_item, ett_saphdb);

		dissect_saphdb_part_buffer(tvb, pinfo, part_buffer_tree, offset, bufferlength, argcount, partkind, partkind_item);
		offset += bufferlength; length += bufferlength;
	}

	/* Adjust the item tree length */
	proto_item_set_len(part_tree, length);

	return length;
}


static int
dissect_saphdb_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_, guint32 offset, gint16 number_of_segments, guint16 nosegment, gboolean compressed)
{
	gint8 segmentkind = 0, message_type = 0;
	gint16 number_of_parts = 0, segment_number = 0, function_code = 0;
	guint32 length = 0, part_length = 0;
	gint32 segmentlength = 0;
	proto_item *segment_item = NULL, *segmentlength_item = NULL, *number_of_parts_item = NULL, *segment_number_item = NULL, *segment_buffer_item = NULL;
	proto_tree *segment_tree = NULL, *segment_buffer_tree = NULL;

	/* Add the Segment subtree */
	segment_item = proto_tree_add_item(tree, hf_saphdb_segment, tvb, offset, 13, ENC_NA);
	segment_tree = proto_item_add_subtree(segment_item, ett_saphdb);
	proto_item_append_text(segment_item, " (%d/%d)", nosegment, number_of_segments);

	/* Add the Segment fields */
	segmentlength = tvb_get_gint32(tvb, offset, ENC_LITTLE_ENDIAN);
	segmentlength_item = proto_tree_add_item(segment_tree, hf_saphdb_segment_segmentlength, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;
	proto_tree_add_item(segment_tree, hf_saphdb_segment_segmentofs, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4; length += 4;
	number_of_parts = tvb_get_gint16(tvb, offset, ENC_LITTLE_ENDIAN);
	number_of_parts_item = proto_tree_add_item(segment_tree, hf_saphdb_segment_noofparts, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length += 2;
	segment_number = tvb_get_gint16(tvb, offset, ENC_LITTLE_ENDIAN);
	segment_number_item = proto_tree_add_item(segment_tree, hf_saphdb_segment_segmentno, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length += 2;
	segmentkind = tvb_get_gint8(tvb, offset);
	proto_tree_add_item(segment_tree, hf_saphdb_segment_segmentkind, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, "Segment %s (", val_to_str(segmentkind, saphdb_segment_segmentkind_vals, "Unknown"));
	proto_item_append_text(segment_item, ", %s", val_to_str(segmentkind, saphdb_segment_segmentkind_vals, "Unknown"));

	/* Check a couple of fields */
	if (segmentlength < 13) {
		expert_add_info_format(pinfo, segmentlength_item, &ei_saphdb_segment_length, "Segment length %d is invalid", segmentlength);
	}
	if (number_of_parts < 0) {
		expert_add_info_format(pinfo, number_of_parts_item, &ei_saphdb_parts_number_incorrect, "Number of parts %d is invalid", number_of_parts);
	}
	if (segment_number < 0 || nosegment != segment_number) {
		expert_add_info_format(pinfo, segment_number_item, &ei_saphdb_segments_incorrect_order, "Segment number %d is invalid (expected %d)", segment_number, nosegment);
	}

	/* Add additional fields according to the segment kind*/
	switch (segmentkind) {
		case 1: /* Request */
			message_type = tvb_get_gint8(tvb, offset);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s)", val_to_str(message_type, saphdb_segment_messagetype_vals, "Unknown"));
			proto_item_append_text(segment_item, ", %s", val_to_str(message_type, saphdb_segment_messagetype_vals, "Unknown"));
			proto_tree_add_item(segment_tree, hf_saphdb_segment_messagetype, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;

			proto_tree_add_item(segment_tree, hf_saphdb_segment_commit, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;
			proto_tree_add_item(segment_tree, hf_saphdb_segment_commandoptions, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1; length += 1;

			offset += 8; length += 8; // Reserved1 field
			break;
		case 2: /* Reply */
			offset += 1; length += 1; // Reserved2 field

			function_code = tvb_get_gint16(tvb, offset, ENC_LITTLE_ENDIAN);
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s)", val_to_str(function_code, saphdb_segment_functioncode_vals, "Unknown"));
			proto_item_append_text(segment_item, ", %s", val_to_str(function_code, saphdb_segment_functioncode_vals, "Unknown"));
			proto_tree_add_item(segment_tree, hf_saphdb_segment_functioncode, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2; length += 2;

			offset += 8; length += 8; // Reserved3 field
			break;
		default: /* Error and other types */
			offset += 11; length += 11; // Reserved or unused fields
			col_append_fstr(pinfo->cinfo, COL_INFO, ")");

			break;
	}

	/* If the packet is compressed, compression will apply from here on. As we don't support compression yet, we stop dissecting here. */
	if (compressed) {
		return length;
	}

	/* Add the Segment Buffer subtree */
	if (((guint32)segmentlength > length) && (number_of_parts > 0)) {
		segment_buffer_item = proto_tree_add_item(segment_tree, hf_saphdb_segment_buffer, tvb, offset, segmentlength - length, ENC_NA);
		segment_buffer_tree = proto_item_add_subtree(segment_buffer_item, ett_saphdb);

		/* Iterate over the parts and dissect them */
		for (guint16 part_number = 1; part_number <= number_of_parts && tvb_reported_length_remaining(tvb, offset) >= 16; part_number++) {
			part_length = dissect_saphdb_part(tvb, pinfo, segment_buffer_tree, NULL, offset, number_of_parts, part_number);
			offset += part_length; length += part_length;
		}

	}

	/* Adjust the item tree length */
	proto_item_set_len(segment_tree, length);

	return length;
}


static int
dissect_saphdb_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint32 offset = 0;

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPHDB");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	/* we are being asked for details */
	if (tree && (tvb_reported_length(tvb) == 8 || tvb_reported_length(tvb) == 14 || tvb_reported_length(tvb) >= 32)) {

		proto_item *ti = NULL;
		proto_tree *saphdb_tree = NULL;

		/* Add the main saphdb subtree */
		ti = proto_tree_add_item(tree, proto_saphdb, tvb, offset, -1, ENC_NA);
		saphdb_tree = proto_item_add_subtree(ti, ett_saphdb);


		/* Initialization Request message */
		if (tvb_reported_length(tvb) == 14) {
			proto_tree_add_item(saphdb_tree, hf_saphdb_initialization_request, tvb, offset, 14, ENC_NA); offset += 14;
			col_add_str(pinfo->cinfo, COL_INFO, "Initialization Request");

		/* Initialization Reply message */
		} else if (tvb_reported_length(tvb) == 8) {
			proto_item *initialization_reply = NULL;
			proto_tree *initialization_reply_tree = NULL;

			/* Add the Initialization Reply subtree */
			initialization_reply = proto_tree_add_item(saphdb_tree, hf_saphdb_initialization_reply, tvb, offset, 8, ENC_NA);
			initialization_reply_tree = proto_item_add_subtree(initialization_reply, ett_saphdb);

			proto_tree_add_item(initialization_reply_tree, hf_saphdb_initialization_reply_product_version_major, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1;
			proto_tree_add_item(initialization_reply_tree, hf_saphdb_initialization_reply_product_version_minor, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
			proto_tree_add_item(initialization_reply_tree, hf_saphdb_initialization_reply_protocol_version_major, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1;
			proto_tree_add_item(initialization_reply_tree, hf_saphdb_initialization_reply_protocol_version_minor, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;

			col_add_str(pinfo->cinfo, COL_INFO, "Initialization Reply");

		/* All other message types */
		} else if (tvb_reported_length(tvb) >= 32) {

			gboolean compressed = FALSE;
			gint16 number_of_segments = 0;
			guint32 varpartlength = 0;
			proto_item *message_header_item = NULL, *varpartlength_item = NULL, *number_of_segments_item = NULL, *message_buffer_item = NULL, *compressed_buffer_item = NULL;
			proto_tree *message_header_tree = NULL, *message_buffer_tree = NULL;

			/* Add the Message Header subtree */
			message_header_item = proto_tree_add_item(saphdb_tree, hf_saphdb_message_header, tvb, offset, 32, ENC_NA);
			message_header_tree = proto_item_add_subtree(message_header_item, ett_saphdb);

			/* Add the Message Header fields */
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_sessionid, tvb, offset, 8, ENC_LITTLE_ENDIAN); offset += 8;
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_packetcount, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
			varpartlength_item = proto_tree_add_item_ret_uint(message_header_tree, hf_saphdb_message_header_varpartlength, tvb, offset, 4, ENC_LITTLE_ENDIAN, &varpartlength); offset += 4;
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_varpartsize, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
			number_of_segments = tvb_get_gint16(tvb, offset, ENC_LITTLE_ENDIAN);
			number_of_segments_item = proto_tree_add_item(message_header_tree, hf_saphdb_message_header_noofsegm, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;
			compressed = tvb_get_gint8(tvb, offset) == 2;
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_packetoptions, tvb, offset, 1, ENC_LITTLE_ENDIAN); offset += 1;
			offset += 1;  /* Reserved1 field */
			proto_tree_add_item(message_header_tree, hf_saphdb_message_header_compressionvarpartlength, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
			offset += 4;  /* Reserved2 field */

			/* Check the length of the variable part against the remaining packet */
			if ((guint32)tvb_reported_length_remaining(tvb, offset) != varpartlength) {
				expert_add_info_format(pinfo, varpartlength_item, &ei_saphdb_varpartlenght_incorrect, "Length of variable part %d is invalid", varpartlength);
				varpartlength = tvb_reported_length_remaining(tvb, offset);
			}

			/* Add the Message Buffer subtree */
			if (varpartlength > 0 && number_of_segments > 0) {
				message_buffer_item = proto_tree_add_item(saphdb_tree, hf_saphdb_message_buffer, tvb, offset, varpartlength, ENC_NA);
				message_buffer_tree = proto_item_add_subtree(message_buffer_item, ett_saphdb);

				/* If the packet is compressed, the message header and the first segment header is sent uncompressed. We dissect the
				 * first segment only and add a new item with the compressed buffer. Adding an expert warning as well. */
				if (compressed) {
					offset += dissect_saphdb_segment(tvb, pinfo, message_buffer_tree, NULL, offset, number_of_segments, 1, compressed);
					compressed_buffer_item = proto_tree_add_item(message_buffer_tree, hf_saphdb_compressed_buffer, tvb, offset, varpartlength, ENC_NA);
					if (global_saphdb_highlight_items){
						expert_add_info_format(pinfo, compressed_buffer_item, &ei_saphdb_compressed_unknown, "Packet is compressed and decompression is not supported");
					}

				} else {
					/* Iterate over the segments and dissect them */
					for (guint16 segment_number = 1; segment_number <= number_of_segments && tvb_reported_length_remaining(tvb, offset) >= 13; segment_number++) {
						offset += dissect_saphdb_segment(tvb, pinfo, message_buffer_tree, NULL, offset, number_of_segments, segment_number, compressed);
					}
				}

			} else {
				expert_add_info_format(pinfo, number_of_segments_item, &ei_saphdb_segments_number_incorrect, "Number of segments %d is invalid", number_of_segments);
			}

		}

	}

	return offset;
}

static guint
get_saphdb_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	/* Entire HDB packets are of 32-bytes header plus the value in varpartlength field */
	guint32 varpartlength = tvb_get_guint32(tvb, offset + 12, ENC_LITTLE_ENDIAN);
	return varpartlength + 32;
}

static int
dissect_saphdb_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dissect_saphdb_message(tvb, pinfo, tree, FALSE);
}

static int
dissect_saphdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if (tvb_reported_length(tvb) == 14 || tvb_reported_length(tvb) == 8) {
		return dissect_saphdb_tcp(tvb, pinfo, tree, data);
	}
	else
	{
		tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 32, get_saphdb_pdu_len, dissect_saphdb_tcp, data);
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
			{ "Packet Options", "saphdb.packetoptions", FT_INT8, BASE_DEC, VALS(saphdb_message_header_packetoptions_vals), 0x0, "SAP HDB Message Header Packet Options", HFILL }},
		{ &hf_saphdb_message_header_compressionvarpartlength,
			{ "Compression Var Part Length", "saphdb.compressionvarpartlength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP HDB Message Header Compression Var Part Length", HFILL }},

		/* Message Buffer items */
		{ &hf_saphdb_message_buffer,
			{ "Message Buffer", "saphdb.buffer", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Message Buffer", HFILL }},
		{ &hf_saphdb_compressed_buffer,
			{ "Compressed Buffer", "saphdb.buffer", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Compressed Buffer", HFILL }},

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

		/* Part Buffer Option Part Data items */
		{ &hf_saphdb_part_option_row,
			{ "Option Row", "saphdb.segment.part.option", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Option Part Row", HFILL }},
		{ &hf_saphdb_part_option_argcount,
			{ "Argument Row Count", "saphdb.segment.part.argcount", FT_INT16, BASE_DEC, NULL, 0x0, "SAP HDB Option Part Argument Row Count", HFILL }},
		{ &hf_saphdb_part_option_name,
			{ "Option Name", "saphdb.segment.part.option.name", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Option Part Name", HFILL }},
		{ &hf_saphdb_part_option_type,
			{ "Option Type", "saphdb.segment.part.option.type", FT_INT8, BASE_DEC, VALS(saphdb_part_type_vals), 0x0, "SAP HDB Option Part Type", HFILL }},
		{ &hf_saphdb_part_option_length,
			{ "Option Length", "saphdb.segment.part.option.length", FT_INT16, BASE_DEC, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},
		{ &hf_saphdb_part_option_value,
			{ "Option Value", "saphdb.segment.part.option.value", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},
		{ &hf_saphdb_part_option_value_bool,
			{ "Option Value", "saphdb.segment.part.option.value", FT_BOOLEAN, BASE_DEC, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},
		{ &hf_saphdb_part_option_value_byte,
			{ "Option Value", "saphdb.segment.part.option.value", FT_INT8, BASE_DEC, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},
		{ &hf_saphdb_part_option_value_short,
			{ "Option Value", "saphdb.segment.part.option.value", FT_INT16, BASE_DEC, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},
		{ &hf_saphdb_part_option_value_int,
			{ "Option Value", "saphdb.segment.part.option.value", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},
		{ &hf_saphdb_part_option_value_bigint,
			{ "Option Value", "saphdb.segment.part.option.value", FT_INT64, BASE_DEC, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},
		{ &hf_saphdb_part_option_value_string,
			{ "Option Value", "saphdb.segment.part.option.value", FT_STRING, BASE_NONE, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},
		{ &hf_saphdb_part_option_value_double,
			{ "Option Value", "saphdb.segment.part.option.value", FT_DOUBLE, BASE_NONE, NULL, 0x0, "SAP HDB Option Part Value", HFILL }},

		/* SAP HDB Part Buffer COMMAND items */
		{ &hf_saphdb_part_command,
			{ "Command", "saphdb.segment.part.command", FT_STRING, BASE_NONE, NULL, 0x0, "SAP HDB Command", HFILL }},

		/* SAP HDB Part Buffer ERROR items */
		{ &hf_saphdb_part_error_code,
			{ "Error Code", "saphdb.segment.part.error.code", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Error Code", HFILL }},
		{ &hf_saphdb_part_error_position,
			{ "Error Position", "saphdb.segment.part.error.position", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Error Position", HFILL }},
		{ &hf_saphdb_part_error_text_length,
			{ "Error Text Length", "saphdb.segment.part.error.text_length", FT_INT32, BASE_DEC, NULL, 0x0, "SAP HDB Error Text Length", HFILL }},
		{ &hf_saphdb_part_error_level,
			{ "Error Level", "saphdb.segment.part.error.level", FT_INT8, BASE_DEC, VALS(saphdb_error_level_vals), 0x0, "SAP HDB Error Level", HFILL }},
		{ &hf_saphdb_part_error_sqlstate,
			{ "SQL State", "saphdb.segment.part.error.sqlstate", FT_STRING, BASE_NONE, NULL, 0x0, "SAP HDB Error SQL State", HFILL }},
		{ &hf_saphdb_part_error_text,
			{ "Error Text", "saphdb.segment.part.error.text", FT_STRING, BASE_NONE, NULL, 0x0, "SAP HDB Error Text", HFILL }},

		/* Part Buffer AUTHENTICATION items */
		{ &hf_saphdb_part_authentication_field_count,
			{ "Field Count", "saphdb.segment.part.authentication.fieldcount", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP HDB AUTHENTICATION Field Count", HFILL }},
		{ &hf_saphdb_part_authentication_field_length,
			{ "Field Length", "saphdb.segment.part.authentication.fieldlength", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP HDB AUTHENTICATION Field Length", HFILL }},
		{ &hf_saphdb_part_authentication_field_value,
			{ "Field Value", "saphdb.segment.part.authentication.fieldvalue", FT_NONE, BASE_NONE, NULL, 0x0, "SAP HDB AUTHENTICATION Field Value", HFILL }},

		/* SAP HDB Part Buffer CLIENTID items */
		{ &hf_saphdb_part_clientid,
			{ "Client ID", "saphdb.segment.part.clientid", FT_STRING, BASE_NONE, NULL, 0x0, "SAP HDB Client ID", HFILL }},

	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_saphdb
	};

	/* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_saphdb_compressed_unknown, { "saphdb.compressed", PI_UNDECODED, PI_WARN, "The packet is compressed, and decompression is not supported", EXPFILL }},
		{ &ei_saphdb_option_part_unknown, { "saphdb.segment.part.option.unknown", PI_UNDECODED, PI_WARN, "The Option Part has a unknown type that is not dissected", EXPFILL }},
		{ &ei_saphdb_part_buffer_length_invalid, { "saphdb.segment.part.bufferlength", PI_MALFORMED, PI_ERROR, "The Part Buffer length is incorrect", EXPFILL }},
		{ &ei_saphdb_segments_incorrect_order, { "saphdb.segment.segmentno", PI_MALFORMED, PI_ERROR, "The segments are in incorrect order or are invalid", EXPFILL }},
		{ &ei_saphdb_segments_number_incorrect, { "saphdb.noofsegm", PI_MALFORMED, PI_ERROR, "The number of segments is incorrect", EXPFILL }},
		{ &ei_saphdb_segment_length, { "saphdb.segment.segmentlength", PI_MALFORMED, PI_ERROR, "The segment length is incorrect", EXPFILL }},
		{ &ei_saphdb_buffer_length, { "saphdb.segment.part.bufferlength", PI_MALFORMED, PI_ERROR, "The part buffer length is incorrect", EXPFILL }},
		{ &ei_saphdb_parts_number_incorrect, { "saphdb.segment.noofparts", PI_MALFORMED, PI_ERROR, "The number of parts is incorrect", EXPFILL }},
		{ &ei_saphdb_varpartlenght_incorrect, { "saphdb.varpartlength", PI_MALFORMED, PI_ERROR, "The length is incorrect", EXPFILL }},
	};

	module_t *saphdb_module;
	expert_module_t* saphdb_expert;

	/* Register the protocol */
	proto_saphdb = proto_register_protocol("SAP HANA SQL Command Network Protocol", "SAPHDB", "saphdb");

	saphdb_expert = expert_register_protocol(proto_saphdb);
	expert_register_field_array(saphdb_expert, ei, array_length(ei));

	saphdb_handle = register_dissector("saphdb", dissect_saphdb, proto_saphdb);

	proto_register_field_array(proto_saphdb, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the preferences */
	saphdb_module = prefs_register_protocol(proto_saphdb, proto_reg_handoff_saphdb);

	range_convert_str(wmem_epan_scope(), &global_saphdb_port_range, SAPHDB_PORT_RANGE, MAX_TCP_PORT);
	prefs_register_range_preference(saphdb_module, "tcp_ports", "SAP HANA SQL Command Network Protocol port numbers", "Port numbers used for SAP HANA SQL Command Network Protocol (default " SAPHDB_PORT_RANGE ")", &global_saphdb_port_range, MAX_TCP_PORT);

	prefs_register_bool_preference(saphdb_module, "highlight_unknown_items", "Highlight unknown SAP HANA HDB items", "Whether the SAP HANA HDB Protocol dissector should highlight unknown items (might be noise and generate a lot of expert warnings)", &global_saphdb_highlight_items);

}

/**
 * Helpers for dealing with the port range
 */
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

	saphdb_port_range = range_copy(wmem_epan_scope(), global_saphdb_port_range);
	range_foreach(saphdb_port_range, range_add_callback, NULL);
	ssl_dissector_add(0, saphdb_handle);

	gssapi_handle = find_dissector_add_dependency("gssapi", proto_saphdb);

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
