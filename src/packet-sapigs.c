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
#   Layer added by Yvan Genuer (@iggy38), Devoteam.
#   Martin Gallo (@martingalloar) from SecureAuth's Innovation Labs team.
#
*/

#include "config.h"

#include <inttypes.h>
#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <wsutil/wmem/wmem.h>

/* Define default ports */
#define SAPIGS_PORT_RANGE "40000-49999"

/* IGS Functions values */
static const value_string sapigs_function_lst[] = {
	{ 1, "ADM:REGPW"},		/* Register a PortWatcher */
	{ 2, "ADM:UNREGPW"},		/* Unregsiter a PortWatcher */
	{ 3, "ADM:REGIP"},		/* Register an Interpreter */
	{ 4, "ADM:UNREGIP"},		/* Unregsiter an Interpreter */
	{ 5, "ADM:FREEIP"},		/* Inform than Interpreter is free */
	{ 6, "ADM:ILLBEBACK"},		/* Call back function */
	{ 7, "ADM:ABORT"},		/* Abort Interpreter work */
	{ 8, "ADM:PING"},		/* Ping receive */
	{ 9, "ADM:PONG"},		/* Ping send */
	{ 10, "ADM:SHUTDOWNIGS"},	/* Shutdown IGS */
	{ 11, "ADM:SHUTDOWNPW"},	/* Shutdown PortWatcher */
	{ 12, "ADM:CHECKCONSUMER"},	/* Check Portwatcher status */
	{ 13, "ADM:FREECONSUMER"},	/* Inform than portwather is free */
	{ 14, "ADM:GETLOGFILE"},	/* Display log file */
	{ 15, "ADM:GETCONFIGFILE"},	/* Display configfile */
	{ 16, "ADM:GETDUMP"},		/* Display dump file */
	{ 17, "ADM:DELETEDUMP"},	/* Delete dump file */
	{ 18, "ADM:INSTALL"},		/* Upload shapefiles for GIS */
	{ 19, "ADM:SWITCH"},		/* Switch trace log level */
	{ 20, "ADM:GETVERSION"},	/* Get IGS Version */
	{ 21, "ADM:STATUS"},		/* Display IGS Status */
	{ 22, "ADM:STATISTIC"},		/* old Display IGS Statistic */
	{ 23, "ADM:STATISTICNEW"},	/* Display IGS Statistic */
	{ 24, "ADM:GETSTATCHART"},	/* Get IGS Statistic chart */
	{ 25, "ADM:SIM"},		/* Simulation function */
	{ 30, "ZIPPER"},		/* ZIP provide file(s) */
	{ 31, "IMGCONV"},		/* Image converter */
	{ 32, "RSPOCONNECTOR"},		/* Remote Spool Connector */
	{ 33, "XMLCHART"},		/* Chart generator throught xml input */
	{ 34, "CHART"},			/* Chart generator throught ABAP Table input */
	{ 35, "BWGIS"},			/* BW Geographic Information System */
	{ 36, "SAPGISXML"},		/* old SAP GIS throught xml input */
	/* NULL */
	{ 0, NULL}
};

static int proto_sapigs = -1;

/* Headers */
static int hf_sapigs_function = -1;
static int hf_sapigs_listener = -1;
static int hf_sapigs_hostname = -1;
static int hf_sapigs_id = -1;
static int hf_sapigs_padd1 = -1;
static int hf_sapigs_flag1 = -1;
static int hf_sapigs_padd2 = -1;
static int hf_sapigs_flag2 = -1;
static int hf_sapigs_padd3 = -1;

/* Data */
static int hf_sapigs_eye_catcher = -1;
static int hf_sapigs_padd4 = -1;
static int hf_sapigs_codepage = -1;
static int hf_sapigs_offset_data = -1;
static int hf_sapigs_data_size = -1;
static int hf_sapigs_data = -1;

/* Table definition */
static int hf_sapigs_tables = -1;
static int hf_sapigs_table_version = -1;
static int hf_sapigs_table_name = -1;
static int hf_sapigs_table_line_number = -1;
static int hf_sapigs_table_width = -1;
static int hf_sapigs_table_column_name = -1;
static int hf_sapigs_table_column_number = -1;
static int hf_sapigs_table_column_width = -1;

/* Others */
static int hf_sapigs_portwatcher = -1;
static int hf_sapigs_portwatcher_version = -1;
static int hf_sapigs_portwatcher_info = -1;
static int hf_sapigs_interpreter = -1;
static int hf_sapigs_chart_config = -1;

static gint ett_sapigs = -1;

/* Global port preference */
static range_t *global_sapigs_port_range;

/* Global highlight preference */
static gboolean global_sapigs_highlight_items = TRUE;

/* Protocol handle */
static dissector_handle_t sapigs_handle;

void proto_reg_handoff_sapigs(void);


static int
dissect_sapigs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPIGS");
	/* Add function name in the info column */
	col_add_fstr(pinfo->cinfo, COL_INFO, " function: %s", tvb_get_string_enc(wmem_packet_scope(), tvb, 0, 32, ENC_ASCII));

	if (tree) { /* we are being asked for details */

		guint32 offset = 0, err_val = 0;
		long data_offset = 0, data_length = 0;
		gchar *sapigs_info_function = NULL, *illbeback_type = NULL, *is_table = NULL;
		proto_item *ti = NULL, *sapigs_tables = NULL;
		proto_tree *sapigs_tree = NULL, *sapigs_tables_tree = NULL;

		/* Add the main sapigs subtree */
		ti = proto_tree_add_item(tree, proto_sapigs, tvb, 0, -1, ENC_NA);
		sapigs_tree = proto_item_add_subtree(ti, ett_sapigs);

		/* Retreive function name */
		sapigs_info_function = (char *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 32, ENC_ASCII);

		/* Headers */
		proto_tree_add_item(sapigs_tree, hf_sapigs_function, tvb, offset, 32, ENC_ASCII|ENC_NA); offset += 32;
		proto_tree_add_item(sapigs_tree, hf_sapigs_listener, tvb, offset, 32, ENC_ASCII|ENC_NA); offset += 32;
		proto_tree_add_item(sapigs_tree, hf_sapigs_hostname, tvb, offset, 81, ENC_ASCII|ENC_NA); offset += 81;
		proto_tree_add_item(sapigs_tree, hf_sapigs_id, tvb, offset, 4, ENC_ASCII|ENC_NA); offset += 4;
		proto_tree_add_item(sapigs_tree, hf_sapigs_padd1, tvb, offset, 15, ENC_NA); offset += 15;
		proto_tree_add_item(sapigs_tree, hf_sapigs_flag1, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
		proto_tree_add_item(sapigs_tree, hf_sapigs_padd2, tvb, offset, 20, ENC_NA); offset += 20;
		proto_tree_add_item(sapigs_tree, hf_sapigs_flag2, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
		proto_tree_add_item(sapigs_tree, hf_sapigs_padd3, tvb, offset, 6, ENC_NA); offset += 6;

		/* switch over function name value */
		switch (str_to_val(sapigs_info_function, sapigs_function_lst, err_val)){
			case 8:{	/* ADM:PING */
				proto_tree_add_item(sapigs_tree, hf_sapigs_portwatcher, tvb, offset, 5, ENC_ASCII|ENC_NA); offset += 5;
				break;
			}
			case 9:{	/* ADM:PONG */
				break;
			}
			case 1:{	/* ADM:REGPW */
				proto_tree_add_item(sapigs_tree, hf_sapigs_portwatcher, tvb, offset, 5, ENC_ASCII|ENC_NA); offset += 32;
				proto_tree_add_item(sapigs_tree, hf_sapigs_portwatcher_version, tvb, offset, 16, ENC_ASCII|ENC_NA); offset += 16;
				break;
			}
			case 3:		/* ADM:REGIP */
			case 5:{	/* ADM:FREEIP */
				proto_tree_add_item(sapigs_tree, hf_sapigs_portwatcher, tvb, offset, 5, ENC_ASCII|ENC_NA); offset += 32;
				proto_tree_add_item(sapigs_tree, hf_sapigs_interpreter, tvb, offset, 16, ENC_ASCII|ENC_NA); offset += 32;
				proto_tree_add_item(sapigs_tree, hf_sapigs_portwatcher_version, tvb, offset, 16, ENC_ASCII|ENC_NA); offset += 32;
				proto_tree_add_item(sapigs_tree, hf_sapigs_portwatcher_info, tvb, offset, 16, ENC_ASCII|ENC_NA); offset += 32;
				break;
			}
			case 6:{	/* ADM:ILLBEBACK */
				illbeback_type = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 10, ENC_ASCII|ENC_NA);
				if (strncmp("TransMagic", illbeback_type, 10) == 0){
					/* data is raw after eye_catcher */
					proto_tree_add_item(sapigs_tree, hf_sapigs_eye_catcher, tvb, offset, 10, ENC_ASCII|ENC_NA); offset += 16;
					proto_tree_add_item(sapigs_tree, hf_sapigs_data, tvb, offset, -1, ENC_ASCII|ENC_NA);
				} else {
					/* we receive sized data */
					data_length = strtol((gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 5, ENC_ASCII), NULL, 10);
					proto_tree_add_item(sapigs_tree, hf_sapigs_data_size, tvb, offset, 5, ENC_ASCII|ENC_NA); offset += 5;
					/* Data */
					if ((data_length > 0) && (tvb_reported_length_remaining(tvb, offset) >= data_length)) {
						proto_tree_add_item(sapigs_tree, hf_sapigs_data, tvb, offset, data_length, ENC_ASCII|ENC_NA); offset += data_length;
					}
				}
				break;
			}
			case 30:	/* ZIPPER */
			case 31:	/* IMGCONV */
			case 33:	/* XMLCHART */
			case 16:{	/* ADM:GETDUMP */
				proto_tree_add_item(sapigs_tree, hf_sapigs_eye_catcher, tvb, offset, 10, ENC_ASCII|ENC_NA); offset += 10;
				proto_tree_add_item(sapigs_tree, hf_sapigs_padd4, tvb, offset, 2, ENC_NA); offset += 2;
				proto_tree_add_item(sapigs_tree, hf_sapigs_codepage, tvb, offset, 4, ENC_ASCII|ENC_NA); offset += 4;
				/* Data offset */
				data_offset = strtol((gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 16, ENC_ASCII), NULL, 10);
				proto_tree_add_item(sapigs_tree, hf_sapigs_offset_data, tvb, offset, 16, ENC_ASCII|ENC_NA); offset += 16;
				/* Data length */
				data_length = strtol((gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 16, ENC_ASCII), NULL, 10);
				proto_tree_add_item(sapigs_tree, hf_sapigs_data_size, tvb, offset, 16, ENC_ASCII|ENC_NA); offset += 16;
				data_offset += offset;
		                /* Definition tables */
				is_table = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ENC_ASCII);
				/* if the 4 next char is VERS, we are at the begining of one definition table */
				while(strncmp("VERS", is_table, 4) == 0){
					/* Build a tree for Tables */
			                sapigs_tables = proto_tree_add_item(sapigs_tree, hf_sapigs_tables, tvb, offset, 336, ENC_NA);
			                sapigs_tables_tree = proto_item_add_subtree(sapigs_tables, ett_sapigs);
					proto_tree_add_item(sapigs_tables_tree, hf_sapigs_table_version, tvb, offset+8, 40, ENC_NA); offset += 48;
			                proto_tree_add_item(sapigs_tables_tree, hf_sapigs_table_name, tvb, offset+8, 40, ENC_NA); offset += 48;
			                proto_tree_add_item(sapigs_tables_tree, hf_sapigs_table_line_number, tvb, offset+8, 40, ENC_NA); offset += 48;
			                proto_tree_add_item(sapigs_tables_tree, hf_sapigs_table_width, tvb, offset+8, 40, ENC_NA); offset += 48;
			                proto_tree_add_item(sapigs_tables_tree, hf_sapigs_table_column_name, tvb, offset+8, 40, ENC_NA); offset += 48;
			                proto_tree_add_item(sapigs_tables_tree, hf_sapigs_table_column_number, tvb, offset+8, 40, ENC_NA); offset += 48;
			                proto_tree_add_item(sapigs_tables_tree, hf_sapigs_table_column_width, tvb, offset+8, 40, ENC_NA); offset += 48;
					is_table = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 4, ENC_ASCII);
					}
				/* Data */
				if ((data_length > 0) && (tvb_reported_length_remaining(tvb, offset) >= data_length)) {
					proto_tree_add_item(sapigs_tree, hf_sapigs_data, tvb, data_offset, data_length, ENC_ASCII|ENC_NA); offset += data_length;
				}
				break;
			}
			case 34:{	/* CHART */
				proto_tree_add_item(sapigs_tree, hf_sapigs_chart_config, tvb, offset, 32, ENC_ASCII|ENC_NA); offset += 32;
				proto_tree_add_item(sapigs_tree, hf_sapigs_data, tvb, offset, -1, ENC_ASCII|ENC_NA);
				break;
			}
		}
	}

	return tvb_reported_length(tvb);
}

void
proto_register_sapigs(void)
{
	static hf_register_info hf[] = {
		/* General Header fields */
		{ &hf_sapigs_function,
			{ "Function", "sapigs.function", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Function", HFILL }},
		{ &hf_sapigs_listener,
			{ "Listener", "sapigs.listener", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Listener", HFILL }},
		{ &hf_sapigs_hostname,
			{ "Hostname", "sapigs.hostname", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Hostname", HFILL }},
		{ &hf_sapigs_id,
			{ "Id", "sapigs.id", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Id", HFILL }},
		{ &hf_sapigs_padd1,
			{ "Padd1", "sapigs.padd1", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Padd 1", HFILL }},
		{ &hf_sapigs_flag1,
			{ "Flag1", "sapigs.flag1", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Flag 1", HFILL }},
		{ &hf_sapigs_padd2,
			{ "Padd2", "sapigs.padd2", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Padd 2", HFILL }},
		{ &hf_sapigs_flag2,
			{ "Flag2", "sapigs.flag2", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Flag 2", HFILL }},
		{ &hf_sapigs_padd3,
			{ "Padd3", "sapigs.padd3", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Padd 3", HFILL }},

		/* Data headers */
		{ &hf_sapigs_eye_catcher,
			{ "Eye catcher", "sapigs.eye_catcher", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Eye Catcher", HFILL }},
		{ &hf_sapigs_padd4,
			{ "Padd4", "sapigs.padd4", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Padd 4", HFILL }},
		{ &hf_sapigs_codepage,
			{ "Codepage", "sapigs.codepage", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Codepage", HFILL }},
		{ &hf_sapigs_offset_data,
			{ "Offset to data", "sapigs.offset_data", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Offset to data", HFILL }},
		{ &hf_sapigs_data_size,
			{ "Data size", "sapigs.data_size", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Data size", HFILL }},

		/* Portwatcher fields */
		{ &hf_sapigs_portwatcher,
			{ "Portwatcher Port", "sapigs.portwatcher", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Portwatcher port", HFILL }},
		{ &hf_sapigs_portwatcher_version,
			{ "Portwatcher version", "sapigs.portwatcher_version", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Portwatcher version", HFILL }},
		{ &hf_sapigs_portwatcher_info,
			{ "Portwatcher Info", "sapigs.portwatcher_info", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Portwatcher info", HFILL }},

		/* Interpreter information */
		{ &hf_sapigs_interpreter,
			{ "Interpreter name", "sapigs.interpreter", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Interpreter name", HFILL }},
		{ &hf_sapigs_chart_config,
			{ "Chart configuration", "sapigs.chart_config", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Chart configuration", HFILL }},

		/* Table definition fields */
		{ &hf_sapigs_tables,
			{ "Table definition", "sapigs.tables", FT_NONE, BASE_NONE, NULL, 0x0, "SAP IGS Tables definition", HFILL }},
		{ &hf_sapigs_table_version,
			{ "VERS", "sapigs.table_version", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Table Version", HFILL }},
		{ &hf_sapigs_table_name,
			{ "TBNM", "sapigs.table_name", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Table Name", HFILL }},
		{ &hf_sapigs_table_line_number,
			{ "TBLN", "sapigs.table_line_number", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Line count", HFILL }},
		{ &hf_sapigs_table_width,
			{ "TBWD", "sapigs.table_width", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Table Width", HFILL }},
		{ &hf_sapigs_table_column_name,
			{ "TBCL", "sapigs.table_column_name", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Table Column Name", HFILL }},
		{ &hf_sapigs_table_column_number,
			{ "CLNM", "sapigs.table_column_number", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Column count", HFILL }},
		{ &hf_sapigs_table_column_width,
			{ "CLWD", "sapigs.table_column_width", FT_STRING, BASE_NONE, NULL, 0x0, "SAP IGS Column width", HFILL }},

		/* Data */
		{ &hf_sapigs_data,
			{ "Data", "sapigs.table_data", FT_NONE, BASE_NONE, NULL, 0x0, "SAP IGS Data", HFILL }}
	};

	/* Setup protocol subtre array */
	static gint *ett[] = {
		&ett_sapigs
	};

	module_t *sapigs_module;

	/* Register the protocol */
	proto_sapigs = proto_register_protocol("SAP Internet Graphic Server", "SAPIGS", "sapigs");

	register_dissector("sapigs", dissect_sapigs, proto_sapigs);

	proto_register_field_array(proto_sapigs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register the preferences */
	sapigs_module = prefs_register_protocol(proto_sapigs, proto_reg_handoff_sapigs);

	range_convert_str(wmem_epan_scope(), &global_sapigs_port_range, SAPIGS_PORT_RANGE, MAX_TCP_PORT);
	prefs_register_range_preference(sapigs_module, "tcp_ports", "SAP IGS Protocol TCP port numbers", "Port numbers used for SAP IGS Protocol (default "SAPIGS_PORT_RANGE ")", &global_sapigs_port_range, MAX_TCP_PORT);

	prefs_register_bool_preference(sapigs_module, "highlight_unknow_items", "Highlight unknow SAP IGS messages", "wheter the SAP IGS Protocol dissector should highlight unknown IGS messages", &global_sapigs_highlight_items);

}

/**
 * Helpers for dealing with the port range
 */
static void range_delete_callback (guint32 port, gpointer ptr _U_)
{
        dissector_delete_uint("sapni.port", port, sapigs_handle);
}

static void range_add_callback (guint32 port, gpointer ptr _U_)
{
        dissector_add_uint("sapni.port", port, sapigs_handle);
}

/**
 * Register Hand off for the SAP IGS Protocol
 */
void
proto_reg_handoff_sapigs(void)
{
	static range_t *sapigs_port_range;
	static gboolean initialized = FALSE;

	if (!initialized) {
		sapigs_handle = create_dissector_handle(dissect_sapigs, proto_sapigs);
		initialized = TRUE;
	} else {
		range_foreach(sapigs_port_range, range_delete_callback, NULL);
		wmem_free(wmem_epan_scope(), sapigs_port_range);
	}

	sapigs_port_range = range_copy(wmem_epan_scope(), global_sapigs_port_range);
	range_foreach(sapigs_port_range, range_add_callback, NULL);
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
