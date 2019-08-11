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

static gint ett_saphdb = -1;


/* Global port preference */
static range_t *global_saphdb_port_range;


/* Protocol handle */
static dissector_handle_t saphdb_handle;

void proto_reg_handoff_saphdb(void);


static int
dissect_saphdb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPHDB");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	if (tree) { /* we are being asked for details */

		proto_item *ti = NULL;
		proto_tree *saphdb_tree = NULL;

		/* Add the main saphdb subtree */
		ti = proto_tree_add_item(tree, proto_saphdb, tvb, 0, -1, ENC_NA);
		saphdb_tree = proto_item_add_subtree(ti, ett_saphdb);

	}

	return tvb_reported_length(tvb);
}

void
proto_register_saphdb(void)
{
	static hf_register_info hf[] = {
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
