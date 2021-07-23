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
#include <epan/wmem/wmem.h>

/* Common helpers for adding items */
#include "saphelpers.h"

/* SAP Decompression routine */
#include "sapdecompress.h"


/* Define default ports. It could be 3200-3299, but 3298 it's usually
 * used for the niping tool and 3299 is associated to SAP Router. */
#define SAPDIAG_PORT_RANGE "3200-3297"

/* SAP Diag Header Communication Flag values */
#define SAPDIAG_COM_FLAG_TERM_EOS   0x01
#define SAPDIAG_COM_FLAG_TERM_EOC   0x02
#define SAPDIAG_COM_FLAG_TERM_NOP   0x04
#define SAPDIAG_COM_FLAG_TERM_EOP   0x08
#define SAPDIAG_COM_FLAG_TERM_INI   0x10
#define SAPDIAG_COM_FLAG_TERM_CAS   0x20
#define SAPDIAG_COM_FLAG_TERM_NNM   0x40
#define SAPDIAG_COM_FLAG_TERM_GRA   0x80

/* SAP Diag Header Compression field values */
static const value_string sapdiag_compress_vals[] = {
	{ 0x0, "Compression switched off" },
	{ 0x1, "Compression switched on" },
	{ 0x2, "Data encrypted" },
	{ 0x3, "Data encrypted wrap" },
	/* NULL */
	{ 0x0, NULL }
};

/* SAP Diag Header Algorithm field values */
static const value_string sapdiag_algorithm_vals[] = {
	{ 0x10, "LZC" },
	{ 0x12, "LZH" },
	/* NULL */
	{ 0x00, NULL }
};


/* SAP Diag DP Header Request ID values */
static const value_string sapdiag_dp_request_id_vals[] = {
	{ 0x00000000, "NOWP" },
	{ 0x00000001, "DIA" },
	{ 0x00000002, "DUPD" },
	{ 0x00000003, "DENQ" },
	{ 0x00000004, "DBTC" },
	{ 0x00000005, "DSPO" },
	{ 0x00000006, "DUP2" },
	/* NULL */
	{ 0x00000000, NULL}
};

/* SAP Diag DP Header Sender ID values */
static const value_string sapdiag_dp_sender_id_vals[] = {
	{ 0x01, "DISPATCHER" },
	{ 0x02, "WORK_PROCESS" },
	{ 0x04, "REMOTE_TERMINAL" },
	{ 0x20, "APPC_TERMINAL" },
	{ 0x40, "APPC_GATEWAY" },
	{ 0xC8, "ICMAN" },
	{ 0xC9, "IC_MONITOR" },
	{ 0xCB, "LCOM" },
	/* NULL */
	{ 0x00, NULL}
};

/* SAP Diag DP Header Action Type values */
static const value_string sapdiag_dp_action_type_vals[] = {
	{ 0x01, "SEND_TO_DP" },
	{ 0x02, "SEND_TO_WP" },
	{ 0x03, "SEND_TO_TM" },
	{ 0x04, "SEND_TO_APPC" },
	{ 0x05, "SEND_TO_APPCTM" },
	{ 0x06, "SEND_MSG_TYPE" },
	{ 0x07, "SEND_MSG_REQUES" },
	{ 0x08, "SEND_MSG_REPLY" },
	{ 0x09, "SEND_MSG_ONEWAY" },
	{ 0x0A, "SEND_MSG_ADMIN" },
	{ 0x0B, "WAKE_UP_WPS" },
	{ 0x0C, "SET_TIMEOUT" },
	{ 0x0D, "DEL_SCHEDULE" },
	{ 0x0E, "ADD_SOFT_SERV" },
	{ 0x0F, "SUB_SOFT_SERV" },
	{ 0x10, "SHUTDOWN" },
	{ 0x11, "SEND_TO_MSGSERV" },
	{ 0x12, "SEND_TO_PLUGIN" },
	/* NULL */
	{ 0x00, NULL}
};

/* SAP Diag DP Header Request Info Flag constants */
#define SAPDIAG_DP_REQ_INFO_UNDEFINED 		0x00
#define SAPDIAG_DP_REQ_INFO_LOGIN		0x01
#define SAPDIAG_DP_REQ_INFO_LOGOFF		0x02
#define SAPDIAG_DP_REQ_INFO_SHUTDOWN		0x04
#define SAPDIAG_DP_REQ_INFO_GRAPHIC_TM		0x08
#define SAPDIAG_DP_REQ_INFO_ALPHA_TM		0x10
#define SAPDIAG_DP_REQ_INFO_ERROR_FROM_APPC	0x20
#define SAPDIAG_DP_REQ_INFO_CANCELMODE		0x40
#define SAPDIAG_DP_REQ_INFO_MSG_WITH_REQ_BUF	0x80

#define SAPDIAG_DP_REQ_INFO_MSG_WITH_OH		0x01
#define SAPDIAG_DP_REQ_INFO_BUFFER_REFRESH	0x02
#define SAPDIAG_DP_REQ_INFO_BTC_SCHEDULER	0x04
#define SAPDIAG_DP_REQ_INFO_APPC_SERVER_DOWN	0x08
#define SAPDIAG_DP_REQ_INFO_MS_ERROR		0x10
#define SAPDIAG_DP_REQ_INFO_SET_SYSTEM_USER	0x20
#define SAPDIAG_DP_REQ_INFO_DP_CANT_HANDLE_REQ	0x40
#define SAPDIAG_DP_REQ_INFO_DP_AUTO_ABAP	0x80

#define SAPDIAG_DP_REQ_INFO_DP_APPL_SERV_INFO	0x01
#define SAPDIAG_DP_REQ_INFO_DP_ADMIN		0x02
#define SAPDIAG_DP_REQ_INFO_DP_SPOOL_ALRM	0x04
#define SAPDIAG_DP_REQ_INFO_DP_HAND_SHAKE	0x08
#define SAPDIAG_DP_REQ_INFO_DP_CANCEL_PRIV	0x10
#define SAPDIAG_DP_REQ_INFO_DP_RAISE_TIMEOUT	0x20
#define SAPDIAG_DP_REQ_INFO_DP_NEW_MODE		0x40
#define SAPDIAG_DP_REQ_INFO_DP_SOFT_CANCEL	0x80

#define SAPDIAG_DP_REQ_INFO_DP_TM_INPUT		0x01
#define SAPDIAG_DP_REQ_INFO_DP_TM_OUTPUT	0x02
#define SAPDIAG_DP_REQ_INFO_DP_ASYNC_RFC	0x04
#define SAPDIAG_DP_REQ_INFO_DP_ICM_EVENT	0x08
#define SAPDIAG_DP_REQ_INFO_DP_AUTO_TH		0x10
#define SAPDIAG_DP_REQ_INFO_DP_RFC_CANCEL	0x20
#define SAPDIAG_DP_REQ_INFO_DP_MS_ADM		0x40

/* SAP Diag Support Bits */
#define SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR	0x01  /* 0 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS	0x02  /* 1 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION	0x04  /* 2 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT	0x08  /* 3 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT	0x10  /* 4 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC	0x20  /* 5 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED	0x40  /* 6 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE	0x80  /* 7 */

#define SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE	0x01  /* 8 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE	0x02  /* 9 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1	0x04  /* 10 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1	0x08  /* 11 */
#define SAPDIAG_SUPPORT_BIT_UPPERCASE	0x10  /* 12 */
#define SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY	0x20  /* 13 */
#define SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE	0x40  /* 14 */
#define SAPDIAG_SUPPORT_BIT_RFC_DIALOG	0x80  /* 15 */

#define SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT	0x01  /* 16 */
#define SAPDIAG_SUPPORT_BIT_FKEY_TABLE	0x02  /* 17 */
#define SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT	0x04  /* 18 */
#define SAPDIAG_SUPPORT_BIT_STOP_TRANS	0x08  /* 19 */
#define SAPDIAG_SUPPORT_BIT_FULL_MENU	0x10  /* 20 */
#define SAPDIAG_SUPPORT_BIT_OBJECT_NAMES	0x20  /* 21 */
#define SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE	0x40  /* 22 */
#define SAPDIAG_SUPPORT_BIT_DLGH_FLAGS	0x80  /* 23 */

#define SAPDIAG_SUPPORT_BIT_APPL_MNU	0x01  /* 24 */
#define SAPDIAG_SUPPORT_BIT_MESSAGE_INFO	0x02  /* 25 */
#define SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1	0x04  /* 26 */
#define SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB	0x08  /* 27 */
#define SAPDIAG_SUPPORT_BIT_GUIAPI	0x10  /* 28 */
#define SAPDIAG_SUPPORT_BIT_NOGRAPH	0x20  /* 29 */
#define SAPDIAG_SUPPORT_BIT_NOMESSAGES	0x40  /* 30 */
#define SAPDIAG_SUPPORT_BIT_NORABAX	0x80  /* 31 */

#define SAPDIAG_SUPPORT_BIT_NOSYSMSG	0x01  /* 32 */
#define SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT	0x02  /* 33 */
#define SAPDIAG_SUPPORT_BIT_NORFC	0x04  /* 34 */
#define SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT	0x08  /* 35 */
#define SAPDIAG_SUPPORT_BIT_MESSAGE_VARS	0x10  /* 36 */
#define SAPDIAG_SUPPORT_BIT_OCX_SUPPORT	0x20  /* 37 */
#define SAPDIAG_SUPPORT_BIT_SCROLL_INFOS	0x40  /* 38 */
#define SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK	0x80  /* 39 */

#define SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2	0x01  /* 40 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE	0x02  /* 41 */
#define SAPDIAG_SUPPORT_BIT_CURR_TCODE	0x04  /* 42 */
#define SAPDIAG_SUPPORT_BIT_CONN_WSIZE	0x08  /* 43 */
#define SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2	0x10  /* 44 */
#define SAPDIAG_SUPPORT_BIT_TABSTRIP	0x20  /* 45 */
#define SAPDIAG_SUPPORT_BIT_UNKNOWN_1	0x40  /* 46 (Unknown support bit) */
#define SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS	0x80  /* 47 */

#define SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES	0x01  /* 48 */
#define SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST	0x02  /* 49 */
#define SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER	0x04  /* 50 */
#define SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER	0x08  /* 51 */
#define SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER	0x10  /* 52 */
#define SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED	0x20  /* 53 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED	0x40  /* 54 */
#define SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO	0x80  /* 55 */

#define SAPDIAG_SUPPORT_BIT_TYPE_SERVER	0x01  /* 56 */
#define SAPDIAG_SUPPORT_BIT_COMBOBOX	0x02  /* 57 */
#define SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED	0x04  /* 58 */
#define SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE	0x08  /* 59 */
#define SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE	0x10  /* 60 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS	0x20  /* 61 */
#define SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS	0x40  /* 62 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_USERID	0x80  /* 63 */

#define SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT	0x01  /* 64 */
#define SAPDIAG_SUPPORT_BIT_USER_TURNTIME2	0x02  /* 65 */
#define SAPDIAG_SUPPORT_BIT_NUM_FIELD	0x04  /* 66 */
#define SAPDIAG_SUPPORT_BIT_WIN16	0x08  /* 67 */
#define SAPDIAG_SUPPORT_BIT_CONTEXT_MENU	0x10  /* 68 */
#define SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE	0x20  /* 69 */
#define SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION	0x40  /* 70 */
#define SAPDIAG_SUPPORT_BIT_LABEL_OWNER	0x80  /* 71 */

#define SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD	0x01  /* 72 */
#define SAPDIAG_SUPPORT_BIT_PROPERTY_BAG	0x02  /* 73 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_1	0x04  /* 74 */
#define SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2	0x08  /* 75 */
#define SAPDIAG_SUPPORT_BIT_PROPFONT_VALID	0x10  /* 76 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER	0x20  /* 77 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID	0x40  /* 78 */
#define SAPDIAG_SUPPORT_BIT_NOTGUI	0x80  /* 79 */

#define SAPDIAG_SUPPORT_BIT_WAN	0x01  /* 80 */
#define SAPDIAG_SUPPORT_BIT_XML_BLOBS	0x02  /* 81 */
#define SAPDIAG_SUPPORT_BIT_RFC_QUEUE	0x04  /* 82 */
#define SAPDIAG_SUPPORT_BIT_RFC_COMPRESS	0x08  /* 83 */
#define SAPDIAG_SUPPORT_BIT_JAVA_BEANS	0x10  /* 84 */
#define SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND	0x20  /* 85 */
#define SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE	0x40  /* 86 */
#define SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID	0x80  /* 87 */

#define SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB	0x01  /* 88 */
#define SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS	0x02  /* 89 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_2	0x04  /* 90 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_3	0x08  /* 91 */
#define SAPDIAG_SUPPORT_BIT_XML_PROPERTIES	0x10  /* 92 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_4	0x20  /* 93 */
#define SAPDIAG_SUPPORT_BIT_HEX_FIELD	0x40  /* 94 */
#define SAPDIAG_SUPPORT_BIT_HAS_CACHE	0x80  /* 95 */

#define SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE	0x01  /* 96 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_5	0x02  /* 97 */
#define SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2	0x04  /* 98 */
#define SAPDIAG_SUPPORT_BIT_ITS	0x08  /* 99 */
#define SAPDIAG_SUPPORT_BIT_NO_EASYACCESS	0x10  /* 100 */
#define SAPDIAG_SUPPORT_BIT_PROPERTYPUMP	0x20  /* 101 */
#define SAPDIAG_SUPPORT_BIT_COOKIE	0x40  /* 102 */
#define SAPDIAG_SUPPORT_BIT_UNUSED_6	0x80  /* 103 */

#define SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE	0x01  /* 104 */
#define SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE	0x02  /* 105 */
#define SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS	0x04  /* 106 */
#define SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY	0x08  /* 107 */
#define SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE	0x10  /* 108 */
#define SAPDIAG_SUPPORT_BIT_CACHED_VSETS	0x20  /* 109 */
#define SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR	0x40  /* 110 */
#define SAPDIAG_SUPPORT_BIT_AREA2FRONT	0x80  /* 111 */

#define SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH	0x01  /* 112 */
#define SAPDIAG_SUPPORT_BIT_AUTORESIZE	0x02  /* 113 */
#define SAPDIAG_SUPPORT_BIT_EDIT_VARLEN	0x04  /* 114 */
#define SAPDIAG_SUPPORT_BIT_WORKPLACE	0x08  /* 115 */
#define SAPDIAG_SUPPORT_BIT_PRINTDATA	0x10  /* 116 */
#define SAPDIAG_SUPPORT_BIT_UNKNOWN_2	0x20  /* 117 (Unknown support bit) */
#define SAPDIAG_SUPPORT_BIT_SINGLE_SESSION	0x40  /* 118 */
#define SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE	0x80  /* 119 */

#define SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT	0x01  /* 120 */
#define SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER	0x02  /* 121 */
#define SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO	0x04  /* 122 */
#define SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT	0x08  /* 123 */
#define SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT	0x10  /* 124 */
#define SAPDIAG_SUPPORT_BIT_WEBGUI	0x20  /* 125 */
#define SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE	0x40  /* 126 */
#define SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST	0x80  /* 127 */

#define SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2	0x01  /* 128 */
#define SAPDIAG_SUPPORT_BIT_EOKDUMMY_1	0x02  /* 129 */
#define SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING	0x04  /* 130 */
#define SAPDIAG_SUPPORT_BIT_SLC	0x08  /* 131 */
#define SAPDIAG_SUPPORT_BIT_ACCESSIBILITY	0x10  /* 132 */
#define SAPDIAG_SUPPORT_BIT_ECATT	0x20  /* 133 */
#define SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3	0x40  /* 134 */
#define SAPDIAG_SUPPORT_BIT_ENABLE_UTF8	0x80  /* 135 */

#define SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME	0x01  /* 136 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST	0x02  /* 137 */
#define SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE	0x04  /* 138 */
#define SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE	0x08  /* 139 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP	0x10  /* 140 */
#define SAPDIAG_SUPPORT_BIT_ENABLE_APPL4	0x20  /* 141 */
#define SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL	0x40  /* 142 */
#define SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE	0x80  /* 143 */

#define SAPDIAG_SUPPORT_BIT_BINARY_EVENTID	0x01  /* 144 */
#define SAPDIAG_SUPPORT_BIT_GUI_THEME	0x02  /* 145 */
#define SAPDIAG_SUPPORT_BIT_TOP_WINDOW	0x04  /* 146 */
#define SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1	0x08  /* 147 */
#define SAPDIAG_SUPPORT_BIT_SPLITTER	0x10  /* 148 */
#define SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY	0x20  /* 149 */
#define SAPDIAG_SUPPORT_BIT_ACC_LIST	0x40  /* 150 */
#define SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO	0x80  /* 151 */

#define SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM	0x01  /* 152 */
#define SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS	0x02  /* 153 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1	0x04  /* 154 */
#define SAPDIAG_SUPPORT_BIT_FRAME_1	0x08  /* 155 */
#define SAPDIAG_SUPPORT_BIT_TICKET4GUI	0x10  /* 156 */
#define SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS	0x20  /* 157 */
#define SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT	0x40  /* 158 */
#define SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP	0x80  /* 159 */

#define SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2	0x01  /* 160 */
#define SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3	0x02  /* 161 */
#define SAPDIAG_SUPPORT_BIT_CELLINFO	0x04  /* 162 */
#define SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2	0x08  /* 163 */
#define SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT	0x10  /* 164 */
#define SAPDIAG_SUPPORT_BIT_ITS_PLUGIN	0x20  /* 165 */
#define SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS	0x40  /* 166 */
#define SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI	0x80  /* 167 */

#define SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2	0x01  /* 168 */
#define SAPDIAG_SUPPORT_BIT_RCUI	0x02  /* 169 */
#define SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE	0x04  /* 170 */
#define SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE	0x08  /* 171 */
#define SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION	0x10  /* 172 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP	0x20  /* 173 */
#define SAPDIAG_SUPPORT_BIT_EOKDUMMY_2	0x40  /* 174 */
#define SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3	0x80  /* 175 */

#define SAPDIAG_SUPPORT_BIT_SBA2	0x01  /* 176 */
#define SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE	0x02  /* 177 */
#define SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2	0x04  /* 178 */
#define SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE	0x08  /* 179 */
#define SAPDIAG_SUPPORT_BIT_GUI_PACKET	0x10  /* 180 */
#define SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER	0x20  /* 181 */
#define SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION	0x40  /* 182 */
#define SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST	0x80  /* 183 */

#define SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME	0x01  /* 184 */
#define SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN	0x02  /* 185 */
#define SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1	0x04  /* 186 */
#define SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS	0x08  /* 187 */
#define SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO	0x10  /* 188 */
#define SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT	0x20  /* 189 */
#define SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH	0x40  /* 190 */
#define SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT	0x80  /* 191 */

#define SAPDIAG_SUPPORT_BIT_UNKNOWN_3	0x01  /* 192 (Unknown support bit) */
#define SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR	0x02  /* 193 */
#define SAPDIAG_SUPPORT_BIT_MAX_WSIZE	0x04  /* 194 */
#define SAPDIAG_SUPPORT_BIT_SAP_PERSONAS	0x08  /* 195 */
#define SAPDIAG_SUPPORT_BIT_IDA_ALV	0x10  /* 196 */
#define SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS	0x20  /* 197 */
#define SAPDIAG_SUPPORT_BIT_AMC	0x40  /* 198 */
#define SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC	0x80  /* 199 */

#define SAPDIAG_SUPPORT_BIT_GROUPBOX	0x01  /* 200 */
#define SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON	0x02  /* 201 */
#define SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST	0x04  /* 202 */
#define SAPDIAG_SUPPORT_BIT_FIORI_MODE	0x08  /* 203 */
#define SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE	0x10  /* 204 */
#define SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE	0x20  /* 205 */
#define SAPDIAG_SUPPORT_BIT_AGI_ID	0x40  /* 206 */
#define SAPDIAG_SUPPORT_BIT_AGI_ID_TC	0x80  /* 207 */

#define SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS	0x01  /* 208 */
#define SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE	0x02  /* 209 */
#define SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3	0x04  /* 210 */
#define SAPDIAG_SUPPORT_BIT_NWBC	0x08  /* 211 */
#define SAPDIAG_SUPPORT_BIT_CONTAINER_LIST	0x10  /* 212 */
#define SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR	0x20  /* 213 */
#define SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE	0x40  /* 214 */


/* SAP Diag DP Header New Status values */
static const value_string sapdiag_dp_new_stat_vals[] = {
	{ 0x00, "NO_CHANGE" },
	{ 0x01, "WP_SLOT_FREE" },
	{ 0x02, "WP_WAIT" },
	{ 0x04, "WP_RUN" },
	{ 0x08, "WP_HOLD" },
	{ 0x10, "WP_KILLED" },
	{ 0x20, "WP_SHUTDOWN" },
	{ 0x40, "WP_RESTRICTED" },
	{ 0x80, "WP_NEW" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item Type values */
static const value_string sapdiag_item_type_vals[] = {
	{ 0x01,	"SES" },
	{ 0x02, "ICO" },
	{ 0x03, "TIT" },
	{ 0x07, "DiagMessage (old format)" },
	{ 0x08, "OKC" },
	{ 0x09, "CHL" },
	{ 0x0a, "SFE" },
	{ 0x0b, "SBA" },
	{ 0x0c, "EOM" },
	{ 0x10,	"APPL" },
	{ 0x11, "DIAG_XMLBLOB" },
	{ 0x12, "APPL4" },
	{ 0x13, "SLC" },
	{ 0x15, "SBA2" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 ID values */
static const value_string sapdiag_item_id_vals[] = {
	{ 0x01, "SCRIPT" },
	{ 0x02, "GRAPH" },
	{ 0x03, "IXOS" },
	{ 0x04, "ST_USER" },
	{ 0x05, "DYNN" },
	{ 0x06, "ST_R3INFO" },
	{ 0x07, "POPU" },
	{ 0x08, "RFC_TR" },
	{ 0x09, "DYNT" },
	{ 0x0a, "CONTAINER" },
	{ 0x0b, "MNUENTRY" },
	{ 0x0c, "VARINFO" },
	{ 0x0e, "CONTROL" },
	{ 0x0f, "UI_EVENT" },
	{ 0x12, "ACC_LIST" },
	{ 0x13, "RCUI" },
	{ 0x14, "GUI_PACKET" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 SCRIPT SID values */
static const value_string sapdiag_item_appl_script_vals[] = {
	/* SCRIPT */
	{ 0x01, "SCRIPT_OTF" },
	{ 0x02, "SCRIPT_SCREEN" },
	{ 0x03, "SCRIPT_POSTSCRIPT" },
	{ 0x04, "SCRIPT_ITF" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 GRAPH SID values */
static const value_string sapdiag_item_appl_graph_vals[] = {
	/* GRAPH */
	{ 0x03, "GRAPH RELEASE 3" },
	{ 0x05, "GRAPH RELEASE 5" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 IXOS SID values */
static const value_string sapdiag_item_appl_ixos_vals[] = {
	/* IXOS */
	{ 0x01, "ABLAGE" },
	{ 0x02, "ANZEIGE" },
	{ 0x03, "IXOS_COMMAND" },
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 ST_USER SID values */
static const value_string sapdiag_item_appl_st_user_vals[] = {
	/* ST_USER */
	{ 0x01, "V1" },
	{ 0x02, "CONNECT" },
	{ 0x03, "SELECTEDRECT" },
	{ 0x04, "FONTMETRIC" },
	{ 0x05, "TABLEMETRIC" },
	{ 0x06, "GUITIME" },
	{ 0x07, "GUITIMEZONE" },
	{ 0x08, "TURNTIME" },
	{ 0x09, "GUIVERSION" },
	{ 0x0b, "SUPPORTDATA" },
	{ 0x0c, "RFC_CONNECT" },
	{ 0x0d, "WSIZE" },
	{ 0x0e, "V2" },
	{ 0x0f, "TURNTIME2" },
	{ 0x10, "RFC_PARENT_UUID" },
	{ 0x11, "RFC_NEW_UUID" },
	{ 0x12, "RFC_UUIDS" },
	{ 0x13, "RFC_UUIDS2" },
	{ 0x14, "XML_LOGIN" },
	{ 0x15, "XML_TRANSACTION" },
	{ 0x16, "SCROLLBAR_WIDTH" },
	{ 0x17, "TOOLBAR_HEIGHT" },
	{ 0x18, "PASSPORT_DATA" },
	{ 0x19, "GUI_STATE" },
	{ 0x1a, "DECIMALPOINT" },
	{ 0x1b, "LANGUAGE" },
	{ 0x1c, "USERNAME" },
	{ 0x1d, "GUIPATCHLEVEL" },
	{ 0x1e, "WSIZE_PIXEL" },
	{ 0x1f, "GUI_OS_VERSION" },
	{ 0x20, "BROWSER_VERSION" },
	{ 0x21, "OFFICE_VERSION" },
	{ 0x22, "JDK_VERSION" },
	{ 0x23, "GUIXT_VERSION" },
	{ 0x24, "DISPLAY_SIZE" },
	{ 0x25, "GUI_TYPE" },
	{ 0x26, "DIALOG_STEP_NUMBER" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 DYNN SID values */
static const value_string sapdiag_item_appl_dynn_vals[] = {
	/* DYNN */
	{ 0x01, "CHL" },
	{ 0x03, "XMLPROP DYNPRO" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 ST_R3INFO SID values */
static const value_string sapdiag_item_appl_st_r3info_vals[] = {
	/* ST_R3INFO */
	{ 0x01, "MODENUMBER" },
	{ 0x02, "DBNAME" },
	{ 0x03, "CPUNAME" },
	{ 0x04, "RFC_TRIGGER" },
	{ 0x05, "GUI_LABEL" },
	{ 0x06, "DIAGVERSION" },
	{ 0x07, "TCODE" },
	{ 0x08, "RFC_WAITING" },
	{ 0x09, "RFC_REFRESH" },
	{ 0x0a, "IMODENUMBER" },
	{ 0x0b, "MESSAGE" },
	{ 0x0c, "CLIENT" },
	{ 0x0d, "DYNPRONAME" },
	{ 0x0e, "DYNPRONUMBER" },
	{ 0x0f, "CUANAME" },
	{ 0x10, "CUASTATUS" },
	{ 0x11, "SUPPORTDATA" },
	{ 0x12, "RFC_CONNECT_OK" },
	{ 0x13, "GUI_FKEY" },
	{ 0x14, "GUI_FKEYT" },
	{ 0x15, "STOP_TRANS" },
	{ 0x16, "RFC_DIAG_BLOCK_SIZE" },
	{ 0x17, "USER_CHECKED" },
	{ 0x18, "FLAGS" },
	{ 0x19, "USERID" },
	{ 0x1a, "ROLLCOUNT" },
	{ 0x1b, "GUI_XT_VAR" },
	{ 0x1c, "IMODEUUID" },
	{ 0x1d, "IMODEUUID_INVALIDATE" },
	{ 0x1e, "IMODEUUIDS" },
	{ 0x1f, "IMODEUUIDS2" },
	{ 0x20, "CODEPAGE" },
	{ 0x21, "CONTEXTID" },
	{ 0x22, "AUTOLOGOUT_TIME" },
	{ 0x23, "CODEPAGE_DIAG_GUI" },
	{ 0x24, "CODEPAGE_APP_SERVER" },
	{ 0x25, "GUI_THEME" },
	{ 0x26, "GUI_USER_SCRIPTING" },
	{ 0x27, "CODEPAGE_APP_SERVER_1" },
	{ 0x28, "TICKET4GUI" },
	{ 0x29, "KERNEL_VERSION" },
	{ 0x2a, "STD_TOOLBAR_ITEMS" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 POPU SID values */
static const value_string sapdiag_item_appl_popu_vals[] = {
	/* POPU */
	{ 0x02, "DEST" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 RFC_TR SID values */
static const value_string sapdiag_item_appl_rfc_tr_vals[] = {
	/* RFC_TR */
	{ 0x00, "RFC_TR_REQ" },
	{ 0x01, "RFC_TR_RET" },
	{ 0x02, "RFC_TR_ERR" },
	{ 0x03, "RFC_TR_RQT" },
	{ 0x04, "RFC_TR_MOR" },
	{ 0x05, "RFC_TR_MOB" },
	{ 0x06, "RFC_TR_RNB" },
	{ 0x07, "RFC_TR_RNT" },
	{ 0x08, "RFC_TR_DIS" },
	{ 0x09, "RFC_TR_CALL" },
	{ 0x0a, "RFC_TR_CALL_END" },
	{ 0x0b, "RFC_TR_RES" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 DYNT SID values */
static const value_string sapdiag_item_appl_dynt_vals[] = {
	/* DYNT */
	{ 0x01, "DYNT_FOCUS" },
	{ 0x02, "DYNT_ATOM" },
	{ 0x03, "DYNT_EVENT_UNUSED" },
	{ 0x04, "TABLE_ROW_REFERENCE" },
	{ 0x05, "TABLE_ROW_DAT_INPUT_DUMMY" },
	{ 0x06, "TABLE_INPUT_HEADER" },
	{ 0x07, "TABLE_OUTPUT_HEADER" },
	{ 0x08, "TABLE_ROW_DATA_INPUT" },
	{ 0x09, "TABLE_ROW_DATA_OUTPUT" },
	{ 0x0a, "DYNT_NOFOCUS" },
	{ 0x0b, "DYNT_FOCUS_1" },
	{ 0x0c, "TABLE_ROW_REFERENCE_1" },
	{ 0x0d, "TABLE_FIELD_NAMES" },
	{ 0x0e, "TABLE_HEADER" },
	{ 0x0f, "DYNT_TABSTRIP_HEADER" },
	{ 0x10, "DYNT_TABSTRIP_BUTTONS" },
	{ 0x11, "TABLE_ROW_REFERENCE_2" },
	{ 0x12, "DYNT_CONTROL_FOCUS" },
	{ 0x13, "TABLE_FIELD_XMLPROP" },
	{ 0x14, "DYNT_SPLITTER_HEADER" },
	{ 0x15, "DYNT_TC_COLUMN_TITLE_XMLP" },
	{ 0x16, "DYNT_TC_ROW_SELECTOR_NAME" },
	{ 0x17, "DYNT_FOCUS_FRAME" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 CONTAINER SID values */
static const value_string sapdiag_item_appl_container_vals[] = {
	/* CONTAINTER */
	{ 0x01, "RESET" },
	{ 0x02, "DEFAULT" },
	{ 0x03, "SUBSCREEN" },
	{ 0x04, "LOOP" },
	{ 0x05, "TABLE" },
	{ 0x06, "NAME" },
	{ 0x08, "TABSTRIP" },
	{ 0x09, "TABSTRIP_PAGE" },
	{ 0x0a, "CONTROL" },
	{ 0x0c, "XMLPROP" },
	{ 0x0d, "SPLITTER" },
	{ 0x0e, "SPLITTER_CELL" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 MNUENTRY SID values */
static const value_string sapdiag_item_appl_mnuentry_vals[] = {
	/* MNUENTRY */
	{ 0x01, "MENU_ACT" },
	{ 0x02, "MENU_MNU" },
	{ 0x03, "MENU_PFK" },
	{ 0x04, "MENU_KYB" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 VARINFO SID values */
static const value_string sapdiag_item_appl_varinfo_vals[] = {
	/* VARINFO */
	{ 0x01, "MESTYPE" },
	{ 0x02, "SCROLL_INFOS" },
	{ 0x03, "MESTYPE2" },
	{ 0x04, "OKCODE" },
	{ 0x05, "CONTAINER" },
	{ 0x06, "SCROLL_INFOS2" },
	{ 0x07, "AREASIZE" },
	{ 0x08, "AREA_PIXELSIZE" },
	{ 0x09, "SESSION_TITLE" },
	{ 0x0a, "SESSION_ICON" },
	{ 0x0b, "LIST_CELL_TEXT" },
	{ 0x0c, "CONTAINER_LOOP" },
	{ 0x0d, "LIST_FOCUS" },
	{ 0x0e, "MAINAREA_PIXELSIZE" },
	{ 0x0f, "SERVICE_REQUEST" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 CONTROl SID values */
static const value_string sapdiag_item_appl_control_vals[] = {
	/* CONTROL */
	{ 0x01, "CONTROL_PROPERTIES" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 UI_EVENT SID values */
static const value_string sapdiag_item_appl_ui_event_vals[] = {
	/* UI_EVENT */
	{ 0x01, "UI_EVENT_SOURCE" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 ACC_LIST SID values */
static const value_string sapdiag_item_appl_acc_list_vals[] = {
	/* ACC_LIST */
	{ 0x01, "ACC_LIST_INFO4FIELD" },
	{ 0x02, "ACC_LIST_CONTAINER" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 RCUI SID values */
static const value_string sapdiag_item_appl_rcui_vals[] = {
	/* RCUI */
	{ 0x01, "RCUI_STREAM" },
	{ 0x02, "RCUI_SYSTEM_ERROR" },
	{ 0x03, "RCUI_SPAGPA" },
	{ 0x04, "RCUI_MEMORYID" },
	{ 0x05, "RCUI_TXOPTION" },
	{ 0x06, "RCUI_VALUE" },
	{ 0x07, "RCUI_COMMAND" },
	{ 0x08, "RCUI_BDCMSG" },
	{ 0x09, "RCUI_CONNECT_DATA" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Item APPL/APPL4 GUI_PACKET SID values */
static const value_string sapdiag_item_appl_gui_packet_vals[] = {
	/* GUI_PACKET */
	{ 0x01, "GUI_PACKET_STATE" },
	{ 0x02, "GUI_PACKET_DATA" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Dynt Atom Etype values */
static const value_string sapdiag_item_dynt_atom_item_etype_vals[] = {
	{ 101, "DIAG_DGOTYP_EFIELD" },
	{ 102, "DIAG_DGOTYP_OFIELD" },
	{ 103, "DIAG_DGOTYP_KEYWORD" },
	{ 104, "DIAG_DGOTYP_CHECKBUTTON_4" },
	{ 105, "DIAG_DGOTYP_RADIOBUTTON_0" },
	{ 106, "DIAG_DGOTYP_PUSHBUTTON_3" },
	{ 107, "DIAG_DGOTYP_FRAME_3" },
	{ 108, "DIAG_DGOTYP_LOOP_6" },
	{ 109, "DIAG_DGOTYP_SUBSCREEN" },
	{ 111, "DIAG_DGOTYP_PROPERTY" },
	{ 112, "DIAG_DGOTYP_ICON_0" },
	{ 113, "DIAG_DGOTYP_PUSHBUTTON_1" },
	{ 114, "DIAG_DGOTYP_FNAME" },
	{ 115, "DIAG_DGOTYP_PUSHBUTTON_2" },
	{ 116, "DIAG_DGOTYP_TABSTRIP_BUTTON" },
	{ 117, "DIAG_DGOTYP_COMBOBOX" },
	{ 118, "DIAG_DGOTYP_CHECKBUTTON_1" },
	{ 119, "DIAG_DGOTYP_RADIOBUTTON_1" },
	{ 120, "DIAG_DGOTYP_XMLPROP" },
	{ 121, "DIAG_DGOTYP_EFIELD_1" },
	{ 122, "DIAG_DGOTYP_OFIELD_1" },
	{ 123, "DIAG_DGOTYP_KEYWORD_1_1" },
	{ 124, "DIAG_DGOTYP_CHECKBUTTON_2" },
	{ 125, "DIAG_DGOTYP_RADIOBUTTON__0" },
	{ 126, "DIAG_DGOTYP_COMBOBOX_1" },
	{ 127, "DIAG_DGOTYP_FRAME_1" },
	{ 128, "DIAG_DGOTYP_CHECKBUTTON_3" },
	{ 129, "DIAG_DGOTYP_RADIOBUTTON_3" },
	{ 130, "DIAG_DGOTYP_EFIELD_2" },
	{ 131, "DIAG_DGOTYP_OFIELD_2" },
	{ 132, "DIAG_DGOTYP_KEYWORD_2" },
	/* NULL */
	{ 000, NULL }
};

/* SAP Diag UI Event Source Event Type Values */
static const value_string sapdiag_item_ui_event_event_type_vals[] = {
	{ 0x01, "SELECT" },
	{ 0x02, "HE" },
	{ 0x03, "VALUEHELP" },
	{ 0x06, "RESIZE" },
	{ 0x07, "FUNCTIONKEY" },
	{ 0x08, "SCROLL" },
	{ 0x09, "BUTTONPRESSED" },
	{ 0x0a, "VALUECHANGED" },
	{ 0x0b, "STATECHANGED" },
	{ 0x0c, "NAVIGATION" },
	/* NULL */
	{ 0x00, NULL }
};

static const value_string sapdiag_item_ui_event_control_type_vals[] = {
	{ 0x00, "NONE" },
	{ 0x01, "FIELD" },
	{ 0x02, "RADIOBUTTON" },
	{ 0x03, "CHECKBUTTON" },
	{ 0x04, "MENUBUTTON" },
	{ 0x05, "TOOLBARBUTTON" },
	{ 0x06, "STANDARDTOOLBARBUTTON" },
	{ 0x07, "PUSHBUTTON" },
	{ 0x08, "TABLEVIEW" },
	{ 0x09, "TABSTRIP" },
	{ 0x0a, "DYNPRO" },
	{ 0x0b, "CUSTOM_CONTROL" },
	{ 0x0d, "FRAME" },
	{ 0x0e, "TABLEVIEW_COLSEL_BUTTON" },
	{ 0x0f, "TABLEVIEW_ROWSEL_BUTTON" },
	{ 0x10, "TABLEVIEW_CELL" },
	{ 0x11, "CONTEXTMENU" },
	{ 0x12, "SPLITTER" },
	{ 0x13, "MESSAGE" },
	{ 0x14, "OKCODE" },
	{ 0x15, "ACC_CONTAINER" },
	/* NULL */
	{ 0x00, NULL }
};

static const value_string sapdiag_item_ui_event_navigation_data_vals[] = {
	{ 0x01, "TAB" },
	{ 0x02, "TAB_BACK" },
	{ 0x03, "JUMP_OVER" },
	{ 0x04, "JUMP_OVER_BACK" },
	{ 0x05, "JUMP_OUT" },
	{ 0x06, "JUMP_OUT_BACK" },
	{ 0x07, "JUMP_SECTION" },
	{ 0x08, "JUMP_SECTION_BACK" },
	{ 0x09, "FIRST_FIELD" },
	{ 0x0a, "LAST_FIELD" },
	/* NULL */
	{ 0x00, NULL }
};

static const value_string sapdiag_item_control_properties_id_vals[] = {
	{ 0x01, "CONTROL_AREA" },
	{ 0x02, "CONTROL_ID" },
	{ 0x03, "CONTROL_VISIBLE" },
	{ 0x04, "CONTROL_ROW" },
	{ 0x05, "CONTROL_COLUMN" },
	{ 0x06, "CONTROL_ROWS" },
	{ 0x07, "CONTROL_COLUMNS" },
	/* NULL */
	{ 0x00, NULL }
};

/* SAP Diag Dynt Atom Attr flags */
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_PROTECTED	0x01
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_INVISIBLE	0x02
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_INTENSIFY	0x04
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_JUSTRIGHT	0x08
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_MATCHCODE	0x10
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_PROPFONT	0x20
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_YES3D	0x40
#define SAPDIAG_ATOM_ATTR_DIAG_BSD_COMBOSTYLE	0x80

/* SAP Diag UI Event Source flags */
#define SAPDIAG_UI_EVENT_VALID_FLAG_MENU_POS		0x01
#define SAPDIAG_UI_EVENT_VALID_FLAG_CONTROL_POS		0x02
#define SAPDIAG_UI_EVENT_VALID_FLAG_NAVIGATION_DATA	0x04
#define SAPDIAG_UI_EVENT_VALID_FLAG_FUNCTIONKEY_DATA	0x08

static int proto_sapdiag = -1;

static int hf_sapdiag_dp = -1;
static int hf_sapdiag_header = -1;
static int hf_sapdiag_payload = -1;

/* Diag Header */
static int hf_sapdiag_mode = -1;
static int hf_sapdiag_com_flag = -1;
static int hf_sapdiag_com_flag_TERM_EOS = -1;
static int hf_sapdiag_com_flag_TERM_EOC = -1;
static int hf_sapdiag_com_flag_TERM_NOP = -1;
static int hf_sapdiag_com_flag_TERM_EOP = -1;
static int hf_sapdiag_com_flag_TERM_INI = -1;
static int hf_sapdiag_com_flag_TERM_CAS = -1;
static int hf_sapdiag_com_flag_TERM_NNM = -1;
static int hf_sapdiag_com_flag_TERM_GRA = -1;

static int hf_sapdiag_mode_stat = -1;
static int hf_sapdiag_err_no = -1;
static int hf_sapdiag_msg_type = -1;
static int hf_sapdiag_msg_info = -1;
static int hf_sapdiag_msg_rc = -1;
static int hf_sapdiag_compress = -1;

/* Error messages */
static int hf_sapdiag_error_message = -1;

/* Compression header */
static int hf_sapdiag_compress_header = -1;
static int hf_sapdiag_uncomplength = -1;
static int hf_sapdiag_algorithm = -1;
static int hf_sapdiag_magic = -1;
static int hf_sapdiag_special = -1;
static int hf_sapdiag_decompress_return_code = -1;

/* Message Data */
static int hf_sapdiag_item = -1;
static int hf_sapdiag_item_type = -1;
static int hf_sapdiag_item_id = -1;
static int hf_sapdiag_item_sid = -1;
static int hf_sapdiag_item_length = -1;
static int hf_sapdiag_item_value = -1;

/* Message DP Header */
static int hf_sapdiag_dp_request_id = -1;
static int hf_sapdiag_dp_retcode = -1;
static int hf_sapdiag_dp_sender_id = -1;
static int hf_sapdiag_dp_action_type = -1;
static int hf_sapdiag_dp_req_info = -1;

static int hf_sapdiag_dp_req_info_LOGIN = -1;
static int hf_sapdiag_dp_req_info_LOGOFF = -1;
static int hf_sapdiag_dp_req_info_SHUTDOWN = -1;
static int hf_sapdiag_dp_req_info_GRAPHIC_TM = -1;
static int hf_sapdiag_dp_req_info_ALPHA_TM = -1;
static int hf_sapdiag_dp_req_info_ERROR_FROM_APPC = -1;
static int hf_sapdiag_dp_req_info_CANCELMODE = -1;
static int hf_sapdiag_dp_req_info_MSG_WITH_REQ_BUF = -1;
static int hf_sapdiag_dp_req_info_MSG_WITH_OH = -1;
static int hf_sapdiag_dp_req_info_BUFFER_REFRESH = -1;
static int hf_sapdiag_dp_req_info_BTC_SCHEDULER = -1;
static int hf_sapdiag_dp_req_info_APPC_SERVER_DOWN = -1;
static int hf_sapdiag_dp_req_info_MS_ERROR = -1;
static int hf_sapdiag_dp_req_info_SET_SYSTEM_USER = -1;
static int hf_sapdiag_dp_req_info_DP_CANT_HANDLE_REQ = -1;
static int hf_sapdiag_dp_req_info_DP_AUTO_ABAP = -1;
static int hf_sapdiag_dp_req_info_DP_APPL_SERV_INFO = -1;
static int hf_sapdiag_dp_req_info_DP_ADMIN = -1;
static int hf_sapdiag_dp_req_info_DP_SPOOL_ALRM = -1;
static int hf_sapdiag_dp_req_info_DP_HAND_SHAKE = -1;
static int hf_sapdiag_dp_req_info_DP_CANCEL_PRIV = -1;
static int hf_sapdiag_dp_req_info_DP_RAISE_TIMEOUT = -1;
static int hf_sapdiag_dp_req_info_DP_NEW_MODE = -1;
static int hf_sapdiag_dp_req_info_DP_SOFT_CANCEL = -1;
static int hf_sapdiag_dp_req_info_DP_TM_INPUT = -1;
static int hf_sapdiag_dp_req_info_DP_TM_OUTPUT = -1;
static int hf_sapdiag_dp_req_info_DP_ASYNC_RFC = -1;
static int hf_sapdiag_dp_req_info_DP_ICM_EVENT = -1;
static int hf_sapdiag_dp_req_info_DP_AUTO_TH = -1;
static int hf_sapdiag_dp_req_info_DP_RFC_CANCEL = -1;
static int hf_sapdiag_dp_req_info_DP_MS_ADM = -1;

static int hf_sapdiag_dp_tid = -1;
static int hf_sapdiag_dp_uid = -1;
static int hf_sapdiag_dp_mode = -1;
static int hf_sapdiag_dp_wp_id = -1;
static int hf_sapdiag_dp_wp_ca_blk = -1;
static int hf_sapdiag_dp_appc_ca_blk = -1;
static int hf_sapdiag_dp_len = -1; /* Length of the SAP Diag Items in the login */
static int hf_sapdiag_dp_new_stat = -1;
static int hf_sapdiag_dp_rq_id = -1;
static int hf_sapdiag_dp_terminal = -1;

/* Dynt Atom */
static int hf_sapdiag_item_dynt_atom = -1;
static int hf_sapdiag_item_dynt_atom_item = -1;
static int hf_sapdiag_item_dynt_atom_item_etype = -1;
static int hf_sapdiag_item_dynt_atom_item_attr = -1;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_COMBOSTYLE = -1;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_YES3D = -1;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROPFONT = -1;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_MATCHCODE = -1;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_JUSTRIGHT = -1;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INTENSIFY = -1;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INVISIBLE = -1;
static int hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROTECTED = -1;

/* Control properties */
static int hf_sapdiag_item_control_properties_id = -1;
static int hf_sapdiag_item_control_properties_value = -1;

/* UI Event Source */
static int ht_sapdiag_item_ui_event_event_type = -1;
static int ht_sapdiag_item_ui_event_control_type = -1;
static int ht_sapdiag_item_ui_event_valid = -1;
static int ht_sapdiag_item_ui_event_valid_MENU_POS = -1;
static int ht_sapdiag_item_ui_event_valid_CONTROL_POS = -1;
static int ht_sapdiag_item_ui_event_valid_NAVIGATION_DATA = -1;
static int ht_sapdiag_item_ui_event_valid_FUNCTIONKEY_DATA = -1;
static int ht_sapdiag_item_ui_event_control_row = -1;
static int ht_sapdiag_item_ui_event_control_col = -1;
static int ht_sapdiag_item_ui_event_data = -1;
static int ht_sapdiag_item_ui_event_navigation_data = -1;
static int ht_sapdiag_item_ui_event_container_nrs = -1;
static int ht_sapdiag_item_ui_event_container = -1;

/* Menu Entries */
static int hf_sapdiag_item_menu_entry = -1;

/* Diag Support Bits */
static int hf_SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UPPERCASE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY = -1;
static int hf_SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_DIALOG = -1;
static int hf_SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_FKEY_TABLE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_STOP_TRANS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_FULL_MENU = -1;
static int hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DLGH_FLAGS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_APPL_MNU = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUIAPI = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NOGRAPH = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NOMESSAGES = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NORABAX = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NOSYSMSG = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NORFC = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_VARS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_OCX_SUPPORT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SCROLL_INFOS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CURR_TCODE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONN_WSIZE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TABSTRIP = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST = -1;
static int hf_SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TYPE_SERVER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_COMBOBOX = -1;
static int hf_SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_USERID = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_USER_TURNTIME2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NUM_FIELD = -1;
static int hf_SAPDIAG_SUPPORT_BIT_WIN16 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONTEXT_MENU = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION = -1;
static int hf_SAPDIAG_SUPPORT_BIT_LABEL_OWNER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD = -1;
static int hf_SAPDIAG_SUPPORT_BIT_PROPERTY_BAG = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_PROPFONT_VALID = -1;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NOTGUI = -1;
static int hf_SAPDIAG_SUPPORT_BIT_WAN = -1;
static int hf_SAPDIAG_SUPPORT_BIT_XML_BLOBS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_QUEUE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_COMPRESS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_JAVA_BEANS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID = -1;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB = -1;
static int hf_SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_3 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_XML_PROPERTIES = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_4 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_HEX_FIELD = -1;
static int hf_SAPDIAG_SUPPORT_BIT_HAS_CACHE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_5 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ITS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NO_EASYACCESS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_PROPERTYPUMP = -1;
static int hf_SAPDIAG_SUPPORT_BIT_COOKIE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNUSED_6 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY = -1;
static int hf_SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CACHED_VSETS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR = -1;
static int hf_SAPDIAG_SUPPORT_BIT_AREA2FRONT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH = -1;
static int hf_SAPDIAG_SUPPORT_BIT_AUTORESIZE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_EDIT_VARLEN = -1;
static int hf_SAPDIAG_SUPPORT_BIT_WORKPLACE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_PRINTDATA = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SINGLE_SESSION = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_WEBGUI = -1;
static int hf_SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SLC = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ACCESSIBILITY = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ECATT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF8 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME = -1;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ENABLE_APPL4 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_BINARY_EVENTID = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_THEME = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TOP_WINDOW = -1;
static int hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SPLITTER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ACC_LIST = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_FRAME_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TICKET4GUI = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP = -1;
static int hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CELLINFO = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ITS_PLUGIN = -1;
static int hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_RCUI = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION = -1;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP = -1;
static int hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SBA2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_PACKET = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST = -1;
static int hf_SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN = -1;
static int hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO = -1;
static int hf_SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH = -1;
static int hf_SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT = -1;
static int hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_3 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MAX_WSIZE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_SAP_PERSONAS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_IDA_ALV = -1;
static int hf_SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_AMC = -1;
static int hf_SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GROUPBOX = -1;
static int hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST = -1;
static int hf_SAPDIAG_SUPPORT_BIT_FIORI_MODE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_AGI_ID = -1;
static int hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TC = -1;
static int hf_SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS = -1;
static int hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE = -1;
static int hf_SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3 = -1;
static int hf_SAPDIAG_SUPPORT_BIT_NWBC = -1;
static int hf_SAPDIAG_SUPPORT_BIT_CONTAINER_LIST = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR = -1;
static int hf_SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE = -1;

static gint ett_sapdiag = -1;

/* Expert info */
static expert_field ei_sapdiag_item_unknown = EI_INIT;
static expert_field ei_sapdiag_item_partial = EI_INIT;
static expert_field ei_sapdiag_item_unknown_length = EI_INIT;
static expert_field ei_sapdiag_item_offset_invalid = EI_INIT;
static expert_field ei_sapdiag_item_length_invalid = EI_INIT;
static expert_field ei_sapdiag_atom_item_unknown = EI_INIT;
static expert_field ei_sapdiag_atom_item_partial = EI_INIT;
static expert_field ei_sapdiag_atom_item_malformed = EI_INIT;
static expert_field ei_sapdiag_dynt_focus_more_cont_ids = EI_INIT;
static expert_field ei_sapdiag_password_field = EI_INIT;
static expert_field ei_sapdiag_invalid_decompresssion = EI_INIT;
static expert_field ei_sapdiag_invalid_decompress_length = EI_INIT;

/* Global decompress preference */
static gboolean global_sapdiag_decompress = TRUE;

/* Global RFC dissection preference */
static gboolean global_sapdiag_rfc_dissection = TRUE;

/* Global SNC dissection preference */
static gboolean global_sapdiag_snc_dissection = TRUE;

/* Global port preference */
static range_t *global_sapdiag_port_range;

/* Global highlight preference */
static gboolean global_sapdiag_highlight_items = TRUE;

/* Protocol handle */
static dissector_handle_t sapdiag_handle;

void proto_reg_handoff_sapdiag(void);

static void
dissect_sapdiag_dp_req_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset){
	proto_item *ri = NULL;
	proto_tree *req_info_tree;

	ri = proto_tree_add_item(tree, hf_sapdiag_dp_req_info, tvb, offset, 4, ENC_BIG_ENDIAN);
	req_info_tree = proto_item_add_subtree(ri, ett_sapdiag);

	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_LOGIN, tvb, offset, 1, ENC_BIG_ENDIAN);		/* 0x08 */
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_LOGOFF, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_SHUTDOWN, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_GRAPHIC_TM, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_ALPHA_TM, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_ERROR_FROM_APPC, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_CANCELMODE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_MSG_WITH_REQ_BUF, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_MSG_WITH_OH, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 0x09 */
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_BUFFER_REFRESH, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_BTC_SCHEDULER, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_APPC_SERVER_DOWN, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_MS_ERROR, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_SET_SYSTEM_USER, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_CANT_HANDLE_REQ, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_AUTO_ABAP, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_APPL_SERV_INFO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 0x0a */
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_ADMIN, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_SPOOL_ALRM, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_HAND_SHAKE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_CANCEL_PRIV, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_RAISE_TIMEOUT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_NEW_MODE, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_SOFT_CANCEL, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_TM_INPUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 0x0b */
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_TM_OUTPUT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_ASYNC_RFC, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_ICM_EVENT, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_AUTO_TH, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_RFC_CANCEL, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(req_info_tree, hf_sapdiag_dp_req_info_DP_MS_ADM, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_sapdiag_dp(tvbuff_t *tvb, proto_tree *tree, guint32 offset){
	proto_item *dp = NULL;
	proto_tree *dp_tree;

	dp = proto_tree_add_item(tree, hf_sapdiag_dp, tvb, offset, 200, ENC_NA);
	dp_tree = proto_item_add_subtree(dp, ett_sapdiag);

	proto_tree_add_item(dp_tree, hf_sapdiag_dp_request_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4; 		/* 0x00 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_retcode, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;			/* 0x04 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_sender_id, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;			/* 0x05 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_action_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset++; 		/* 0x06 */
	dissect_sapdiag_dp_req_info(tvb, dp_tree, offset); offset+=4; 	/* Request info flags */		/* 0x07 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_tid, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;				/* 0x0b */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_uid, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;				/* 0x0f */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_mode, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;				/* 0x11 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_wp_id, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;			/* 0x12 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_wp_ca_blk, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;		/* 0x16 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_appc_ca_blk, tvb, offset, 4, ENC_BIG_ENDIAN); offset+=4;		/* 0x1a */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_len, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset+=4;	/* 0x1e */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_new_stat, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;			/* 0x22 */
	offset+=4; 	/* Unknown 4 bytes */																/* 0x23 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_rq_id, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;			/* 0x27 */
	offset+=40; /* Unknown 40 bytes (0x20 * 40) */													/* 0x29 */
	proto_tree_add_item(dp_tree, hf_sapdiag_dp_terminal, tvb, offset, 15, ENC_ASCII|ENC_NA); offset+=15;		/* 0x51 */
	offset+=10; /* Unknown 10 bytes (0x00 * 10) */													/* 0x60 */
	offset+=20; /* Unknown 20 bytes (0x20 * 20) */													/* 0x6a */
	offset+=4; 	/* Unknown dword (0x00) */															/* 0x7e */
	offset+=4;	/* Unknown dword (0x00) */															/* 0x82 */
	offset+=4;	/* Unknown dword (0xFF * 4) */														/* 0x86 */
	offset+=4;	/* Unknown dword (0x00) */															/* 0x8a */
	offset++;	/* Unknown byte (0x01) */															/* 0x8e */
	offset+=57;	/* Unknown byte (0x00 * 57) */														/* 0x8f */
																									/* 0xc8 */
}

static void
dissect_sapdiag_support_bits(tvbuff_t *tvb, proto_tree *tree, guint32 offset){

	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 0 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 1 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 2 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 3 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 4 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 5 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 6 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 7 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 8 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 9 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 10 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 11 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UPPERCASE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 12 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 13 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 14 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_DIALOG, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 15 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 16 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FKEY_TABLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 17 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 18 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_STOP_TRANS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 19 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FULL_MENU, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 20 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 21 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 22 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DLGH_FLAGS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 23 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_APPL_MNU, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 24 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 25 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 26 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 27 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUIAPI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 28 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOGRAPH, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 29 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOMESSAGES, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 30 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NORABAX, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 31 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOSYSMSG, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 32 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 33 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NORFC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 34 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 35 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_VARS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 36 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_OCX_SUPPORT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 37 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SCROLL_INFOS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 38 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 39 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 40 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 41 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CURR_TCODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 42 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONN_WSIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 43 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 44 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABSTRIP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 45 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 46 (Unknown support bit) */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 47 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 48 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 49 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 50 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 51 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 52 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 53 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 54 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 55 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TYPE_SERVER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 56 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_COMBOBOX, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 57 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 58 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 59 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 60 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 61 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 62 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_USERID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 63 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 64 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_USER_TURNTIME2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 65 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NUM_FIELD, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 66 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WIN16, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 67 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTEXT_MENU, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 68 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 69 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 70 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_LABEL_OWNER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 71 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 72 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PROPERTY_BAG, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 73 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 74 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 75 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PROPFONT_VALID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 76 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 77 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 78 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOTGUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 79 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WAN, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 80 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XML_BLOBS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 81 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_QUEUE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 82 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_COMPRESS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 83 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_JAVA_BEANS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 84 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 85 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 86 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 87 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 88 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 89 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 90 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 91 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XML_PROPERTIES, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 92 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_4, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 93 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_HEX_FIELD, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 94 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_HAS_CACHE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 95 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 96 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_5, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 97 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 98 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ITS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 99 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NO_EASYACCESS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 100 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PROPERTYPUMP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 101 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_COOKIE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 102 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNUSED_6, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 103 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 104 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 105 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 106 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 107 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 108 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CACHED_VSETS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 109 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 110 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AREA2FRONT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 111 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 112 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AUTORESIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 113 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EDIT_VARLEN, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 114 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WORKPLACE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 115 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_PRINTDATA, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 116 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 117 (Unknown support bit) */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SINGLE_SESSION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 118 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 119 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 120 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 121 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 122 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 123 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 124 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WEBGUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 125 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 126 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 127 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 128 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 129 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 130 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SLC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 131 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ACCESSIBILITY, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 132 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ECATT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 133 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 134 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF8, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 135 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 136 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 137 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 138 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 139 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 140 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ENABLE_APPL4, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 141 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 142 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 143 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_BINARY_EVENTID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 144 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_THEME, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 145 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TOP_WINDOW, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 146 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 147 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SPLITTER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 148 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 149 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ACC_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 150 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 151 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 152 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 153 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 154 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FRAME_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 155 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TICKET4GUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 156 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 157 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 158 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 159 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 160 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 161 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CELLINFO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 162 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 163 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 164 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ITS_PLUGIN, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 165 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 166 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 167 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 168 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_RCUI, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 169 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 170 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 171 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 172 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 173 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 174 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 175 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SBA2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 176 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 177 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 178 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 179 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_PACKET, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 180 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 181 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 182 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 183 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 184 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 185 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 186 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 187 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 188 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 189 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 190 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 191 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 192 (Unknown support bit) */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 193 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MAX_WSIZE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 194 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_SAP_PERSONAS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 195 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_IDA_ALV, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 196 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 197 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AMC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 198 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 199 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GROUPBOX, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 200 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 201 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 202 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FIORI_MODE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 203 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 204 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 205 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AGI_ID, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 206 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 207 */
	offset+=1;
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 208 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 209 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 210 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_NWBC, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 211 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_CONTAINER_LIST, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 212 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 213 */
	proto_tree_add_item(tree, hf_SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE, tvb, offset, 1, ENC_BIG_ENDIAN);  /* 214 */

}

static void
dissect_sapdiag_rfc_call(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 item_length){

	tvbuff_t *next_tvb = NULL;
	dissector_handle_t rfc_handle;

	/* Call the RFC internal dissector */
	if (global_sapdiag_rfc_dissection == TRUE){
		rfc_handle = find_dissector("saprfcinternal");
		if (rfc_handle){
			/* Set the column to not writable so the RFC dissector doesn't override the Diag info */
			col_set_writable(pinfo->cinfo, -1, FALSE);
			/* Create a new tvb buffer and call the dissector */
			next_tvb = tvb_new_subset_length(tvb, offset, item_length);
			call_dissector(rfc_handle, next_tvb, pinfo, tree);
		}
	}

}


gboolean
check_length(packet_info *pinfo, proto_tree *tree, guint32 expected, guint32 real, const char *name_string){
	if (expected != real){
		expert_add_info_format(pinfo, tree, &ei_sapdiag_item_length_invalid, "Item %s length is invalid", name_string);
		return (FALSE);
	} else return (TRUE);
}


guint8
add_item_value_uint8(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, const char *text){
	proto_tree_add_none_format(tree, hf, tvb, offset, 1, "%s: %d", text, tvb_get_guint8(tvb, offset));
	proto_item_append_text(item, ", %s=%d", text, tvb_get_guint8(tvb, offset));
	return (tvb_get_guint8(tvb, offset));
}


guint16
add_item_value_uint16(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, const char *text){
	proto_tree_add_none_format(tree, hf, tvb, offset, 2, "%s: %d", text, tvb_get_ntohs(tvb, offset));
	proto_item_append_text(item, ", %s=%d", text, tvb_get_ntohs(tvb, offset));
	return (tvb_get_ntohs(tvb, offset));
}


guint32
add_item_value_uint32(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, const char *text){
	proto_tree_add_none_format(tree, hf, tvb, offset, 4, "%s: %d", text, tvb_get_ntohl(tvb, offset));
	proto_item_append_text(item, ", %s=%d", text, tvb_get_ntohl(tvb, offset));
	return (tvb_get_ntohl(tvb, offset));
}


void
add_item_value_string(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, guint32 length, const char *text, int show_in_tree){
	guint8 *string = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
	proto_tree_add_none_format(tree, hf, tvb, offset, length, "%s: %s", text, string);
	if (show_in_tree) proto_item_append_text(item, ", %s=%s", text, string);
}


guint32
add_item_value_stringz(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, const char *text, int show_in_tree){
	guint32 length = tvb_strsize(tvb, offset);
	guint8 *string = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length - 1, ENC_ASCII);
	proto_tree_add_none_format(tree, hf, tvb, offset, length, "%s: %s", text, string);
	if (show_in_tree) proto_item_append_text(item, ", %s=%s", text, string);
	return (length);
}


void
add_item_value_hexstring(tvbuff_t *tvb, proto_item *item, proto_tree *tree, int hf, guint32 offset, guint32 length, const char *text){
	proto_tree_add_none_format(tree, hf, tvb, offset, length, "%s: %s", text, tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, length));
	proto_item_append_text(item, ", %s=%s", text, tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, length));
}


static void
dissect_sapdiag_dyntatom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 length){
	guint32 final = offset + length;
	guint16 atom_length = 0, atom_item_length = 0;
	guint8 etype = 0, attr = 0;

	proto_item *atom = NULL, *atom_item = NULL, *atom_item_attr = NULL;
	proto_tree *atom_tree = NULL, *atom_item_tree = NULL, *atom_item_attr_tree = NULL;

	while (offset < final){

		etype = tvb_get_guint8(tvb, offset+4);
		if ((etype != 114) && (etype != 120)) {
			/* Add a new atom subtree */
			atom_length = 0;
			atom = proto_tree_add_item(tree, hf_sapdiag_item_dynt_atom, tvb, offset, atom_length, ENC_NA);
			atom_tree = proto_item_add_subtree(atom, ett_sapdiag);
			proto_item_append_text(atom, ", Etype=%s", val_to_str(etype, sapdiag_item_dynt_atom_item_etype_vals, "Unknown")); /* Add the Etype to the Atom tree also */
		}

		/* Check the atom_tree for NULL values. If the atom_tree wasn't created at this point, the atom
		 * starts with an item different to 114 or 120. */
		if (atom_tree == NULL){
			expert_add_info(pinfo, tree, &ei_sapdiag_atom_item_malformed);
			break;
		}

		/* Add the item atom subtree */
		atom_item = proto_tree_add_item(atom_tree, hf_sapdiag_item_dynt_atom_item, tvb, offset, tvb_get_ntohs(tvb, offset), ENC_NA);
		atom_item_tree = proto_item_add_subtree(atom_item, ett_sapdiag);

		/* Get the atom item length */
		atom_item_length = add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Atom Length");

		/* Adjust the length of the atom tree, adding the new item's length and the length field */
		atom_length+= atom_item_length;
		proto_item_set_len(atom_tree, atom_length);

		/* Continue with the dissection */
		offset+=2; atom_item_length-=2;
		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Dlg Flag 1"); offset+=1; atom_item_length-=1;
		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Dlg Flag 2"); offset+=1; atom_item_length-=1;

		proto_tree_add_item(atom_item_tree, hf_sapdiag_item_dynt_atom_item_etype, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_item_append_text(atom_item, ", EType=%d", tvb_get_guint8(tvb, offset));offset+=1; atom_item_length-=1;

		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Area"); offset+=1; atom_item_length-=1;
		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Block"); offset+=1; atom_item_length-=1;
		add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Group"); offset+=1; atom_item_length-=1;
		add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Row"); offset+=2; atom_item_length-=2;
		add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Col"); offset+=2; atom_item_length-=2;

		atom_item_attr = proto_tree_add_item(atom_item_tree, hf_sapdiag_item_dynt_atom_item_attr, tvb, offset, 1, ENC_BIG_ENDIAN);
		atom_item_attr_tree = proto_item_add_subtree(atom_item_attr, ett_sapdiag);

		attr = tvb_get_guint8(tvb, offset);
		proto_item_append_text(atom_item, ", Attr=%d", attr);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROTECTED, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INVISIBLE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INTENSIFY, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_JUSTRIGHT, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_MATCHCODE, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROPFONT, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_YES3D, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(atom_item_attr_tree, hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_COMBOSTYLE, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset+=1; atom_item_length-=1;

		/* If the attribute is set to invisible we're dealing probably with a password field */
		if (attr & SAPDIAG_ATOM_ATTR_DIAG_BSD_INVISIBLE){
			expert_add_info(pinfo, atom_item, &ei_sapdiag_password_field);
		}

		switch (etype){
			case 114:{  /* DIAG_DGOTYP_FNAME */
				add_item_value_string(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 1);
				proto_item_append_text(atom, ", Text=%s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, atom_item_length, ENC_ASCII)); offset+=atom_item_length;
				break;

			} case 115:{ /* DIAG_DGOTYP_PUSHBUTTON_2 */
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "V Length"); offset+=1; atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "V Height"); offset+=1; atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Function Code Offset"); offset+=2; atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text Offset"); offset+=2; atom_item_length-=2;
				offset+=add_item_value_stringz(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text", 1);
				offset+=add_item_value_stringz(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Function Code", 1);
				break;

			} case 116:{ /* DIAG_DGOTYP_TABSTRIP_BUTTON */
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "V Length"); offset+=1; atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "V Height"); offset+=1; atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Page Id"); offset+=1; atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Function Code Offset"); offset+=2; atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text Offset"); offset+=2; atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Id Offset"); offset+=2; atom_item_length-=2;
				offset+=add_item_value_stringz(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text", 1);
				offset+=add_item_value_stringz(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Function Code", 1);
				offset+=add_item_value_stringz(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "ID", 1);
				break;

			} case 118:  /* DIAG_DGOTYP_CHECKBUTTON_1" */
			  case 119:{ /* DIAG_DGOTYP_RADIOBUTTON_1 */
				/* If the preference is set, report the item as partially dissected in the expert info */
				if (global_sapdiag_highlight_items){
					expert_add_info_format(pinfo, atom_item, &ei_sapdiag_atom_item_partial, "The Diag Atom is dissected partially (0x%.2x)", etype);
				}
				break;

			} case 120:{ /* DIAG_DGOTYP_XMLPROP */
				add_item_value_string(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "XMLProp", 1);
				proto_item_append_text(atom, ", XMLProp=%s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, atom_item_length, ENC_ASCII)); offset+=atom_item_length;
				break;

			} case 121:  /* DIAG_DGOTYP_EFIELD_1 */
			  case 122:  /* DIAG_DGOTYP_OFIELD_1 */
			  case 123:{ /* DIAG_DGOTYP_KEYWORD_1_1 */
				/* Found in NW 7.00 and 7.01 versions */
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Flag1"); offset+=1; atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "DLen"); offset+=1; atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "MLen"); offset+=1; atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "MaxNrChars"); offset+=2; atom_item_length-=2;
				add_item_value_string(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 0); offset+=atom_item_length;

				break;

			  } case 127:{ /* DIAG_DGOTYP_FRAME_1 */
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "DRows"); offset+=2; atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "DCols"); offset+=2; atom_item_length-=2;
				add_item_value_string(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 1); offset+=atom_item_length;
				break;

			} case 129:{ /* DIAG_DGOTYP_RADIOBUTTON_3 */
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Button"); offset+=1; atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Visible Label Length"); offset+=2; atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "EventID Off"); offset+=2; atom_item_length-=2;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "EventID Len"); offset+=1; atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text Off"); offset+=2; atom_item_length-=2;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Text Length"); offset+=2; atom_item_length-=2;
				add_item_value_string(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 1); offset+=atom_item_length;
				break;

			} case 130:  /* DIAG_DGOTYP_EFIELD_2 */
			  case 131:  /* DIAG_DGOTYP_OFIELD_2 */
			  case 132:{ /* DIAG_DGOTYP_KEYWORD_2 */
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "Flag1"); offset+=2; atom_item_length-=2;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "DLen"); offset+=1; atom_item_length-=1;
				add_item_value_uint8(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "MLen"); offset+=1; atom_item_length-=1;
				add_item_value_uint16(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, "MaxNrChars"); offset+=2; atom_item_length-=2;
				add_item_value_string(tvb, atom_item, atom_item_tree, hf_sapdiag_item_value, offset, atom_item_length, "Text", 0); offset+=atom_item_length;

				break;
			} default:
				/* If the preference is set, report the item as unknown in the expert info */
				if (global_sapdiag_highlight_items){
					expert_add_info_format(pinfo, atom_item, &ei_sapdiag_atom_item_unknown, "The Diag Atom has a unknown type that is not dissected (%d)", etype);
				}
				offset+=atom_item_length;

				break;
		}
	}

}

static void
dissect_sapdiag_menu(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 length){

	guint32 final = offset + length;

	proto_item *menu = NULL;
	proto_tree *menu_tree = NULL;

	while (offset < final){

		/* Add the menu entry subtree */
		menu = proto_tree_add_item(tree, hf_sapdiag_item_menu_entry, tvb, offset, tvb_get_ntohs(tvb, offset), ENC_NA);
		menu_tree = proto_item_add_subtree(menu, ett_sapdiag);

		add_item_value_uint16(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Length"); offset+=2;

		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Position 1"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Position 2"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Position 3"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Position 4"); offset+=1;

		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Flag"); offset+=1;   /* XXX: Add flag values */
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Virtual Key"); offset+=1;

		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 1"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 2"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 3"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 4"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 5"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Return Code 6"); offset+=1;

		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 1"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 2"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 3"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 4"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 5"); offset+=1;
		add_item_value_uint8(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Function Code 6"); offset+=1;

		offset+=add_item_value_stringz(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Text", 1);
		offset+=add_item_value_stringz(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Accelerator", 1);
		offset+=add_item_value_stringz(tvb, menu, menu_tree, hf_sapdiag_item_value, offset, "Info", 1);
	}

}

static void
dissect_sapdiag_uievent(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, guint32 length){

	proto_item *event_valid_item = NULL;
	proto_tree *event_valid_tree = NULL;
	guint8 event_valid = 0;
	guint16 container_nrs = 0, i = 0;

	event_valid = tvb_get_guint8(tvb, offset);
	event_valid_item = proto_tree_add_item(tree, ht_sapdiag_item_ui_event_valid, tvb, offset, 1, ENC_BIG_ENDIAN);
	event_valid_tree = proto_item_add_subtree(event_valid_item, ett_sapdiag);

	proto_tree_add_item(event_valid_tree, ht_sapdiag_item_ui_event_valid_MENU_POS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(event_valid_tree, ht_sapdiag_item_ui_event_valid_CONTROL_POS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(event_valid_tree, ht_sapdiag_item_ui_event_valid_NAVIGATION_DATA, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(event_valid_tree, ht_sapdiag_item_ui_event_valid_FUNCTIONKEY_DATA, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;length-=1;

	proto_tree_add_item(tree, ht_sapdiag_item_ui_event_event_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_item_append_text(tree, ", Event Type=%s", val_to_str(tvb_get_ntohs(tvb, offset), sapdiag_item_ui_event_event_type_vals, "Unknown")); offset+=2;length-=2;

	proto_tree_add_item(tree, ht_sapdiag_item_ui_event_control_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_item_append_text(tree, ", Control Type=%s", val_to_str(tvb_get_ntohs(tvb, offset), sapdiag_item_ui_event_control_type_vals, "Unknown")); offset+=2;length-=2;

	/* The semantic of the event data changes depending of the event valid flag and are ignored if the
	SAPDIAG_UI_EVENT_VALID_FLAG_NAVIGATION_DATA flag or the SAPDIAG_UI_EVENT_VALID_FLAG_FUNCTIONKEY_DATA
	flags are not set. We dissect them always. */
	if (event_valid & SAPDIAG_UI_EVENT_VALID_FLAG_NAVIGATION_DATA){
		proto_tree_add_item(tree, ht_sapdiag_item_ui_event_navigation_data, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;length-=1;
	} else { /* SAPDIAG_UI_EVENT_VALID_FLAG_FUNCTIONKEY_DATA */
		proto_tree_add_item(tree, ht_sapdiag_item_ui_event_data, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;length-=1;
		proto_tree_add_item(tree, ht_sapdiag_item_ui_event_data, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;length-=1;
		proto_tree_add_item(tree, ht_sapdiag_item_ui_event_data, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;length-=1;
		proto_tree_add_item(tree, ht_sapdiag_item_ui_event_data, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;length-=1;
	}

	/* These items are ignored if the flag SAPDIAG_UI_EVENT_VALID_FLAG_CONTROL_POS is not set. We dissect them always. */
	proto_tree_add_item(tree, ht_sapdiag_item_ui_event_control_row, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;length-=2;
	proto_tree_add_item(tree, ht_sapdiag_item_ui_event_control_col, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;length-=2;

	i = container_nrs = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, ht_sapdiag_item_ui_event_container_nrs, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;length-=2;

	while (i>0 && length>0){
		proto_tree_add_item(tree, ht_sapdiag_item_ui_event_container, tvb, offset, 1, ENC_BIG_ENDIAN); offset+=1;length-=1; i--;
	}

	if (i>0)
		expert_add_info_format(pinfo, tree, &ei_sapdiag_dynt_focus_more_cont_ids, "Number of Container IDs (%d) is invalid", container_nrs);

}

static void
dissect_sapdiag_item(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *item_value_tree, proto_tree *parent_tree, guint32 offset, guint8 item_type, guint8 item_id, guint8 item_sid, guint32 item_length){

	/* SES item */
	if (item_type==0x01){
		guint8 event_array = 0;
		check_length(pinfo, item_value_tree, 16, item_length, "SES");

		event_array = tvb_get_guint8(tvb, offset);
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event Array");offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 1"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 2"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 3"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 4"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Event ID 5"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Screen Flag"); offset+=1; /* XXX: Add flag values */
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Modal No"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "X Pos"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Y Pos"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "IMode"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Flag 1"); offset+=1; /* XXX: Add flag values */
		offset+=2;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Dim Row"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Dim Col"); offset+=1;

		/* TODO: Incomplete dissection of this item */
		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The SES item is dissected partially (event array = 0x%.2x)", event_array);
		}

	} else if (item_type==0x0a) { /* SFE */
		check_length(pinfo, item_value_tree, 3, item_length, "SFE");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control format"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control color"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control extended"); offset+=1;

	} else if (item_type==0x0b) { /* SBA */
		check_length(pinfo, item_value_tree, 2, item_length, "SBA");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control y-position"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Control x-position"); offset+=1;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x26){		/* Dialog Step Number */
		check_length(pinfo, item_value_tree, 4, item_length, "Dialog Step Number");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Dialog Step Number"); offset+=4;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x02){		/* Connect */
		check_length(pinfo, item_value_tree, 12, item_length, "Connect");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Protocol Version"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Code Page"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "WS Type"); offset+=4;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x04){		/* Font Metric */
		check_length(pinfo, item_value_tree, 8, item_length, "Font Metric");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Variable font size (y)"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Variable font size (x)"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Fixed font size (y)"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Fixed font size (x)"); offset+=2;

	} else if ((item_type==0x10 && item_id==0x04 && item_sid==0x0b) ||		/* Support Data */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x11)){
		check_length(pinfo, item_value_tree, 32, item_length, "Support Data");
		dissect_sapdiag_support_bits(tvb, item_value_tree, offset); offset+=32;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x0d){		/* Window Size */
		check_length(pinfo, item_value_tree, 16, item_length, "Window Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Width"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Width"); offset+=4;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x0f){		/* Turn Time 2 (Response time) */
		check_length(pinfo, item_value_tree, 4, item_length, "Response time");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Response time"); offset+=4;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x16){		/* Scrollbar Width */
		check_length(pinfo, item_value_tree, 2, item_length, "Scrollbar Width");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Toollbar Width"); offset+=2;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x17){		/* Scrollbar Height */
		check_length(pinfo, item_value_tree, 2, item_length, "Scrollbar Height");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Scrollbar Height"); offset+=2;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x19){		/* Gui State */
		check_length(pinfo, item_value_tree, 2, item_length, "Gui State");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Flag 1"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Flag 2"); offset+=1;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x1d){		/* GUI patch level */

		/* GUI Patch level could be a string in old versions, or a single byte integer in newer ones */
		if (item_length == 2){
			add_item_value_string(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, 2, "GUI patch level", 1); offset+=2;
		} else {
			check_length(pinfo, item_value_tree, 1, item_length, "GUI patch level");
			add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "GUI patch level"); offset+=1;
		}

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x24){		/* Display Size */
		check_length(pinfo, item_value_tree, 8, item_length, "Display Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Height"); offset+=4;

	} else if (item_type==0x10 && item_id==0x04 && item_sid==0x25){		/* GUI Type */
		check_length(pinfo, item_value_tree, 2, item_length, "GUI Type");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "GUI Type"); offset+=2;

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x01){		/* Mode Number */
		check_length(pinfo, item_value_tree, 2, item_length, "Mode Number");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Mode Number"); offset+=2;

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x06){		/* Diag version */
		check_length(pinfo, item_value_tree, 2, item_length, "Diag version");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Diag version"); offset+=2;

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x0a){		/* Internal Mode Number */
		check_length(pinfo, item_value_tree, 2, item_length, "Internal Mode Number");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Internal Mode Number"); offset+=2;

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x13){		/* GUI_FKEY */
		guint32 length = offset+item_length;
		offset++;  /* TODO: Skip one byte here */
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Virtual key number", 1);
		while ((offset < length) && tvb_offset_exists(tvb, offset)){
			offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "String number", 1);
		}
		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The Diag Item is dissected partially (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x14){		/* GUI_FKEYT */
		offset++;  /* TODO: Skip one byte here */
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Virtual key number"); offset+=1;
		offset++;  /* TODO: Skip one byte here */
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Virtual key text", 1);
		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The Diag Item is dissected partially (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x16){		/* RFC Diag Block Size */
		check_length(pinfo, item_value_tree, 4, item_length, "RFC Diag Block Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "RFC Diag Block Size"); offset+=4;

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x18){		/* Info flags */
		check_length(pinfo, item_value_tree, 2, item_length, "Info flags");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Info flags"); offset+=2;
		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The Diag Item is dissected partially (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x19){		/* User ID */
		check_length(pinfo, item_value_tree, 2, item_length, "User ID");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "User ID"); offset+=2;

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x1f){		/* IMode uuids 2 */
		guint8 uuids = tvb_get_guint8(tvb, offset);
		if (!check_length(pinfo, item_value_tree, 1 + 17 * uuids, item_length, "IMode uuids") ) return;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Number of uuids"); offset+=1;
		while ((uuids > 0) && (tvb_offset_exists(tvb, offset + 16 + 1))){
			add_item_value_hexstring(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, 16, "UUID"); offset+=16;
			add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Active context"); offset+=1;
			uuids--;
		}
	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x22){		/* Auto logout time */
		check_length(pinfo, item_value_tree, 4, item_length, "Auto logout time");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Auto logout time"); offset+=4;

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x23){		/* Codepage Diag GUI */
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage number (numeric representation)"); offset+=4;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Minimum number of bytes per character"); offset+=1;
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage number (string representation)", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage description", 1);

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x27){		/* Codepage App Server */
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage number (numeric representation)"); offset+=4;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Minimum number of bytes per character"); offset+=1;
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage number (string representation)", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Codepage description", 1);

	} else if (item_type==0x10 && item_id==0x06 && item_sid==0x29){		/* Kernel Version */
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Database version", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Kernel version", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Kernel patch level", 1);

	} else if (item_type==0x10 && item_id==0x09 && item_sid==0x0b){		/* Dynt Focus */
		guint32 length = offset + item_length;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Num of Area ID"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Row"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Col"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Row Offset"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Col Offset"); offset+=2;
		/* Container IDs up to 30 */
		if (length-offset > 30){
			expert_add_info_format(pinfo, item, &ei_sapdiag_dynt_focus_more_cont_ids, "The Dynt Focus contains more than 30 Container IDs (%d)", offset);
		}
		/* Dissect all the remaining container IDs */
		while((offset < length) && tvb_offset_exists(tvb, offset)){
			add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Focus Container ID"); offset+=1;
		}

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x01){		/* Container Reset */
		check_length(pinfo, item_value_tree, 9, item_length, "Container Reset");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height"); offset+=2;

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x04){		/* Container Loop */
		check_length(pinfo, item_value_tree, 9, item_length, "Container Loop");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height"); offset+=2;

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x05){		/* Container Table */
		check_length(pinfo, item_value_tree, 9, item_length, "Container Table");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height"); offset+=2;

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x06){		/* Container Name */
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Subscreen name", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container name", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Subdynpro name", 1);

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x08){		/* Container TabStrip */
		check_length(pinfo, item_value_tree, 9, item_length, "Container TabStrip");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height"); offset+=2;

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x09){		/* Container TabStrip Page */
		check_length(pinfo, item_value_tree, 9, item_length, "Container TabStrip Page");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height"); offset+=2;

	} else if (item_type==0x10 && item_id==0x0a && item_sid==0x0a){		/* Container Control */
		check_length(pinfo, item_value_tree, 9, item_length, "Container Control");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Id"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Row"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Col"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Width"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Container Height"); offset+=2;

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x03){		/* Message type */
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "T", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "T", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "T", 1);
		offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "T", 1);

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x02){		/* Scroll Infos */
		check_length(pinfo, item_value_tree, 24, item_length, "Scroll Infos");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Total Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Total Width"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Data Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Data Width"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Height Offset"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Width Offset"); offset+=4;

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x06){		/* Scroll Infos 2 */
		check_length(pinfo, item_value_tree, 33, item_length, "Scroll Infos 2");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Total Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Total Width"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Data Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Data Width"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Height Offset"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Width Offset"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Visible Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Visible Width"); offset+=4;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Scroll Flag"); offset+=1;

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x07){		/* Area Size */
		check_length(pinfo, item_value_tree, 16, item_length, "Area Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Width"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Width"); offset+=4;

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x08){		/* Pixel Size */
		check_length(pinfo, item_value_tree, 16, item_length, "Pixel Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Width"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Area Width"); offset+=4;

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x0c){		/* Container Loop */
		check_length(pinfo, item_value_tree, 2, item_length, "Container Loop");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Lines Per Loop Row"); offset+=2;

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x0d){		/* List focus */
		check_length(pinfo, item_value_tree, 5, item_length, "List focus");
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "List focus version"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "List focus Row"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "List focus Column"); offset+=2;

	} else if (item_type==0x10 && item_id==0x0c && item_sid==0x0e){		/* Main Area Pixel Size */
		check_length(pinfo, item_value_tree, 16, item_length, "Main Area Pixel Size");
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Height"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Window Width"); offset+=4;

	/* Dynn items */
	} else if ((item_type==0x09) ||						/* CHL */
		   (item_type==0x10 && item_id==0x05 && item_sid==0x01)){	/* Dynn Chln */
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "scrflg"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "chlflag"); offset+=2;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "current row"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "current column"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "V Slider Size"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "dimlistrow"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "dimlistcol"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "H Slider Size"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "dimrow"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "dimcol"); offset+=1;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "maxlistrow"); offset+=2;
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "listrowoffset"); offset+=2;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "maxlistcol"); offset+=1;
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "listcoloffset"); offset+=1;

		/* If the preference is set, report the item as partially dissected in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_partial, "The Diag Item is dissected partially (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}

	/* Control Properties */
	} else if (item_type==0x10 && item_id==0x0e && item_sid==0x01){ /* Control Properties */
		guint32 length = offset + item_length;

		while((offset < length) && (tvb_offset_exists(tvb, offset + 3))){  /* Check against at least three bytes (2 for ID, 1 for null-terminated value) */
			proto_tree_add_item(item_value_tree, hf_sapdiag_item_control_properties_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_item_append_text(item, ", Control Property ID=%d", tvb_get_ntohs(tvb, offset)); offset+=2;
			offset+=add_item_value_stringz(tvb, item, item_value_tree, hf_sapdiag_item_control_properties_value, offset, "Control Property Value", 1);
		}

	/* UI event source */
	} else if (item_type==0x10 && item_id==0x0f && item_sid==0x01){ /* UI Event Source */
		dissect_sapdiag_uievent(tvb, pinfo, item_value_tree, offset, item_length); offset+=item_length;

	/* GUI Packet state */
	} else if (item_type==0x10 && item_id==0x14 && item_sid==0x01){ /* GUI Packet state */
		add_item_value_uint8(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Flags"); offset+=1; /* TODO: Add flag values */
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Bytes Total"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Bytes Send"); offset+=4;
		add_item_value_uint32(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Bytes Received"); offset+=4;

	/* Dynt items */
	} else if ((item_type==0x12 && item_id==0x09 && item_sid==0x02) ||	/* Dynt Atom */
		   (item_type==0x10 && item_id==0x09 && item_sid==0x02)) {
		dissect_sapdiag_dyntatom(tvb, pinfo, item_value_tree, offset, item_length); offset+=item_length;

	/* String items */
	} else if ((item_type==0x10 && item_id==0x04 && item_sid==0x09) || 		/* Gui Version */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x1a) || 		/* Decimal character */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x1b) || 		/* Language */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x1c) || 		/* Username */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x1f) || 		/* Gui OS Version */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x20) || 		/* Browser Version */
		   (item_type==0x10 && item_id==0x04 && item_sid==0x21) || 		/* Office Version */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x02) || 		/* Database name */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x03) ||	 	/* CPU name */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x07) || 		/* Transaction code */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0b) || 		/* Message */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0c) || 		/* Client */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0d) || 		/* Dynpro name */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0e) || 		/* Dynpro number */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x0f) || 		/* Cuaname */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x10) || 		/* Cuastatus */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x21) || 		/* Context ID */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x24) || 		/* Codepage application server */
		   (item_type==0x10 && item_id==0x06 && item_sid==0x25) || 		/* GUI Theme */
		   (item_type==0x10 && item_id==0x09 && item_sid==0x12) || 		/* Control Focus */
		   (item_type==0x10 && item_id==0x0c && item_sid==0x04) || 		/* OK Code */
		   (item_type==0x10 && item_id==0x0c && item_sid==0x09) || 		/* Session title */
		   (item_type==0x10 && item_id==0x0c && item_sid==0x0a) || 		/* Session icon */
		   (item_type==0x10 && item_id==0x0c && item_sid==0x0b)) 		/* List Cell text */
	{
		add_item_value_string(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, item_length, "Value", 1); offset+=item_length;

	/* RFC Embedded calls */
	} else if (item_type==0x10 && item_id==0x08){ /* RFC_TR */
		dissect_sapdiag_rfc_call(tvb, pinfo, parent_tree, offset, item_length);

	/* String items (long text) */
	} else if (item_type==0x11){										/* Data Stream */
		add_item_value_string(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, item_length, "Value", 0); offset+=item_length;

	/* Tab Strip Controls */
	} else if ((item_type==0x12 && item_id==0x09 && item_sid==0x10)) {
		dissect_sapdiag_dyntatom(tvb, pinfo, item_value_tree, offset, item_length); offset+=item_length;

	/* Menu Entries items */
	} else if ((item_type==0x12 && item_id==0x0b)) {
		dissect_sapdiag_menu(tvb, item_value_tree, offset, item_length); offset+=item_length;

	} else if (item_type==0x13) { /* SLC */
		check_length(pinfo, item_value_tree, 2, item_length, "SLC");
		add_item_value_uint16(tvb, item, item_value_tree, hf_sapdiag_item_value, offset, "Field length in characters"); offset+=2;

	/* Another unknown item */
	} else {
		/* If the preference is set, report the item as unknown in the expert info */
		if (global_sapdiag_highlight_items){
			expert_add_info_format(pinfo, item, &ei_sapdiag_item_unknown, "The Diag Item has a unknown type that is not dissected (0x%.2x, 0x%.2x, 0x%.2x)", item_type, item_id, item_sid);
		}
	}

}

const char *
get_appl_string(guint8 item_id, guint8 item_sid){
	const char *item_name_string = NULL;

	switch (item_id){
		case 0x01:{   /* SCRIPT */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_script_vals, "Unknown"); break;
		} case 0x02:{ /* GRAPH */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_graph_vals, "Unknown"); break;
		} case 0x03:{ /* IXOS */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_ixos_vals, "Unknown"); break;
		} case 0x04:{ /* ST_USER */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_st_user_vals, "Unknown"); break;
		} case 0x05:{ /* DYNN */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_dynn_vals, "Unknown"); break;
		} case 0x06:{ /* ST_R3INFO */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_st_r3info_vals, "Unknown"); break;
		} case 0x07:{ /* POPU */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_popu_vals, "Unknown"); break;
		} case 0x08:{ /* RFC_TR */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_rfc_tr_vals, "Unknown"); break;
		} case 0x09:{ /* DYNT */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_dynt_vals, "Unknown"); break;
		} case 0x0a:{ /* CONTAINER */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_container_vals, "Unknown"); break;
		} case 0x0b:{ /* MNUENTRY */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_mnuentry_vals, "Unknown"); break;
		} case 0x0c:{ /* VARINFO */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_varinfo_vals, "Unknown"); break;
		} case 0x0e:{ /* CONTROL */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_control_vals, "Unknown"); break;
		} case 0x0f:{ /* UI_EVENT */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_ui_event_vals, "Unknown"); break;
		} case 0x12:{ /* ACC_LIST */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_acc_list_vals, "Unknown"); break;
		} case 0x13:{ /* RCUI */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_rcui_vals, "Unknown"); break;
		} case 0x14:{ /* GUI_PACKET */
			item_name_string = val_to_str(item_sid, sapdiag_item_appl_gui_packet_vals, "Unknown"); break;
		}
	}
	return (item_name_string);
}

static void
dissect_sapdiag_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *parent_tree, guint32 offset){
	gint item_value_remaining_length;
	guint8 item_type, item_long, item_id, item_sid;
	guint32 item_length, item_value_length;
	const char *item_name_string = NULL;

	proto_item *item = NULL, *il = NULL, *item_value = NULL;
	proto_tree *item_tree, *item_value_tree;

	while (tvb_offset_exists(tvb, offset)){
		item_id = item_sid = item_length = item_value_length = item_long = 0;

		/* Add the item subtree. We start with a item's length of 1, as we don't have yet the real size of the item */
		item = proto_tree_add_item(tree, hf_sapdiag_item, tvb, offset, 1, ENC_NA);
		item_tree = proto_item_add_subtree(item, ett_sapdiag);

		/* Get the item type */
		item_type = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(item_tree, hf_sapdiag_item_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset++; item_length++;
		proto_item_append_text(item, ": %s", val_to_str(item_type, sapdiag_item_type_vals, "Unknown"));

		switch (item_type){
			case 0x01:{ /* SES */
				item_value_length = 16;
				break;
			}
			case 0x02:{ /* ICO */
				item_value_length = 20;
				break;
			}
			case 0x03:{ /* TIT */
				item_value_length = 3;
				break;
			}
			case 0x07:{ /* DiagMessage (old format) */
				item_value_length = 76;
				break;
			}
			case 0x08:{ /* OCK */
				/* If the preference is set, report the item as partially dissected in the expert info */
				if (global_sapdiag_highlight_items){
					expert_add_info_format(pinfo, item, &ei_sapdiag_item_unknown_length, "Diag Type of unknown length (0x%.2x)", item_type);
				}
				break;
			}
			case 0x09:{ /* CHL */
				item_value_length = 22;
				break;
			}
			case 0x0a:{ /* SFE */
				item_value_length = 3;
				break;
			}
			case 0x0b:{ /* SBA */
				item_value_length = 2;
				break;
			}
			case 0x0C:{ /* EOM End of message */
				break;
			}
			case 0x11:{ /* Data Stream */
				item_long = 4;
				break;
			}
			case 0x13:{ /* SLC */
				item_value_length = 2;
				break;
			}
			case 0x15:{ /* SBA2 XXX: Find the actual length */
				item_value_length = 36;
				break;
			}
			case 0x10:  /* APPL */
			case 0x12:{ /* APPL4 */
				/* Get the APPL(4) ID */
				item_id = tvb_get_guint8(tvb, offset);
				proto_item_append_text(item, ", %s", val_to_str(item_id, sapdiag_item_id_vals, "Unknown"));
				proto_tree_add_item(item_tree, hf_sapdiag_item_id, tvb, offset, 1, ENC_BIG_ENDIAN); offset++; item_length++;

				/* Get the APPL item sid value and set the respective name string according to them XXX: Change this for a multi array */
				item_sid = tvb_get_guint8(tvb, offset);
				item_name_string = get_appl_string(item_id, item_sid);

				proto_item_append_text(item, ", %s", item_name_string);
				proto_tree_add_uint_format_value(item_tree, hf_sapdiag_item_sid, tvb, offset, 1, item_sid, "%s (0x%.2x)", item_name_string, item_sid); offset++; item_length++;

				if (item_type==0x10)
					item_long = 2;
				else if (item_type==0x12)
					item_long = 4;

				break;
			}
		}

		/* Get the item length (word o dword) */
		if (item_long == 2){
			item_value_length = tvb_get_ntohs(tvb, offset);
			il = proto_tree_add_item(item_tree, hf_sapdiag_item_length, tvb, offset, 2, ENC_BIG_ENDIAN); offset += 2; item_length += 2;
		} else if (item_long == 4){
			item_value_length = tvb_get_ntohl(tvb, offset);
			il = proto_tree_add_item(item_tree, hf_sapdiag_item_length, tvb, offset, 4, ENC_BIG_ENDIAN); offset += 4; item_length += 4;
		}

		/* Add the item length */
		proto_item_append_text(item, ", Len=%d", item_value_length);

		/* Now we have the real length of the item, set the proper size */
		item_length += item_value_length;
		proto_item_set_len(item, item_length);

		/* Add the item value */
		if (item_value_length > 0){
			/* Check if the item length is valid */
			item_value_remaining_length = tvb_reported_length_remaining(tvb, offset);
			if (item_value_remaining_length < 0){
				expert_add_info(pinfo, il, &ei_sapdiag_item_offset_invalid);
				return;
			}
			if ((guint32)item_value_remaining_length < item_value_length){
				expert_add_info(pinfo, il, &ei_sapdiag_item_length_invalid);
				item_value_length = (guint32)item_value_remaining_length;
			}
			item_value = proto_tree_add_item(item_tree, hf_sapdiag_item_value, tvb, offset, item_value_length, ENC_NA);
			item_value_tree = proto_item_add_subtree(item_value, ett_sapdiag);
			dissect_sapdiag_item(tvb, pinfo, item, item_value_tree, parent_tree, offset, item_type, item_id, item_sid, item_value_length);
			offset+= item_value_length;
		}
	}
}

static int
check_sapdiag_dp(tvbuff_t *tvb, guint32 offset)
{
	/* Since there's no SAP Diag mode 0xff, if the first byte is a 0xFF the
	 * packet probably holds an initialization DP Header */
	if ((tvb_reported_length_remaining(tvb, offset) >= 200 + 8) && tvb_get_guint8(tvb, offset) == 0xFF){
		return (TRUE);
	}
	return (FALSE);
}

static int
check_sapdiag_compression(tvbuff_t *tvb, guint32 offset)
{
	/* We check for the length, the algorithm value and the presence of magic bytes */
	if ((tvb_reported_length_remaining(tvb, offset) >= 8) &&
		((tvb_get_guint8(tvb, offset+4) == 0x11) || (tvb_get_guint8(tvb, offset+4) == 0x12)) &&
		(tvb_get_guint16(tvb, offset+5, ENC_LITTLE_ENDIAN) == 0x9d1f)){
		return (TRUE);
	}
	return (FALSE);
}

static void
dissect_sapdiag_compressed_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *sapdiag, guint32 offset)
{
	int rt = 0;
	tvbuff_t *next_tvb;
	guint8 *decompressed_buffer = NULL;
	guint32 reported_length = 0, uncompress_length = 0, payload_offset = 0;
	proto_item *compression_header = NULL, *rl = NULL, *payload = NULL;
	proto_tree *compression_header_tree = NULL, *payload_tree = NULL;

	/* Add the compression header subtree */
	compression_header = proto_tree_add_item(tree, hf_sapdiag_compress_header, tvb, offset, 8, ENC_NA);
	compression_header_tree = proto_item_add_subtree(compression_header, ett_sapdiag);

	payload_offset = offset;

	/* Add the uncompressed length */
	reported_length = tvb_get_letohl(tvb, offset);
	rl = proto_tree_add_uint(compression_header_tree, hf_sapdiag_uncomplength, tvb, offset, 4, reported_length); offset+=4;
	proto_item_append_text(sapdiag, ", Uncompressed Len: %u", reported_length);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Uncompressed Length=%u ", reported_length);

	/* Add the algorithm */
	proto_tree_add_item(compression_header_tree, hf_sapdiag_algorithm, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	/* Add the magic bytes */
	proto_tree_add_item(compression_header_tree, hf_sapdiag_magic, tvb, offset, 2, ENC_BIG_ENDIAN); offset+=2;
	/* Add the max bits */
	proto_tree_add_item(compression_header_tree, hf_sapdiag_special, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	if (global_sapdiag_decompress == TRUE){

		/* Allocate the buffer only in the scope of current packet, using the reported length */
		decompressed_buffer = (guint8 *)wmem_alloc0(wmem_packet_scope(), reported_length);
		if (!decompressed_buffer){
			return;
		}

		uncompress_length = reported_length;

		/* Decompress the payload */
		rt = decompress_packet(tvb_get_ptr(tvb, payload_offset, -1),
				tvb_reported_length_remaining(tvb, payload_offset),
				decompressed_buffer,
				&uncompress_length);

		/* Check the return code and add a expert info warning if an error occurred. The dissector continues trying to add
		adding the payload, however the returned size should be 0.  */
		if (rt < 0){
			expert_add_info_format(pinfo, compression_header, &ei_sapdiag_invalid_decompresssion, "Decompression of payload failed with return code %d (%s)", rt, decompress_error_string(rt));
		}

		/* Check the length returned for the compression routine. If differs with the reported, use the actual one and add
		an expert info warning. */
		if (uncompress_length != reported_length){
			expert_add_info_format(pinfo, rl, &ei_sapdiag_invalid_decompress_length, "The uncompressed payload length (%d) differs with the reported length (%d)", uncompress_length, reported_length);
		}

		/* Add the return code to the tree */
		proto_tree_add_int_format_value(compression_header_tree, hf_sapdiag_decompress_return_code, tvb, payload_offset, 8, rt, "%d (%s)", rt, decompress_error_string(rt));

		if (uncompress_length != 0){
			/* Now re-setup the tvb buffer to have the new data */
			next_tvb = tvb_new_real_data(decompressed_buffer, uncompress_length, uncompress_length);
			tvb_set_child_real_data_tvbuff(tvb, next_tvb);
			add_new_data_source(pinfo, next_tvb, "Uncompressed Data");

			/* Add the payload subtree using the new tvb*/
			payload = proto_tree_add_item(tree, hf_sapdiag_payload, next_tvb, 0, -1, ENC_NA);
			payload_tree = proto_item_add_subtree(payload, ett_sapdiag);

			/* Dissect the new uncompressed payload */
			dissect_sapdiag_payload(next_tvb, pinfo, payload_tree, tree, 0);
		} else {

		}
	} else {
		/* Add the payload subtree */
		payload = proto_tree_add_item(tree, hf_sapdiag_payload, tvb, offset, -1, ENC_NA);
		payload_tree = proto_item_add_subtree(payload, ett_sapdiag);
	}
}


static void
dissect_sapdiag_snc_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *sapdiag_tree, proto_tree *tree, guint32 offset){

	tvbuff_t *next_tvb = NULL;
	proto_item *payload = NULL;
	proto_tree *payload_tree = NULL;

	/* Call the SNC dissector */
	if (global_sapdiag_snc_dissection == TRUE){
		next_tvb = dissect_sapsnc_frame(tvb, pinfo, tree, offset);

		/* If the SNC dissection returned a new tvb, we've a payload to dissect */
		if (next_tvb != NULL) {

		/* Add a new data source for the unwrapped data. From now on, the offset is relative
		to the new tvb so its zero. */
			add_new_data_source(pinfo, next_tvb, "SNC unwrapped Data");

			/* Add the payload subtree using the new tvb*/
			payload = proto_tree_add_item(sapdiag_tree, hf_sapdiag_payload, next_tvb, 0, -1, FALSE);
			payload_tree = proto_item_add_subtree(payload, ett_sapdiag);

			if (check_sapdiag_compression(next_tvb, 0)) {
				dissect_sapdiag_compressed_payload(next_tvb, pinfo, payload_tree, payload, 0);
			} else {
				dissect_sapdiag_payload(next_tvb, pinfo, payload_tree, payload, 0);
			}
		}
	}
}

static int
dissect_sapdiag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint8 compress = 0, error_no = 0;
	guint32 offset = 0;
	proto_item *sapdiag = NULL, *header = NULL, *com_flag = NULL, *payload = NULL;
	proto_tree *sapdiag_tree = NULL, *header_tree = NULL, *com_flag_tree = NULL, *payload_tree = NULL;

	/* Add the protocol to the column */
	col_add_str(pinfo->cinfo, COL_PROTOCOL, "SAPDIAG");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	/* Add the main SAPDiag subtree */
	sapdiag = proto_tree_add_item(tree, proto_sapdiag, tvb, 0, -1, ENC_NA);
	sapdiag_tree = proto_item_add_subtree(sapdiag, ett_sapdiag);

	/* Check if the packet holds a DP Header */
	if (check_sapdiag_dp(tvb, offset)){
		dissect_sapdiag_dp(tvb, sapdiag_tree, offset); offset+= 200;
	}

	/* Check for fixed error messages */
	if (tvb_strneql(tvb, 0, "**DPTMMSG**\x00", 12) == 0){
		proto_tree_add_item(sapdiag_tree, hf_sapdiag_payload, tvb, offset, -1, ENC_NA);
		return offset;
	} else if (tvb_strneql(tvb, 0, "**DPTMOPC**\x00", 12) == 0){
		proto_tree_add_item(sapdiag_tree, hf_sapdiag_payload, tvb, offset, -1, ENC_NA);
		return offset;
	}

	/* Add the header subtree */
	header = proto_tree_add_item(sapdiag_tree, hf_sapdiag_header, tvb, offset, 8, ENC_NA);
	header_tree = proto_item_add_subtree(header, ett_sapdiag);

	/* Add the fields */
	proto_tree_add_item(header_tree, hf_sapdiag_mode, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	com_flag = proto_tree_add_item(header_tree, hf_sapdiag_com_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	com_flag_tree = proto_item_add_subtree(com_flag, ett_sapdiag);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_EOS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_EOC, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_NOP, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_EOP, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_INI, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_CAS, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_NNM, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(com_flag_tree, hf_sapdiag_com_flag_TERM_GRA, tvb, offset, 1, ENC_BIG_ENDIAN);offset++;

	proto_tree_add_item(header_tree, hf_sapdiag_mode_stat, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	error_no = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(header_tree, hf_sapdiag_err_no, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(header_tree, hf_sapdiag_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(header_tree, hf_sapdiag_msg_info, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(header_tree, hf_sapdiag_msg_rc, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	compress = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(header_tree, hf_sapdiag_compress, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;

	/* Check for error messages */
	if ((error_no != 0x00) && (tvb_reported_length_remaining(tvb, offset) > 0)){
		gchar *error_message = NULL;
		guint32 error_message_length = 0;

		error_message_length = (guint32)tvb_reported_length_remaining(tvb, offset) - 1;
		error_message = (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, error_message_length, ENC_LITTLE_ENDIAN|ENC_UTF_16);
		proto_tree_add_string(sapdiag_tree, hf_sapdiag_error_message, tvb, offset, error_message_length, error_message);

	/* If the message is compressed */
	} else if ((compress == 0x01) && (tvb_reported_length_remaining(tvb, offset) >= 8)){

		/* Dissect the compressed payload */
		dissect_sapdiag_compressed_payload(tvb, pinfo, sapdiag_tree, sapdiag, offset);

	/* Message wrapped with SNC */
	} else if (((compress == 0x02) || (compress == 0x03)) && (tvb_reported_length_remaining(tvb, offset) > 0)){

		/* Call the SNC dissector */
		dissect_sapdiag_snc_frame(tvb, pinfo, sapdiag_tree, tree, offset);

	/* Uncompressed payload */
	} else {
		/* Check the payload length */
		if (tvb_reported_length_remaining(tvb, offset) > 0){
			/* Add the payload subtree */
			payload = proto_tree_add_item(sapdiag_tree, hf_sapdiag_payload, tvb, offset, -1, ENC_NA);
			payload_tree = proto_item_add_subtree(payload, ett_sapdiag);

			/* Dissect the payload */
			dissect_sapdiag_payload(tvb, pinfo, payload_tree, tree, offset);
		}
	}

	return offset;
}

void
proto_register_sapdiag(void)
{
	static hf_register_info hf[] = {
		{ &hf_sapdiag_dp,
			{ "DP Header", "sapdiag.dp", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Diag DP Header", HFILL }},
		{ &hf_sapdiag_header,
			{ "Header", "sapdiag.header", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Diag Header", HFILL }},
		{ &hf_sapdiag_payload,
			{ "Message", "sapdiag.message", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Diag Message", HFILL }},
		{ &hf_sapdiag_mode,
			{ "Mode", "sapdiag.header.mode", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Diag Mode", HFILL }},
		{ &hf_sapdiag_com_flag,
			{ "Com Flag", "sapdiag.header.comflag", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP Diag Com Flag", HFILL }},
		{ &hf_sapdiag_com_flag_TERM_EOS,
			{ "Com Flag TERM_EOS", "sapdiag.header.comflag.TERM_EOS", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_EOS, "SAP Diag Com Flag TERM_EOS", HFILL }},
		{ &hf_sapdiag_com_flag_TERM_EOC,
			{ "Com Flag TERM_EOC", "sapdiag.header.comflag.TERM_EOC", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_EOC, "SAP Diag Com Flag TERM_EOC", HFILL }},
		{ &hf_sapdiag_com_flag_TERM_NOP,
			{ "Com Flag TERM_NOP", "sapdiag.header.comflag.TERM_NOP", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_NOP, "SAP Diag Com Flag TERM_NOP", HFILL }},
		{ &hf_sapdiag_com_flag_TERM_EOP,
			{ "Com Flag TERM_EOP", "sapdiag.header.comflag.TERM_EOP", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_EOP, "SAP Diag Com Flag TERM_EOP", HFILL }},
		{ &hf_sapdiag_com_flag_TERM_INI,
			{ "Com Flag TERM_INI", "sapdiag.header.comflag.TERM_INI", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_INI, "SAP Diag Com Flag TERM_INI", HFILL }},
		{ &hf_sapdiag_com_flag_TERM_CAS,
			{ "Com Flag TERM_CAS", "sapdiag.header.comflag.TERM_CAS", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_CAS, "SAP Diag Com Flag TERM_CAS", HFILL }},
		{ &hf_sapdiag_com_flag_TERM_NNM,
			{ "Com Flag TERM_NNM", "sapdiag.header.comflag.TERM_NNM", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_NNM, "SAP Diag Com Flag TERM_NNM", HFILL }},
		{ &hf_sapdiag_com_flag_TERM_GRA,
			{ "Com Flag TERM_GRA", "sapdiag.header.comflag.TERM_GRA", FT_BOOLEAN, 8, NULL, SAPDIAG_COM_FLAG_TERM_GRA, "SAP Diag Com Flag TERM_GRA", HFILL }},

		{ &hf_sapdiag_mode_stat,
			{ "Mode Stat", "sapdiag.header.modestat", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Diag Mode Stat", HFILL }},
		{ &hf_sapdiag_err_no,
			{ "Error Number", "sapdiag.header.errorno", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Diag Error Number", HFILL }},
		{ &hf_sapdiag_msg_type,
			{ "Message Type", "sapdiag.header.msgtype", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Diag Message Type", HFILL }},
		{ &hf_sapdiag_msg_info,
			{ "Message Info", "sapdiag.header.msginfo", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Diag Message Info", HFILL }},
		{ &hf_sapdiag_msg_rc,
			{ "Message Rc", "sapdiag.header.msgrc", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP Diag Message RC", HFILL }},
		{ &hf_sapdiag_compress,
			{ "Compress", "sapdiag.header.compress", FT_UINT8, BASE_HEX, VALS(sapdiag_compress_vals), 0x0, "SAP Diag Compress", HFILL }},

		/* Error Messages */
		{ &hf_sapdiag_error_message,
			{ "Error Message", "sapdiag.error_message", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Diag Error Message", HFILL }},

		/* Compression header */
		{ &hf_sapdiag_compress_header,
			{ "Compression Header", "sapdiag.header.compression", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Diag Compression Header", HFILL }},
		{ &hf_sapdiag_uncomplength,
			{ "Uncompressed Length", "sapdiag.header.compression.uncomplength", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Diag Uncompressed Message Length", HFILL }},
		{ &hf_sapdiag_algorithm,
			{ "Compression Algorithm", "sapdiag.header.compression.algorithm", FT_UINT8, BASE_HEX, VALS(sapdiag_algorithm_vals), 0x0, "SAP Diag Compression Algorithm", HFILL }},
		{ &hf_sapdiag_magic,
			{ "Magic Bytes", "sapdiag.header.compression.magic", FT_UINT16, BASE_HEX, NULL, 0x0, "SAP Diag Compression Magic Bytes", HFILL }},
		{ &hf_sapdiag_special,
			{ "Special", "sapdiag.header.compression.special", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP Diag Special", HFILL }},
		{ &hf_sapdiag_decompress_return_code,
			{ "Decompress Return Code", "sapdiag.header.compression.returncode", FT_INT8, BASE_DEC, NULL, 0x0, "SAP Diag Decompression routine return code", HFILL }},
		/* SAPDiag Messages */
		{ &hf_sapdiag_item,
			{ "Item", "sapdiag.item", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Diag Item", HFILL }},
		{ &hf_sapdiag_item_type,
			{ "Type", "sapdiag.item.type", FT_UINT8, BASE_HEX, VALS(sapdiag_item_type_vals), 0x0, "SAP Diag Item Type", HFILL }},
		{ &hf_sapdiag_item_id,
			{ "ID", "sapdiag.item.id", FT_UINT8, BASE_HEX, VALS(sapdiag_item_id_vals), 0x0, "SAP Diag Item ID", HFILL }},
		{ &hf_sapdiag_item_sid,
			{ "SID", "sapdiag.item.sid", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP Diag Item SID", HFILL }},
		{ &hf_sapdiag_item_length,
			{ "Length", "sapdiag.item.length", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP Diag Item Length", HFILL }},
		{ &hf_sapdiag_item_value,
			{ "Value", "sapdiag.item.value", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Diag Item Value", HFILL }},
		/* SAPDiag DP Header */
		{ &hf_sapdiag_dp_request_id,
			{ "Request ID", "sapdiag.dp.reqid", FT_INT32, BASE_DEC, VALS(sapdiag_dp_request_id_vals), 0x0, "SAP Diag DP Request ID", HFILL }},
		{ &hf_sapdiag_dp_retcode,
			{ "Retcode", "sapdiag.dp.retcode", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP Diag DP Retcode", HFILL }},
		{ &hf_sapdiag_dp_sender_id,
			{ "Sender ID", "sapdiag.dp.senderid", FT_UINT8, BASE_HEX, VALS(sapdiag_dp_sender_id_vals), 0x0, "SAP Diag DP Sender ID", HFILL }},
		{ &hf_sapdiag_dp_action_type,
			{ "Action type", "sapdiag.dp.actiontype", FT_UINT8, BASE_HEX, VALS(sapdiag_dp_action_type_vals), 0x0, "SAP Diag DP Action Type", HFILL }},
		{ &hf_sapdiag_dp_req_info,
			{ "Request Info", "sapdiag.dp.reqinfo", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP Diag DP Request Info", HFILL }},
		/* Request Info Flag */
		{ &hf_sapdiag_dp_req_info_LOGIN,
			{ "Login Flag", "sapdiag.dp.reqinfo.login", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_LOGIN, "SAP Diag DP Request Info Login Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_LOGOFF,
			{ "Logoff Flag", "sapdiag.dp.reqinfo.logoff", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_LOGOFF, "SAP Diag DP Request Info Logoff Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_SHUTDOWN,
			{ "Shutdown Flag", "sapdiag.dp.reqinfo.shutdown", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_SHUTDOWN, "SAP Diag DP Request Info Shutdown Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_GRAPHIC_TM,
			{ "Graphic TM Flag", "sapdiag.dp.reqinfo.graphictm", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_GRAPHIC_TM, "SAP Diag DP Request Info Graphic TM Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_ALPHA_TM,
			{ "Alpha TM Flag", "sapdiag.dp.reqinfo.alphatm", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_ALPHA_TM, "SAP Diag DP Request Info Alpha TM Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_ERROR_FROM_APPC,
			{ "Error from APPC Flag", "sapdiag.dp.reqinfo.errorfromappc", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_ERROR_FROM_APPC, "SAP Diag DP Request Info Error from APPC Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_CANCELMODE,
			{ "Cancel Mode Flag", "sapdiag.dp.reqinfo.cancelmode", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_CANCELMODE, "SAP Diag DP Request Info Cancel Mode Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_MSG_WITH_REQ_BUF,
			{ "Msg with Req Buf Flag", "sapdiag.dp.reqinfo.msg_with_req_buf", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_MSG_WITH_REQ_BUF, "SAP Diag DP Request Info Msg with Req Buf Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_MSG_WITH_OH,
			{ "Msg with OH Flag", "sapdiag.dp.reqinfo.msg_with_oh", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_MSG_WITH_OH, "SAP Diag DP Request Info Msg with OH Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_BUFFER_REFRESH,
			{ "Buffer Refresh Flag", "sapdiag.dp.reqinfo.buffer_refresh", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_BUFFER_REFRESH, "SAP Diag DP Request Info Buffer Refresh Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_BTC_SCHEDULER,
			{ "BTC Scheduler Flag", "sapdiag.dp.reqinfo.btc_scheduler", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_BTC_SCHEDULER, "SAP Diag DP Request Info BTC Scheduler Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_APPC_SERVER_DOWN,
			{ "APPC Server Down Flag", "sapdiag.dp.reqinfo.appc_server_down", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_APPC_SERVER_DOWN, "SAP Diag DP Request Info APPC Server Down Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_MS_ERROR,
			{ "MS Error Flag", "sapdiag.dp.reqinfo.ms_error", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_MS_ERROR, "SAP Diag DP Request Info MS Error Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_SET_SYSTEM_USER,
			{ "Set System User Flag", "sapdiag.dp.reqinfo.set_system_user", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_SET_SYSTEM_USER, "SAP Diag DP Request Info Set System User Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_CANT_HANDLE_REQ,
			{ "DP Can't handle req Flag", "sapdiag.dp.reqinfo.dp_cant_hanlde_req", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_CANT_HANDLE_REQ, "SAP Diag DP Request DP Can't handle req Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_AUTO_ABAP,
			{ "DP Auto ABAP Flag", "sapdiag.dp.reqinfo.dp_auto_abap", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_AUTO_ABAP, "SAP Diag DP Request Info DP Auto ABAP Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_APPL_SERV_INFO,
			{ "DP Appl Serv Info Flag", "sapdiag.dp.reqinfo.dp_appl_serv_info", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_APPL_SERV_INFO, "SAP Diag DP Request Info DP Appl Serv Info Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_ADMIN,
			{ "DP Admin Flag", "sapdiag.dp.reqinfo.dp_admin", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_ADMIN, "SAP Diag DP Request Info DP Admin Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_SPOOL_ALRM,
			{ "DP Spool Alrm Flag", "sapdiag.dp.reqinfo.dp_spool_alrm", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_SPOOL_ALRM, "SAP Diag DP Request Info DP Spool Alrm Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_HAND_SHAKE,
			{ "DP Hand Shake Flag", "sapdiag.dp.reqinfo.dp_hand_shake", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_HAND_SHAKE, "SAP Diag DP Request Info DP Hand Shake Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_CANCEL_PRIV,
			{ "DP Cancel Privileges Flag", "sapdiag.dp.reqinfo.dp_cancel_priv", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_CANCEL_PRIV, "SAP Diag DP Request Info DP Cancel Privileges Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_RAISE_TIMEOUT,
			{ "DP Raise Timeout Flag", "sapdiag.dp.reqinfo.dp_raise_timeout", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_RAISE_TIMEOUT, "SAP Diag DP Request Info DP Raise Timeout Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_NEW_MODE,
			{ "DP New Mode Flag", "sapdiag.dp.reqinfo.dp_new_mode", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_NEW_MODE, "SAP Diag DP Request Info DP New Mode Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_SOFT_CANCEL,
			{ "DP Soft Cancel Flag", "sapdiag.dp.reqinfo.dp_soft_cancel", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_SOFT_CANCEL, "SAP Diag DP Request Info DP Soft Cancel Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_TM_INPUT,
			{ "DP TM Input Flag", "sapdiag.dp.reqinfo.dp_tm_input", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_TM_INPUT, "SAP Diag DP Request Info DP TM Input Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_TM_OUTPUT,
			{ "DP TM Output Flag", "sapdiag.dp.reqinfo.dp_tm_output", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_TM_OUTPUT, "SAP Diag DP Request Info DP TM Output Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_ASYNC_RFC,
			{ "DP Async RFC Flag", "sapdiag.dp.reqinfo.dp_async_rfc", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_ASYNC_RFC, "SAP Diag DP Request Info DP Async RFC Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_ICM_EVENT,
			{ "DP ICM Event Flag", "sapdiag.dp.reqinfo.dp_icm_event", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_ICM_EVENT, "SAP Diag DP Request Info DP ICM Event Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_AUTO_TH,
			{ "DP Auto TH Flag", "sapdiag.dp.reqinfo.dp_auto_th", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_AUTO_TH, "SAP Diag DP Request Info DP Auto TH Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_RFC_CANCEL,
			{ "DP RFC Cancel Flag", "sapdiag.dp.reqinfo.dp_rfc_cancel", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_RFC_CANCEL, "SAP Diag DP Request Info DP RFC Cancel Flag", HFILL }},
		{ &hf_sapdiag_dp_req_info_DP_MS_ADM,
			{ "DP MS Adm Flag", "sapdiag.dp.reqinfo.dp_ms_adm", FT_BOOLEAN, 8, NULL, SAPDIAG_DP_REQ_INFO_DP_MS_ADM, "SAP Diag DP Request Info DP MS Adm Flag", HFILL }},
		{ &hf_sapdiag_dp_tid,
			{ "TID", "sapdiag.dp.tid", FT_INT32, BASE_DEC, NULL, 0x0, "SAP Diag DP TID", HFILL }},
		{ &hf_sapdiag_dp_uid,
			{ "UID", "sapdiag.dp.uid", FT_INT16, BASE_DEC, NULL, 0x0, "SAP Diag DP UID", HFILL }},
		{ &hf_sapdiag_dp_mode,
			{ "Mode", "sapdiag.dp.mode", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP Diag DP Mode", HFILL }},
		{ &hf_sapdiag_dp_wp_id,
			{ "WP Id", "sapdiag.dp.wpid", FT_INT32, BASE_DEC, NULL, 0x0, "SAP Diag DP WP Id", HFILL }},
		{ &hf_sapdiag_dp_wp_ca_blk,
			{ "WP Ca Blk", "sapdiag.dp.wpcablk", FT_INT32, BASE_DEC, NULL, 0x0, "SAP Diag DP WP Ca Blk", HFILL }},
		{ &hf_sapdiag_dp_appc_ca_blk,
			{ "APPC Ca Blk", "sapdiag.dp.appccablk", FT_INT32, BASE_DEC, NULL, 0x0, "SAP Diag DP Appc Ca Blk", HFILL }},
		{ &hf_sapdiag_dp_len,
			{ "Len", "sapdiag.dp.len", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP Diag DP Len", HFILL }},
		{ &hf_sapdiag_dp_new_stat,
			{ "New Stat", "sapdiag.dp.newstat", FT_UINT8, BASE_HEX, VALS(sapdiag_dp_new_stat_vals), 0x0, "SAP Diag DP New Stat", HFILL }},
		{ &hf_sapdiag_dp_rq_id,
			{ "Request ID", "sapdiag.dp.rqid", FT_INT16, BASE_DEC, NULL, 0x0, "SAP Diag DP Request ID", HFILL }},
		{ &hf_sapdiag_dp_terminal,
			{ "Terminal", "sapdiag.dp.terminal", FT_STRING, BASE_NONE, NULL, 0x0, "SAP Diag DP Terminal", HFILL }},

		/* SAP Diag Support Bits */
		{ &hf_SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR,
			{ "Support Bit PROGRESS_INDICATOR", "sapdiag.diag.supportbits.PROGRESS_INDICATOR", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PROGRESS_INDICATOR, "SAP Diag Support Bit PROGRESS_INDICATOR",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS,
			{ "Support Bit SAPGUI_LABELS", "sapdiag.diag.supportbits.SAPGUI_LABELS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_LABELS, "SAP Diag Support Bit SAPGUI_LABELS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION,
			{ "Support Bit SAPGUI_DIAGVERSION", "sapdiag.diag.supportbits.SAPGUI_DIAGVERSION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_DIAGVERSION, "SAP Diag Support Bit SAPGUI_DIAGVERSION",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT,
			{ "Support Bit SAPGUI_SELECT_RECT", "sapdiag.diag.supportbits.SAPGUI_SELECT_RECT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_SELECT_RECT, "SAP Diag Support Bit SAPGUI_SELECT_RECT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT,
			{ "Support Bit SAPGUI_SYMBOL_RIGHT", "sapdiag.diag.supportbits.SAPGUI_SYMBOL_RIGHT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_SYMBOL_RIGHT, "SAP Diag Support Bit SAPGUI_SYMBOL_RIGHT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC,
			{ "Support Bit SAPGUI_FONT_METRIC", "sapdiag.diag.supportbits.SAPGUI_FONT_METRIC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_FONT_METRIC, "SAP Diag Support Bit SAPGUI_FONT_METRIC",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED,
			{ "Support Bit SAPGUI_COMPR_ENHANCED", "sapdiag.diag.supportbits.SAPGUI_COMPR_ENHANCED", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_COMPR_ENHANCED, "SAP Diag Support Bit SAPGUI_COMPR_ENHANCED",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE,
			{ "Support Bit SAPGUI_IMODE", "sapdiag.diag.supportbits.SAPGUI_IMODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_IMODE, "SAP Diag Support Bit SAPGUI_IMODE",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE,
			{ "Support Bit SAPGUI_LONG_MESSAGE", "sapdiag.diag.supportbits.SAPGUI_LONG_MESSAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_LONG_MESSAGE, "SAP Diag Support Bit SAPGUI_LONG_MESSAGE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE,
			{ "Support Bit SAPGUI_TABLE", "sapdiag.diag.supportbits.SAPGUI_TABLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_TABLE, "SAP Diag Support Bit SAPGUI_TABLE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1,
			{ "Support Bit SAPGUI_FOCUS_1", "sapdiag.diag.supportbits.SAPGUI_FOCUS_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_FOCUS_1, "SAP Diag Support Bit SAPGUI_FOCUS_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1,
			{ "Support Bit SAPGUI_PUSHBUTTON_1", "sapdiag.diag.supportbits.SAPGUI_PUSHBUTTON_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_PUSHBUTTON_1, "SAP Diag Support Bit SAPGUI_PUSHBUTTON_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UPPERCASE,
			{ "Support Bit UPPERCASE", "sapdiag.diag.supportbits.UPPERCASE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UPPERCASE, "SAP Diag Support Bit UPPERCASE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY,
			{ "Support Bit SAPGUI_TABPROPERTY", "sapdiag.diag.supportbits.SAPGUI_TABPROPERTY", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAPGUI_TABPROPERTY, "SAP Diag Support Bit SAPGUI_TABPROPERTY",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE,
			{ "Support Bit INPUT_UPPERCASE", "sapdiag.diag.supportbits.INPUT_UPPERCASE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_INPUT_UPPERCASE, "SAP Diag Support Bit INPUT_UPPERCASE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_DIALOG,
			{ "Support Bit RFC_DIALOG", "sapdiag.diag.supportbits.RFC_DIALOG", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_DIALOG, "SAP Diag Support Bit RFC_DIALOG",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT,
			{ "Support Bit LIST_HOTSPOT", "sapdiag.diag.supportbits.LIST_HOTSPOT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_LIST_HOTSPOT, "SAP Diag Support Bit LIST_HOTSPOT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_FKEY_TABLE,
			{ "Support Bit FKEY_TABLE", "sapdiag.diag.supportbits.FKEY_TABLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FKEY_TABLE, "SAP Diag Support Bit FKEY_TABLE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT,
			{ "Support Bit MENU_SHORTCUT", "sapdiag.diag.supportbits.MENU_SHORTCUT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MENU_SHORTCUT, "SAP Diag Support Bit MENU_SHORTCUT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_STOP_TRANS,
			{ "Support Bit STOP_TRANS", "sapdiag.diag.supportbits.STOP_TRANS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_STOP_TRANS, "SAP Diag Support Bit STOP_TRANS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_FULL_MENU,
			{ "Support Bit FULL_MENU", "sapdiag.diag.supportbits.FULL_MENU", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FULL_MENU, "SAP Diag Support Bit FULL_MENU",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES,
			{ "Support Bit OBJECT_NAMES", "sapdiag.diag.supportbits.OBJECT_NAMES", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_OBJECT_NAMES, "SAP Diag Support Bit OBJECT_NAMES",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE,
			{ "Support Bit CONTAINER_TYPE", "sapdiag.diag.supportbits.CONTAINER_TYPE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTAINER_TYPE, "SAP Diag Support Bit CONTAINER_TYPE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DLGH_FLAGS,
			{ "Support Bit DLGH_FLAGS", "sapdiag.diag.supportbits.DLGH_FLAGS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DLGH_FLAGS, "SAP Diag Support Bit DLGH_FLAGS",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_APPL_MNU,
			{ "Support Bit APPL_MNU", "sapdiag.diag.supportbits.APPL_MNU", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_APPL_MNU, "SAP Diag Support Bit APPL_MNU",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO,
			{ "Support Bit MESSAGE_INFO", "sapdiag.diag.supportbits.MESSAGE_INFO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_INFO, "SAP Diag Support Bit MESSAGE_INFO",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1,
			{ "Support Bit MESDUM_FLAG1", "sapdiag.diag.supportbits.MESDUM_FLAG1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESDUM_FLAG1, "SAP Diag Support Bit MESDUM_FLAG1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB,
			{ "Support Bit TABSEL_ATTRIB", "sapdiag.diag.supportbits.TABSEL_ATTRIB", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB, "SAP Diag Support Bit TABSEL_ATTRIB",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUIAPI,
			{ "Support Bit GUIAPI", "sapdiag.diag.supportbits.GUIAPI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUIAPI, "SAP Diag Support Bit GUIAPI",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOGRAPH,
			{ "Support Bit NOGRAPH", "sapdiag.diag.supportbits.NOGRAPH", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOGRAPH, "SAP Diag Support Bit NOGRAPH",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOMESSAGES,
			{ "Support Bit NOMESSAGES", "sapdiag.diag.supportbits.NOMESSAGES", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOMESSAGES, "SAP Diag Support Bit NOMESSAGES",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NORABAX,
			{ "Support Bit NORABAX", "sapdiag.diag.supportbits.NORABAX", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NORABAX, "SAP Diag Support Bit NORABAX",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_NOSYSMSG,
			{ "Support Bit NOSYSMSG", "sapdiag.diag.supportbits.NOSYSMSG", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOSYSMSG, "SAP Diag Support Bit NOSYSMSG",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT,
			{ "Support Bit NOSAPSCRIPT", "sapdiag.diag.supportbits.NOSAPSCRIPT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOSAPSCRIPT, "SAP Diag Support Bit NOSAPSCRIPT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NORFC,
			{ "Support Bit NORFC", "sapdiag.diag.supportbits.NORFC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NORFC, "SAP Diag Support Bit NORFC",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT,
			{ "Support Bit NEW_BSD_JUSTRIGHT", "sapdiag.diag.supportbits.NEW_BSD_JUSTRIGHT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NEW_BSD_JUSTRIGHT, "SAP Diag Support Bit NEW_BSD_JUSTRIGHT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_VARS,
			{ "Support Bit MESSAGE_VARS", "sapdiag.diag.supportbits.MESSAGE_VARS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_VARS, "SAP Diag Support Bit MESSAGE_VARS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_OCX_SUPPORT,
			{ "Support Bit OCX_SUPPORT", "sapdiag.diag.supportbits.OCX_SUPPORT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_OCX_SUPPORT, "SAP Diag Support Bit OCX_SUPPORT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SCROLL_INFOS,
			{ "Support Bit SCROLL_INFOS", "sapdiag.diag.supportbits.SCROLL_INFOS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SCROLL_INFOS, "SAP Diag Support Bit SCROLL_INFOS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK,
			{ "Support Bit TABLE_SIZE_OK", "sapdiag.diag.supportbits.TABLE_SIZE_OK", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABLE_SIZE_OK, "SAP Diag Support Bit TABLE_SIZE_OK",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2,
			{ "Support Bit MESSAGE_INFO2", "sapdiag.diag.supportbits.MESSAGE_INFO2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_INFO2, "SAP Diag Support Bit MESSAGE_INFO2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE,
			{ "Support Bit VARINFO_OKCODE", "sapdiag.diag.supportbits.VARINFO_OKCODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_OKCODE, "SAP Diag Support Bit VARINFO_OKCODE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CURR_TCODE,
			{ "Support Bit CURR_TCODE", "sapdiag.diag.supportbits.CURR_TCODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CURR_TCODE, "SAP Diag Support Bit CURR_TCODE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONN_WSIZE,
			{ "Support Bit CONN_WSIZE", "sapdiag.diag.supportbits.CONN_WSIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONN_WSIZE, "SAP Diag Support Bit CONN_WSIZE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2,
			{ "Support Bit PUSHBUTTON_2", "sapdiag.diag.supportbits.PUSHBUTTON_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PUSHBUTTON_2, "SAP Diag Support Bit PUSHBUTTON_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABSTRIP,
			{ "Support Bit TABSTRIP", "sapdiag.diag.supportbits.TABSTRIP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABSTRIP, "SAP Diag Support Bit TABSTRIP",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_1,
			{ "Support Bit UNKNOWN_1", "sapdiag.diag.supportbits.UNKNOWN_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNKNOWN_1, "SAP Diag Support Bit UNKNOWN_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS,
			{ "Support Bit TABSCROLL_INFOS", "sapdiag.diag.supportbits.TABSCROLL_INFOS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABSCROLL_INFOS, "SAP Diag Support Bit TABSCROLL_INFOS",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES,
			{ "Support Bit TABLE_FIELD_NAMES", "sapdiag.diag.supportbits.TABLE_FIELD_NAMES", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABLE_FIELD_NAMES, "SAP Diag Support Bit TABLE_FIELD_NAMES",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST,
			{ "Support Bit NEW_MODE_REQUEST", "sapdiag.diag.supportbits.NEW_MODE_REQUEST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NEW_MODE_REQUEST, "SAP Diag Support Bit NEW_MODE_REQUEST",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER,
			{ "Support Bit RFCBLOB_DIAG_PARSER", "sapdiag.diag.supportbits.RFCBLOB_DIAG_PARSER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFCBLOB_DIAG_PARSER, "SAP Diag Support Bit RFCBLOB_DIAG_PARSER",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER,
			{ "Support Bit MULTI_LOGIN_USER", "sapdiag.diag.supportbits.MULTI_LOGIN_USER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MULTI_LOGIN_USER, "SAP Diag Support Bit MULTI_LOGIN_USER",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER,
			{ "Support Bit CONTROL_CONTAINER", "sapdiag.diag.supportbits.CONTROL_CONTAINER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTROL_CONTAINER, "SAP Diag Support Bit CONTROL_CONTAINER",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED,
			{ "Support Bit APPTOOLBAR_FIXED", "sapdiag.diag.supportbits.APPTOOLBAR_FIXED", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_APPTOOLBAR_FIXED, "SAP Diag Support Bit APPTOOLBAR_FIXED",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED,
			{ "Support Bit R3INFO_USER_CHECKED", "sapdiag.diag.supportbits.R3INFO_USER_CHECKED", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_USER_CHECKED, "SAP Diag Support Bit R3INFO_USER_CHECKED",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO,
			{ "Support Bit NEED_STDDYNPRO", "sapdiag.diag.supportbits.NEED_STDDYNPRO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NEED_STDDYNPRO, "SAP Diag Support Bit NEED_STDDYNPRO",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_TYPE_SERVER,
			{ "Support Bit TYPE_SERVER", "sapdiag.diag.supportbits.TYPE_SERVER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TYPE_SERVER, "SAP Diag Support Bit TYPE_SERVER",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_COMBOBOX,
			{ "Support Bit COMBOBOX", "sapdiag.diag.supportbits.COMBOBOX", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_COMBOBOX, "SAP Diag Support Bit COMBOBOX",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED,
			{ "Support Bit INPUT_REQUIRED", "sapdiag.diag.supportbits.INPUT_REQUIRED", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_INPUT_REQUIRED, "SAP Diag Support Bit INPUT_REQUIRED",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE,
			{ "Support Bit ISO_LANGUAGE", "sapdiag.diag.supportbits.ISO_LANGUAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ISO_LANGUAGE, "SAP Diag Support Bit ISO_LANGUAGE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE,
			{ "Support Bit COMBOBOX_TABLE", "sapdiag.diag.supportbits.COMBOBOX_TABLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_COMBOBOX_TABLE, "SAP Diag Support Bit COMBOBOX_TABLE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS,
			{ "Support Bit R3INFO_FLAGS", "sapdiag.diag.supportbits.R3INFO_FLAGS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS, "SAP Diag Support Bit R3INFO_FLAGS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS,
			{ "Support Bit CHECKRADIO_EVENTS", "sapdiag.diag.supportbits.CHECKRADIO_EVENTS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CHECKRADIO_EVENTS, "SAP Diag Support Bit CHECKRADIO_EVENTS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_USERID,
			{ "Support Bit R3INFO_USERID", "sapdiag.diag.supportbits.R3INFO_USERID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_USERID, "SAP Diag Support Bit R3INFO_USERID",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT,
			{ "Support Bit R3INFO_ROLLCOUNT", "sapdiag.diag.supportbits.R3INFO_ROLLCOUNT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_ROLLCOUNT, "SAP Diag Support Bit R3INFO_ROLLCOUNT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_USER_TURNTIME2,
			{ "Support Bit USER_TURNTIME2", "sapdiag.diag.supportbits.USER_TURNTIME2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_USER_TURNTIME2, "SAP Diag Support Bit USER_TURNTIME2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NUM_FIELD,
			{ "Support Bit NUM_FIELD", "sapdiag.diag.supportbits.NUM_FIELD", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NUM_FIELD, "SAP Diag Support Bit NUM_FIELD",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WIN16,
			{ "Support Bit WIN16", "sapdiag.diag.supportbits.WIN16", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WIN16, "SAP Diag Support Bit WIN16",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTEXT_MENU,
			{ "Support Bit CONTEXT_MENU", "sapdiag.diag.supportbits.CONTEXT_MENU", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTEXT_MENU, "SAP Diag Support Bit CONTEXT_MENU",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE,
			{ "Support Bit SCROLLABLE_TABSTRIP_PAGE", "sapdiag.diag.supportbits.SCROLLABLE_TABSTRIP_PAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SCROLLABLE_TABSTRIP_PAGE, "SAP Diag Support Bit SCROLLABLE_TABSTRIP_PAGE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION,
			{ "Support Bit EVENT_DESCRIPTION", "sapdiag.diag.supportbits.EVENT_DESCRIPTION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION, "SAP Diag Support Bit EVENT_DESCRIPTION",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_LABEL_OWNER,
			{ "Support Bit LABEL_OWNER", "sapdiag.diag.supportbits.LABEL_OWNER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_LABEL_OWNER, "SAP Diag Support Bit LABEL_OWNER",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD,
			{ "Support Bit CLICKABLE_FIELD", "sapdiag.diag.supportbits.CLICKABLE_FIELD", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CLICKABLE_FIELD, "SAP Diag Support Bit CLICKABLE_FIELD",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PROPERTY_BAG,
			{ "Support Bit PROPERTY_BAG", "sapdiag.diag.supportbits.PROPERTY_BAG", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PROPERTY_BAG, "SAP Diag Support Bit PROPERTY_BAG",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_1,
			{ "Support Bit UNUSED_1", "sapdiag.diag.supportbits.UNUSED_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_1, "SAP Diag Support Bit UNUSED_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2,
			{ "Support Bit TABLE_ROW_REFERENCES_2", "sapdiag.diag.supportbits.TABLE_ROW_REFERENCES_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABLE_ROW_REFERENCES_2, "SAP Diag Support Bit TABLE_ROW_REFERENCES_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PROPFONT_VALID,
			{ "Support Bit PROPFONT_VALID", "sapdiag.diag.supportbits.PROPFONT_VALID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PROPFONT_VALID, "SAP Diag Support Bit PROPFONT_VALID",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER,
			{ "Support Bit VARINFO_CONTAINER", "sapdiag.diag.supportbits.VARINFO_CONTAINER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER, "SAP Diag Support Bit VARINFO_CONTAINER",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID,
			{ "Support Bit R3INFO_IMODEUUID", "sapdiag.diag.supportbits.R3INFO_IMODEUUID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_IMODEUUID, "SAP Diag Support Bit R3INFO_IMODEUUID",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOTGUI,
			{ "Support Bit NOTGUI", "sapdiag.diag.supportbits.NOTGUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOTGUI, "SAP Diag Support Bit NOTGUI",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_WAN,
			{ "Support Bit WAN", "sapdiag.diag.supportbits.WAN", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WAN, "SAP Diag Support Bit WAN",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XML_BLOBS,
			{ "Support Bit XML_BLOBS", "sapdiag.diag.supportbits.XML_BLOBS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XML_BLOBS, "SAP Diag Support Bit XML_BLOBS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_QUEUE,
			{ "Support Bit RFC_QUEUE", "sapdiag.diag.supportbits.RFC_QUEUE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_QUEUE, "SAP Diag Support Bit RFC_QUEUE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_COMPRESS,
			{ "Support Bit RFC_COMPRESS", "sapdiag.diag.supportbits.RFC_COMPRESS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_COMPRESS, "SAP Diag Support Bit RFC_COMPRESS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_JAVA_BEANS,
			{ "Support Bit JAVA_BEANS", "sapdiag.diag.supportbits.JAVA_BEANS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_JAVA_BEANS, "SAP Diag Support Bit JAVA_BEANS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND,
			{ "Support Bit DPLOADONDEMAND", "sapdiag.diag.supportbits.DPLOADONDEMAND", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND, "SAP Diag Support Bit DPLOADONDEMAND",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE,
			{ "Support Bit CTL_PROPCACHE", "sapdiag.diag.supportbits.CTL_PROPCACHE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CTL_PROPCACHE, "SAP Diag Support Bit CTL_PROPCACHE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID,
			{ "Support Bit ENJOY_IMODEUUID", "sapdiag.diag.supportbits.ENJOY_IMODEUUID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID, "SAP Diag Support Bit ENJOY_IMODEUUID",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB,
			{ "Support Bit RFC_ASYNC_BLOB", "sapdiag.diag.supportbits.RFC_ASYNC_BLOB", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_ASYNC_BLOB, "SAP Diag Support Bit RFC_ASYNC_BLOB",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS,
			{ "Support Bit KEEP_SCROLLPOS", "sapdiag.diag.supportbits.KEEP_SCROLLPOS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_KEEP_SCROLLPOS, "SAP Diag Support Bit KEEP_SCROLLPOS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_2,
			{ "Support Bit UNUSED_2", "sapdiag.diag.supportbits.UNUSED_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_2, "SAP Diag Support Bit UNUSED_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_3,
			{ "Support Bit UNUSED_3", "sapdiag.diag.supportbits.UNUSED_3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_3, "SAP Diag Support Bit UNUSED_3",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XML_PROPERTIES,
			{ "Support Bit XML_PROPERTIES", "sapdiag.diag.supportbits.XML_PROPERTIES", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XML_PROPERTIES, "SAP Diag Support Bit XML_PROPERTIES",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_4,
			{ "Support Bit UNUSED_4", "sapdiag.diag.supportbits.UNUSED_4", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_4, "SAP Diag Support Bit UNUSED_4",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_HEX_FIELD,
			{ "Support Bit HEX_FIELD", "sapdiag.diag.supportbits.HEX_FIELD", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_HEX_FIELD, "SAP Diag Support Bit HEX_FIELD",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_HAS_CACHE,
			{ "Support Bit HAS_CACHE", "sapdiag.diag.supportbits.HAS_CACHE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_HAS_CACHE, "SAP Diag Support Bit HAS_CACHE",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE,
			{ "Support Bit XML_PROP_TABLE", "sapdiag.diag.supportbits.XML_PROP_TABLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE, "SAP Diag Support Bit XML_PROP_TABLE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_5,
			{ "Support Bit UNUSED_5", "sapdiag.diag.supportbits.UNUSED_5", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_5, "SAP Diag Support Bit UNUSED_5",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2,
			{ "Support Bit ENJOY_IMODEUUID2", "sapdiag.diag.supportbits.ENJOY_IMODEUUID2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID2, "SAP Diag Support Bit ENJOY_IMODEUUID2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ITS,
			{ "Support Bit ITS", "sapdiag.diag.supportbits.ITS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ITS, "SAP Diag Support Bit ITS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NO_EASYACCESS,
			{ "Support Bit NO_EASYACCESS", "sapdiag.diag.supportbits.NO_EASYACCESS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NO_EASYACCESS, "SAP Diag Support Bit NO_EASYACCESS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PROPERTYPUMP,
			{ "Support Bit PROPERTYPUMP", "sapdiag.diag.supportbits.PROPERTYPUMP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PROPERTYPUMP, "SAP Diag Support Bit PROPERTYPUMP",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_COOKIE,
			{ "Support Bit COOKIE", "sapdiag.diag.supportbits.COOKIE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_COOKIE, "SAP Diag Support Bit COOKIE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNUSED_6,
			{ "Support Bit UNUSED_6", "sapdiag.diag.supportbits.UNUSED_6", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNUSED_6, "SAP Diag Support Bit UNUSED_6",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE,
			{ "Support Bit SUPPBIT_AREA_SIZE", "sapdiag.diag.supportbits.SUPPBIT_AREA_SIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SUPPBIT_AREA_SIZE, "SAP Diag Support Bit SUPPBIT_AREA_SIZE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE,
			{ "Support Bit DPLOADONDEMAND_WRITE", "sapdiag.diag.supportbits.DPLOADONDEMAND_WRITE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DPLOADONDEMAND_WRITE, "SAP Diag Support Bit DPLOADONDEMAND_WRITE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS,
			{ "Support Bit CONTROL_FOCUS", "sapdiag.diag.supportbits.CONTROL_FOCUS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS, "SAP Diag Support Bit CONTROL_FOCUS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY,
			{ "Support Bit ENTRY_HISTORY", "sapdiag.diag.supportbits.ENTRY_HISTORY", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENTRY_HISTORY, "SAP Diag Support Bit ENTRY_HISTORY",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE,
			{ "Support Bit AUTO_CODEPAGE", "sapdiag.diag.supportbits.AUTO_CODEPAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AUTO_CODEPAGE, "SAP Diag Support Bit AUTO_CODEPAGE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CACHED_VSETS,
			{ "Support Bit CACHED_VSETS", "sapdiag.diag.supportbits.CACHED_VSETS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CACHED_VSETS, "SAP Diag Support Bit CACHED_VSETS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR,
			{ "Support Bit EMERGENCY_REPAIR", "sapdiag.diag.supportbits.EMERGENCY_REPAIR", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EMERGENCY_REPAIR, "SAP Diag Support Bit EMERGENCY_REPAIR",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AREA2FRONT,
			{ "Support Bit AREA2FRONT", "sapdiag.diag.supportbits.AREA2FRONT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AREA2FRONT, "SAP Diag Support Bit AREA2FRONT",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH,
			{ "Support Bit SCROLLBAR_WIDTH", "sapdiag.diag.supportbits.SCROLLBAR_WIDTH", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SCROLLBAR_WIDTH, "SAP Diag Support Bit SCROLLBAR_WIDTH",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AUTORESIZE,
			{ "Support Bit AUTORESIZE", "sapdiag.diag.supportbits.AUTORESIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AUTORESIZE, "SAP Diag Support Bit AUTORESIZE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EDIT_VARLEN,
			{ "Support Bit EDIT_VARLEN", "sapdiag.diag.supportbits.EDIT_VARLEN", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EDIT_VARLEN, "SAP Diag Support Bit EDIT_VARLEN",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WORKPLACE,
			{ "Support Bit WORKPLACE", "sapdiag.diag.supportbits.WORKPLACE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WORKPLACE, "SAP Diag Support Bit WORKPLACE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_PRINTDATA,
			{ "Support Bit PRINTDATA", "sapdiag.diag.supportbits.PRINTDATA", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_PRINTDATA, "SAP Diag Support Bit PRINTDATA",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_2,
			{ "Support Bit UNKNOWN_2", "sapdiag.diag.supportbits.UNKNOWN_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNKNOWN_2, "SAP Diag Support Bit UNKNOWN_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SINGLE_SESSION,
			{ "Support Bit SINGLE_SESSION", "sapdiag.diag.supportbits.SINGLE_SESSION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SINGLE_SESSION, "SAP Diag Support Bit SINGLE_SESSION",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE,
			{ "Support Bit NOTIFY_NEWMODE", "sapdiag.diag.supportbits.NOTIFY_NEWMODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NOTIFY_NEWMODE, "SAP Diag Support Bit NOTIFY_NEWMODE",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT,
			{ "Support Bit TOOLBAR_HEIGHT", "sapdiag.diag.supportbits.TOOLBAR_HEIGHT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TOOLBAR_HEIGHT, "SAP Diag Support Bit TOOLBAR_HEIGHT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER,
			{ "Support Bit XMLPROP_CONTAINER", "sapdiag.diag.supportbits.XMLPROP_CONTAINER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XMLPROP_CONTAINER, "SAP Diag Support Bit XMLPROP_CONTAINER",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO,
			{ "Support Bit XMLPROP_DYNPRO", "sapdiag.diag.supportbits.XMLPROP_DYNPRO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XMLPROP_DYNPRO, "SAP Diag Support Bit XMLPROP_DYNPRO",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT,
			{ "Support Bit DP_HTTP_PUT", "sapdiag.diag.supportbits.DP_HTTP_PUT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DP_HTTP_PUT, "SAP Diag Support Bit DP_HTTP_PUT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT,
			{ "Support Bit DYNAMIC_PASSPORT", "sapdiag.diag.supportbits.DYNAMIC_PASSPORT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DYNAMIC_PASSPORT, "SAP Diag Support Bit DYNAMIC_PASSPORT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WEBGUI,
			{ "Support Bit WEBGUI", "sapdiag.diag.supportbits.WEBGUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WEBGUI, "SAP Diag Support Bit WEBGUI",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE,
			{ "Support Bit WEBGUI_HELPMODE", "sapdiag.diag.supportbits.WEBGUI_HELPMODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WEBGUI_HELPMODE, "SAP Diag Support Bit WEBGUI_HELPMODE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST,
			{ "Support Bit CONTROL_FOCUS_ON_LIST", "sapdiag.diag.supportbits.CONTROL_FOCUS_ON_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST, "SAP Diag Support Bit CONTROL_FOCUS_ON_LIST",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2,
			{ "Support Bit CBU_RBUDUMMY_2", "sapdiag.diag.supportbits.CBU_RBUDUMMY_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_2, "SAP Diag Support Bit CBU_RBUDUMMY_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_1,
			{ "Support Bit EOKDUMMY_1", "sapdiag.diag.supportbits.EOKDUMMY_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EOKDUMMY_1, "SAP Diag Support Bit EOKDUMMY_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING,
			{ "Support Bit GUI_USER_SCRIPTING", "sapdiag.diag.supportbits.GUI_USER_SCRIPTING", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING, "SAP Diag Support Bit GUI_USER_SCRIPTING",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SLC,
			{ "Support Bit SLC", "sapdiag.diag.supportbits.SLC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SLC, "SAP Diag Support Bit SLC",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ACCESSIBILITY,
			{ "Support Bit ACCESSIBILITY", "sapdiag.diag.supportbits.ACCESSIBILITY", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ACCESSIBILITY, "SAP Diag Support Bit ACCESSIBILITY",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ECATT,
			{ "Support Bit ECATT", "sapdiag.diag.supportbits.ECATT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ECATT, "SAP Diag Support Bit ECATT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3,
			{ "Support Bit ENJOY_IMODEUUID3", "sapdiag.diag.supportbits.ENJOY_IMODEUUID3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENJOY_IMODEUUID3, "SAP Diag Support Bit ENJOY_IMODEUUID3",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF8,
			{ "Support Bit ENABLE_UTF8", "sapdiag.diag.supportbits.ENABLE_UTF8", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENABLE_UTF8, "SAP Diag Support Bit ENABLE_UTF8",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME,
			{ "Support Bit R3INFO_AUTOLOGOUT_TIME", "sapdiag.diag.supportbits.R3INFO_AUTOLOGOUT_TIME", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_AUTOLOGOUT_TIME, "SAP Diag Support Bit R3INFO_AUTOLOGOUT_TIME",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST,
			{ "Support Bit VARINFO_ICON_TITLE_LIST", "sapdiag.diag.supportbits.VARINFO_ICON_TITLE_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_ICON_TITLE_LIST, "SAP Diag Support Bit VARINFO_ICON_TITLE_LIST",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE,
			{ "Support Bit ENABLE_UTF16BE", "sapdiag.diag.supportbits.ENABLE_UTF16BE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENABLE_UTF16BE, "SAP Diag Support Bit ENABLE_UTF16BE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE,
			{ "Support Bit ENABLE_UTF16LE", "sapdiag.diag.supportbits.ENABLE_UTF16LE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENABLE_UTF16LE, "SAP Diag Support Bit ENABLE_UTF16LE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP,
			{ "Support Bit R3INFO_CODEPAGE_APP", "sapdiag.diag.supportbits.R3INFO_CODEPAGE_APP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP, "SAP Diag Support Bit R3INFO_CODEPAGE_APP",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ENABLE_APPL4,
			{ "Support Bit ENABLE_APPL4", "sapdiag.diag.supportbits.ENABLE_APPL4", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ENABLE_APPL4, "SAP Diag Support Bit ENABLE_APPL4",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL,
			{ "Support Bit GUIPATCHLEVEL", "sapdiag.diag.supportbits.GUIPATCHLEVEL", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL, "SAP Diag Support Bit GUIPATCHLEVEL",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE,
			{ "Support Bit CBURBU_NEW_STATE", "sapdiag.diag.supportbits.CBURBU_NEW_STATE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CBURBU_NEW_STATE, "SAP Diag Support Bit CBURBU_NEW_STATE",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_BINARY_EVENTID,
			{ "Support Bit BINARY_EVENTID", "sapdiag.diag.supportbits.BINARY_EVENTID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_BINARY_EVENTID, "SAP Diag Support Bit BINARY_EVENTID",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_THEME,
			{ "Support Bit GUI_THEME", "sapdiag.diag.supportbits.GUI_THEME", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_THEME, "SAP Diag Support Bit GUI_THEME",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TOP_WINDOW,
			{ "Support Bit TOP_WINDOW", "sapdiag.diag.supportbits.TOP_WINDOW", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TOP_WINDOW, "SAP Diag Support Bit TOP_WINDOW",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1,
			{ "Support Bit EVENT_DESCRIPTION_1", "sapdiag.diag.supportbits.EVENT_DESCRIPTION_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EVENT_DESCRIPTION_1, "SAP Diag Support Bit EVENT_DESCRIPTION_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SPLITTER,
			{ "Support Bit SPLITTER", "sapdiag.diag.supportbits.SPLITTER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SPLITTER, "SAP Diag Support Bit SPLITTER",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY,
			{ "Support Bit VALUE_4_HISTORY", "sapdiag.diag.supportbits.VALUE_4_HISTORY", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VALUE_4_HISTORY, "SAP Diag Support Bit VALUE_4_HISTORY",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ACC_LIST,
			{ "Support Bit ACC_LIST", "sapdiag.diag.supportbits.ACC_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ACC_LIST, "SAP Diag Support Bit ACC_LIST",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO,
			{ "Support Bit GUI_USER_SCRIPTING_INFO", "sapdiag.diag.supportbits.GUI_USER_SCRIPTING_INFO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_USER_SCRIPTING_INFO, "SAP Diag Support Bit GUI_USER_SCRIPTING_INFO",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM,
			{ "Support Bit TEXTEDIT_STREAM", "sapdiag.diag.supportbits.TEXTEDIT_STREAM", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TEXTEDIT_STREAM, "SAP Diag Support Bit TEXTEDIT_STREAM",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS,
			{ "Support Bit DYNT_NOFOCUS", "sapdiag.diag.supportbits.DYNT_NOFOCUS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DYNT_NOFOCUS, "SAP Diag Support Bit DYNT_NOFOCUS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1,
			{ "Support Bit R3INFO_CODEPAGE_APP_1", "sapdiag.diag.supportbits.R3INFO_CODEPAGE_APP_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_CODEPAGE_APP_1, "SAP Diag Support Bit R3INFO_CODEPAGE_APP_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_FRAME_1,
			{ "Support Bit FRAME_1", "sapdiag.diag.supportbits.FRAME_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FRAME_1, "SAP Diag Support Bit FRAME_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TICKET4GUI,
			{ "Support Bit TICKET4GUI", "sapdiag.diag.supportbits.TICKET4GUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TICKET4GUI, "SAP Diag Support Bit TICKET4GUI",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS,
			{ "Support Bit ACC_LIST_PROPS", "sapdiag.diag.supportbits.ACC_LIST_PROPS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ACC_LIST_PROPS, "SAP Diag Support Bit ACC_LIST_PROPS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT,
			{ "Support Bit TABSEL_ATTRIB_INPUT", "sapdiag.diag.supportbits.TABSEL_ATTRIB_INPUT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABSEL_ATTRIB_INPUT, "SAP Diag Support Bit TABSEL_ATTRIB_INPUT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP,
			{ "Support Bit DEFAULT_TOOLTIP", "sapdiag.diag.supportbits.DEFAULT_TOOLTIP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DEFAULT_TOOLTIP, "SAP Diag Support Bit DEFAULT_TOOLTIP",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2,
			{ "Support Bit XML_PROP_TABLE_2", "sapdiag.diag.supportbits.XML_PROP_TABLE_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XML_PROP_TABLE_2, "SAP Diag Support Bit XML_PROP_TABLE_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3,
			{ "Support Bit CBU_RBUDUMMY_3", "sapdiag.diag.supportbits.CBU_RBUDUMMY_3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CBU_RBUDUMMY_3, "SAP Diag Support Bit CBU_RBUDUMMY_3",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CELLINFO,
			{ "Support Bit CELLINFO", "sapdiag.diag.supportbits.CELLINFO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CELLINFO, "SAP Diag Support Bit CELLINFO",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2,
			{ "Support Bit CONTROL_FOCUS_ON_LIST_2", "sapdiag.diag.supportbits.CONTROL_FOCUS_ON_LIST_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTROL_FOCUS_ON_LIST_2, "SAP Diag Support Bit CONTROL_FOCUS_ON_LIST_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT,
			{ "Support Bit TABLE_COLUMNWIDTH_INPUT", "sapdiag.diag.supportbits.TABLE_COLUMNWIDTH_INPUT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TABLE_COLUMNWIDTH_INPUT, "SAP Diag Support Bit TABLE_COLUMNWIDTH_INPUT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ITS_PLUGIN,
			{ "Support Bit ITS_PLUGIN", "sapdiag.diag.supportbits.ITS_PLUGIN", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ITS_PLUGIN, "SAP Diag Support Bit ITS_PLUGIN",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS,
			{ "Support Bit OBJECT_NAMES_4_LOGIN_PROCESS", "sapdiag.diag.supportbits.OBJECT_NAMES_4_LOGIN_PROCESS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_4_LOGIN_PROCESS, "SAP Diag Support Bit OBJECT_NAMES_4_LOGIN_PROCESS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI,
			{ "Support Bit RFC_SERVER_4_GUI", "sapdiag.diag.supportbits.RFC_SERVER_4_GUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RFC_SERVER_4_GUI, "SAP Diag Support Bit RFC_SERVER_4_GUI",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2,
			{ "Support Bit R3INFO_FLAGS_2", "sapdiag.diag.supportbits.R3INFO_FLAGS_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_FLAGS_2, "SAP Diag Support Bit R3INFO_FLAGS_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_RCUI,
			{ "Support Bit RCUI", "sapdiag.diag.supportbits.RCUI", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_RCUI, "SAP Diag Support Bit RCUI",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE,
			{ "Support Bit MENUENTRY_WITH_FCODE", "sapdiag.diag.supportbits.MENUENTRY_WITH_FCODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MENUENTRY_WITH_FCODE, "SAP Diag Support Bit MENUENTRY_WITH_FCODE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE,
			{ "Support Bit WEBSAPCONSOLE", "sapdiag.diag.supportbits.WEBSAPCONSOLE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_WEBSAPCONSOLE, "SAP Diag Support Bit WEBSAPCONSOLE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION,
			{ "Support Bit R3INFO_KERNEL_VERSION", "sapdiag.diag.supportbits.R3INFO_KERNEL_VERSION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_R3INFO_KERNEL_VERSION, "SAP Diag Support Bit R3INFO_KERNEL_VERSION",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP,
			{ "Support Bit VARINFO_CONTAINER_LOOP", "sapdiag.diag.supportbits.VARINFO_CONTAINER_LOOP", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_LOOP, "SAP Diag Support Bit VARINFO_CONTAINER_LOOP",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EOKDUMMY_2,
			{ "Support Bit EOKDUMMY_2", "sapdiag.diag.supportbits.EOKDUMMY_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EOKDUMMY_2, "SAP Diag Support Bit EOKDUMMY_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3,
			{ "Support Bit MESSAGE_INFO3", "sapdiag.diag.supportbits.MESSAGE_INFO3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_INFO3, "SAP Diag Support Bit MESSAGE_INFO3",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_SBA2,
			{ "Support Bit SBA2", "sapdiag.diag.supportbits.SBA2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SBA2, "SAP Diag Support Bit SBA2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE,
			{ "Support Bit MAINAREA_SIZE", "sapdiag.diag.supportbits.MAINAREA_SIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MAINAREA_SIZE, "SAP Diag Support Bit MAINAREA_SIZE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2,
			{ "Support Bit GUIPATCHLEVEL_2", "sapdiag.diag.supportbits.GUIPATCHLEVEL_2", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUIPATCHLEVEL_2, "SAP Diag Support Bit GUIPATCHLEVEL_2",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE,
			{ "Support Bit DISPLAY_SIZE", "sapdiag.diag.supportbits.DISPLAY_SIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DISPLAY_SIZE, "SAP Diag Support Bit DISPLAY_SIZE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_PACKET,
			{ "Support Bit GUI_PACKET", "sapdiag.diag.supportbits.GUI_PACKET", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_PACKET, "SAP Diag Support Bit GUI_PACKET",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER,
			{ "Support Bit DIALOG_STEP_NUMBER", "sapdiag.diag.supportbits.DIALOG_STEP_NUMBER", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DIALOG_STEP_NUMBER, "SAP Diag Support Bit DIALOG_STEP_NUMBER",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION,
			{ "Support Bit TC_KEEP_SCROLL_POSITION", "sapdiag.diag.supportbits.TC_KEEP_SCROLL_POSITION", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TC_KEEP_SCROLL_POSITION, "SAP Diag Support Bit TC_KEEP_SCROLL_POSITION",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST,
			{ "Support Bit MESSAGE_SERVICE_REQUEST", "sapdiag.diag.supportbits.MESSAGE_SERVICE_REQUEST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESSAGE_SERVICE_REQUEST, "SAP Diag Support Bit MESSAGE_SERVICE_REQUEST",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME,
			{ "Support Bit DYNT_FOCUS_FRAME", "sapdiag.diag.supportbits.DYNT_FOCUS_FRAME", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_DYNT_FOCUS_FRAME, "SAP Diag Support Bit DYNT_FOCUS_FRAME",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN,
			{ "Support Bit MAX_STRING_LEN", "sapdiag.diag.supportbits.MAX_STRING_LEN", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MAX_STRING_LEN, "SAP Diag Support Bit MAX_STRING_LEN",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1,
			{ "Support Bit VARINFO_CONTAINER_1", "sapdiag.diag.supportbits.VARINFO_CONTAINER_1", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_VARINFO_CONTAINER_1, "SAP Diag Support Bit VARINFO_CONTAINER_1",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS,
			{ "Support Bit STD_TOOLBAR_ITEMS", "sapdiag.diag.supportbits.STD_TOOLBAR_ITEMS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_STD_TOOLBAR_ITEMS, "SAP Diag Support Bit STD_TOOLBAR_ITEMS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO,
			{ "Support Bit XMLPROP_LIST_DYNPRO", "sapdiag.diag.supportbits.XMLPROP_LIST_DYNPRO", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_XMLPROP_LIST_DYNPRO, "SAP Diag Support Bit XMLPROP_LIST_DYNPRO",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT,
			{ "Support Bit TRACE_GUI_CONNECT", "sapdiag.diag.supportbits.TRACE_GUI_CONNECT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_TRACE_GUI_CONNECT, "SAP Diag Support Bit TRACE_GUI_CONNECT",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH,
			{ "Support Bit LIST_FULLWIDTH", "sapdiag.diag.supportbits.LIST_FULLWIDTH", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_LIST_FULLWIDTH, "SAP Diag Support Bit LIST_FULLWIDTH",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT,
			{ "Support Bit ALLWAYS_SEND_CLIENT", "sapdiag.diag.supportbits.ALLWAYS_SEND_CLIENT", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_ALLWAYS_SEND_CLIENT, "SAP Diag Support Bit ALLWAYS_SEND_CLIENT",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_UNKNOWN_3,
			{ "Support Bit UNKNOWN_3", "sapdiag.diag.supportbits.UNKNOWN_3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_UNKNOWN_3, "SAP Diag Support Bit UNKNOWN_3",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR,
			{ "Support Bit GUI_SIGNATURE_COLOR", "sapdiag.diag.supportbits.GUI_SIGNATURE_COLOR", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_SIGNATURE_COLOR, "SAP Diag Support Bit GUI_SIGNATURE_COLOR",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MAX_WSIZE,
			{ "Support Bit MAX_WSIZE", "sapdiag.diag.supportbits.MAX_WSIZE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MAX_WSIZE, "SAP Diag Support Bit MAX_WSIZE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_SAP_PERSONAS,
			{ "Support Bit SAP_PERSONAS", "sapdiag.diag.supportbits.SAP_PERSONAS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_SAP_PERSONAS, "SAP Diag Support Bit SAP_PERSONAS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_IDA_ALV,
			{ "Support Bit IDA_ALV", "sapdiag.diag.supportbits.IDA_ALV", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_IDA_ALV, "SAP Diag Support Bit IDA_ALV",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS,
			{ "Support Bit IDA_ALV_FRAGMENTS", "sapdiag.diag.supportbits.IDA_ALV_FRAGMENTS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_IDA_ALV_FRAGMENTS, "SAP Diag Support Bit IDA_ALV_FRAGMENTS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AMC,
			{ "Support Bit AMC", "sapdiag.diag.supportbits.AMC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AMC, "SAP Diag Support Bit AMC",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC,
			{ "Support Bit EXTMODE_FONT_METRIC", "sapdiag.diag.supportbits.EXTMODE_FONT_METRIC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_EXTMODE_FONT_METRIC, "SAP Diag Support Bit EXTMODE_FONT_METRIC",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_GROUPBOX,
			{ "Support Bit GROUPBOX", "sapdiag.diag.supportbits.GROUPBOX", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GROUPBOX, "SAP Diag Support Bit GROUPBOX",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON,
			{ "Support Bit AGI_ID_TS_BUTTON", "sapdiag.diag.supportbits.AGI_ID_TS_BUTTON", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AGI_ID_TS_BUTTON, "SAP Diag Support Bit AGI_ID_TS_BUTTON",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST,
			{ "Support Bit NO_FOCUS_ON_LIST", "sapdiag.diag.supportbits.NO_FOCUS_ON_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NO_FOCUS_ON_LIST, "SAP Diag Support Bit NO_FOCUS_ON_LIST",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_FIORI_MODE,
			{ "Support Bit FIORI_MODE", "sapdiag.diag.supportbits.FIORI_MODE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FIORI_MODE, "SAP Diag Support Bit FIORI_MODE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE,
			{ "Support Bit CONNECT_CHECK_DONE", "sapdiag.diag.supportbits.CONNECT_CHECK_DONE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONNECT_CHECK_DONE, "SAP Diag Support Bit CONNECT_CHECK_DONE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE,
			{ "Support Bit MSGINFO_WITH_CODEPAGE", "sapdiag.diag.supportbits.MSGINFO_WITH_CODEPAGE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MSGINFO_WITH_CODEPAGE, "SAP Diag Support Bit MSGINFO_WITH_CODEPAGE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AGI_ID,
			{ "Support Bit AGI_ID", "sapdiag.diag.supportbits.AGI_ID", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AGI_ID, "SAP Diag Support Bit AGI_ID",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_AGI_ID_TC,
			{ "Support Bit AGI_ID_TC", "sapdiag.diag.supportbits.AGI_ID_TC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_AGI_ID_TC, "SAP Diag Support Bit AGI_ID_TC",
			HFILL }},

		{ &hf_SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS,
			{ "Support Bit FIORI_TOOLBARS", "sapdiag.diag.supportbits.FIORI_TOOLBARS", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_FIORI_TOOLBARS, "SAP Diag Support Bit FIORI_TOOLBARS",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE,
			{ "Support Bit OBJECT_NAMES_ENFORCE", "sapdiag.diag.supportbits.OBJECT_NAMES_ENFORCE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_OBJECT_NAMES_ENFORCE, "SAP Diag Support Bit OBJECT_NAMES_ENFORCE",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3,
			{ "Support Bit MESDUMMY_FLAGS_2_3", "sapdiag.diag.supportbits.MESDUMMY_FLAGS_2_3", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_MESDUMMY_FLAGS_2_3, "SAP Diag Support Bit MESDUMMY_FLAGS_2_3",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_NWBC,
			{ "Support Bit NWBC", "sapdiag.diag.supportbits.NWBC", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_NWBC, "SAP Diag Support Bit NWBC",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_CONTAINER_LIST,
			{ "Support Bit CONTAINER_LIST", "sapdiag.diag.supportbits.CONTAINER_LIST", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_CONTAINER_LIST, "SAP Diag Support Bit CONTAINER_LIST",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR,
			{ "Support Bit GUI_SYSTEM_COLOR", "sapdiag.diag.supportbits.GUI_SYSTEM_COLOR", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GUI_SYSTEM_COLOR, "SAP Diag Support Bit GUI_SYSTEM_COLOR",
			HFILL }},
		{ &hf_SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE,
			{ "Support Bit GROUPBOX_WITHOUT_BOTTOMLINE", "sapdiag.diag.supportbits.GROUPBOX_WITHOUT_BOTTOMLINE", FT_BOOLEAN, 8, NULL, SAPDIAG_SUPPORT_BIT_GROUPBOX_WITHOUT_BOTTOMLINE, "SAP Diag Support Bit GROUPBOX_WITHOUT_BOTTOMLINE",
			HFILL }},

		/* Dynt Atom */
		{ &hf_sapdiag_item_dynt_atom,
			{ "Dynt Atom", "sapdiag.item.value.dyntatom", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Dynt Atom",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item,
			{ "Dynt Atom Item", "sapdiag.item.value.dyntatom.item", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Dynt Atom Item",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_etype,
			{ "Dynt Atom Item Type", "sapdiag.item.value.dyntatom.item.type", FT_UINT8, BASE_DEC, VALS(sapdiag_item_dynt_atom_item_etype_vals), 0x0, "SAP Dynt Atom Item Type",
			HFILL }},

		/* Dynt Atom Attribute Flags */
		{ &hf_sapdiag_item_dynt_atom_item_attr,
			{ "Dynt Atom Item Attributes", "sapdiag.item.value.dyntatom.item.attr", FT_UINT8, BASE_HEX, NULL, 0x0, "SAP Dynt Atom Item Attribute",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_COMBOSTYLE,
			{ "Dynt Atom Item Attribute Combo Style", "sapdiag.item.value.dyntatom.item.attr.COMBOSTYLE", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_COMBOSTYLE, "SAP Dynt Atom Item Attribute Combo Style",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_YES3D,
			{ "Dynt Atom Item Attribute Yes3D", "sapdiag.item.value.dyntatom.item.attr.YES3D", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_YES3D, "SAP Dynt Atom Item Attribute Yes3D",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROPFONT,
			{ "Dynt Atom Item Attribute Prop Font", "sapdiag.item.value.dyntatom.item.attr.PROPFONT", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_PROPFONT, "SAP Dynt Atom Item Attribute Prop Font",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_MATCHCODE,
			{ "Dynt Atom Item Attribute Match Code", "sapdiag.item.value.dyntatom.item.attr.MATCHCODE", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_MATCHCODE, "SAP Dynt Atom Item Attribute Match Code",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_JUSTRIGHT,
			{ "Dynt Atom Item Attribute Just Right", "sapdiag.item.value.dyntatom.item.attr.JUSTRIGHT", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_JUSTRIGHT, "SAP Dynt Atom Item Attribute Just Right",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INTENSIFY,
			{ "Dynt Atom Item Attribute Intensify", "sapdiag.item.value.dyntatom.item.attr.INTENSIFY", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_INTENSIFY, "SAP Dynt Atom Item Attribute Intensify",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_INVISIBLE,
			{ "Dynt Atom Item Attribute Invisible", "sapdiag.item.value.dyntatom.item.attr.INVISIBLE", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_INVISIBLE, "SAP Dynt Atom Item Attribute Invisible",
			HFILL }},
		{ &hf_sapdiag_item_dynt_atom_item_attr_DIAG_BSD_PROTECTED,
			{ "Dynt Atom Item Attribute Protected", "sapdiag.item.value.dyntatom.item.attr.PROTECTED", FT_BOOLEAN, 8, NULL, SAPDIAG_ATOM_ATTR_DIAG_BSD_PROTECTED, "SAP Dynt Atom Item Attribute Protected",
			HFILL }},

		/* Control Properties fields */
		{ &hf_sapdiag_item_control_properties_id,
			{ "Control Properties ID", "sapdiag.item.value.controlproperties.id", FT_UINT16, BASE_HEX, VALS(sapdiag_item_control_properties_id_vals), 0x0, "SAP Control Properties ID",
			HFILL }},
		{ &hf_sapdiag_item_control_properties_value,
			{ "Control Properties Value", "sapdiag.item.value.controlproperties.value", FT_NONE, BASE_NONE, NULL, 0x0, "SAP Control Properties Value",
			HFILL }},

		/* UI Event Source fields */
		{ &ht_sapdiag_item_ui_event_event_type,
			{ "UI Event Source Type", "sapdiag.item.value.uievent.type", FT_UINT16, BASE_DEC, VALS(sapdiag_item_ui_event_event_type_vals), 0x0, "SAP UI Event Source Type", HFILL }},
		{ &ht_sapdiag_item_ui_event_control_type,
			{ "UI Event Control Type", "sapdiag.item.value.uievent.control", FT_UINT16, BASE_DEC, VALS(sapdiag_item_ui_event_control_type_vals), 0x0, "SAP UI Event Source Control Type", HFILL }},

		{ &ht_sapdiag_item_ui_event_valid,
			{ "UI Event Valid", "sapdiag.item.value.uievent.valid", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP UI Event Source Valid", HFILL }},
		{ &ht_sapdiag_item_ui_event_valid_MENU_POS,
			{ "UI Event Valid Menu Pos", "sapdiag.item.value.uievent.valid.MENU_POS", FT_BOOLEAN, 8, NULL, SAPDIAG_UI_EVENT_VALID_FLAG_MENU_POS, "SAP UI Event Source Valid Menu Pos", HFILL }},
		{ &ht_sapdiag_item_ui_event_valid_CONTROL_POS,
			{ "UI Event Valid Control Pos", "sapdiag.item.value.uievent.valid.CONTROL_POS", FT_BOOLEAN, 8, NULL, SAPDIAG_UI_EVENT_VALID_FLAG_CONTROL_POS, "SAP UI Event Source Valid Control Pos", HFILL }},
		{ &ht_sapdiag_item_ui_event_valid_NAVIGATION_DATA,
			{ "UI Event Valid Navigation Data", "sapdiag.item.value.uievent.valid.NAVIGATION_DATA", FT_BOOLEAN, 8, NULL, SAPDIAG_UI_EVENT_VALID_FLAG_NAVIGATION_DATA, "SAP UI Event Source Valid Navigation Data", HFILL }},
		{ &ht_sapdiag_item_ui_event_valid_FUNCTIONKEY_DATA,
			{ "UI Event Valid Function Key Data", "sapdiag.item.value.uievent.valid.FUNCTIONKEY_DATA", FT_BOOLEAN, 8, NULL, SAPDIAG_UI_EVENT_VALID_FLAG_FUNCTIONKEY_DATA, "SAP UI Event Source Valid Function Key Data", HFILL }},

		{ &ht_sapdiag_item_ui_event_control_row,
			{ "UI Event Source Control Row", "sapdiag.item.value.uievent.controlrow", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP UI Event Source Control Row", HFILL }},
		{ &ht_sapdiag_item_ui_event_control_col,
			{ "UI Event Source Control Column", "sapdiag.item.value.uievent.controlcol", FT_UINT16, BASE_DEC, NULL, 0x0, "SAP UI Event Source Control Column", HFILL }},
		{ &ht_sapdiag_item_ui_event_navigation_data,
			{ "UI Event Source Navigation Data", "sapdiag.item.value.uievent.navigationdata", FT_UINT32, BASE_DEC, VALS(sapdiag_item_ui_event_navigation_data_vals), 0x0, "SAP UI Event Source Navigation Data", HFILL }},
		{ &ht_sapdiag_item_ui_event_data,
			{ "UI Event Source Data", "sapdiag.item.value.uievent.data", FT_UINT32, BASE_DEC, NULL, 0x0, "SAP UI Event Source Data", HFILL }},
		{ &ht_sapdiag_item_ui_event_container_nrs,
			{ "UI Event Source Container IDs Numbers", "sapdiag.item.value.uievent.containernrs", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP UI Event Source Container IDs Numbers", HFILL }},
		{ &ht_sapdiag_item_ui_event_container,
			{ "UI Event Source Container ID", "sapdiag.item.value.uievent.container", FT_UINT8, BASE_DEC, NULL, 0x0, "SAP UI Event Source Container ID", HFILL }},

		/* Menu Entries */
		{ &hf_sapdiag_item_menu_entry,
			{ "Menu Entry", "sapdiag.item.value.menu", FT_NONE, BASE_NONE, NULL, 0x0, NULL,
			HFILL }},

	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sapdiag
	};

	/* Register the expert info */
	static ei_register_info ei[] = {
		{ &ei_sapdiag_item_unknown, { "sapdiag.item.unknown", PI_UNDECODED, PI_WARN, "The Diag Item has a unknown type that is not dissected", EXPFILL }},
		{ &ei_sapdiag_item_partial, { "sapdiag.item.unknown", PI_UNDECODED, PI_WARN, "The Diag Item is dissected partially", EXPFILL }},
		{ &ei_sapdiag_item_unknown_length, { "sapdiag.item.length.unknown", PI_UNDECODED, PI_WARN, "Diag Type of unknown length", EXPFILL }},
		{ &ei_sapdiag_item_offset_invalid, { "sapdiag.item.offset.invalid", PI_MALFORMED, PI_ERROR, "Invalid offset", EXPFILL }},
		{ &ei_sapdiag_item_length_invalid, { "sapdiag.item.length.invalid", PI_MALFORMED, PI_WARN, "Item length is invalid", EXPFILL }},
		{ &ei_sapdiag_atom_item_unknown, { "sapdiag.item.value.dyntatom.item.unknown", PI_UNDECODED, PI_WARN, "The Diag Atom has a unknown type that is not dissected", EXPFILL }},
		{ &ei_sapdiag_atom_item_partial, { "sapdiag.item.value.dyntatom.item.unknown", PI_UNDECODED, PI_WARN, "The Diag Atom is dissected partially", EXPFILL }},
		{ &ei_sapdiag_atom_item_malformed, { "sapdiag.item.value.dyntatom.invalid", PI_MALFORMED, PI_WARN, "The Diag Atom is malformed", EXPFILL }},
		{ &ei_sapdiag_dynt_focus_more_cont_ids, { "sapdiag.item.value.uievent.containernrs.invalid", PI_MALFORMED, PI_WARN, "Number of Container IDs is invalid", EXPFILL }},
		{ &ei_sapdiag_password_field, { "sapdiag.item.value.dyntatom.item.password", PI_SECURITY, PI_WARN, "Password field?", EXPFILL }},
		{ &ei_sapdiag_invalid_decompresssion, { "sapdiag.header.compression.invalid", PI_MALFORMED, PI_WARN, "Decompression of payload failed", EXPFILL }},
		{ &ei_sapdiag_invalid_decompress_length, { "sapdiag.header.compression.uncomplength.invalid", PI_MALFORMED, PI_WARN, "The uncompressed payload length differs with the reported length", EXPFILL }},
	};

	module_t *sapdiag_module;
	expert_module_t* sapdiag_expert;

	/* Register the protocol */
	proto_sapdiag = proto_register_protocol("SAP Diag Protocol", "SAPDIAG", "sapdiag");

	proto_register_field_array(proto_sapdiag, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	sapdiag_expert = expert_register_protocol(proto_sapdiag);
	expert_register_field_array(sapdiag_expert, ei, array_length(ei));

	register_dissector("sapdiag", dissect_sapdiag, proto_sapdiag);

	/* Register the preferences */
	sapdiag_module = prefs_register_protocol(proto_sapdiag, proto_reg_handoff_sapdiag);

	range_convert_str(wmem_epan_scope(), &global_sapdiag_port_range, SAPDIAG_PORT_RANGE, MAX_TCP_PORT);
	prefs_register_range_preference(sapdiag_module, "tcp_ports", "SAP Diag Protocol TCP port numbers", "Port numbers used for SAP Diag Protocol (default " SAPDIAG_PORT_RANGE ")", &global_sapdiag_port_range, MAX_TCP_PORT);

	prefs_register_bool_preference(sapdiag_module, "decompress", "Decompress SAP Diag Protocol message payloads", "Whether the SAP Diag Protocol dissector should decompress message's payloads.", &global_sapdiag_decompress);

	prefs_register_bool_preference(sapdiag_module, "rfc_dissection", "Dissect embeded SAP RFC calls", "Whether the SAP Diag Protocol dissector should call the SAP RFC dissector for embeded RFC calls", &global_sapdiag_rfc_dissection);

	prefs_register_bool_preference(sapdiag_module, "snc_dissection", "Dissect SAP SNC frames", "Whether the SAP Diag Protocol dissector should call the SAP SNC dissector for SNC frames", &global_sapdiag_snc_dissection);

	prefs_register_bool_preference(sapdiag_module, "highlight_unknown_items", "Highlight unknown SAP Diag Items", "Whether the SAP Diag Protocol dissector should highlight unknown SAP Diag item (migth be noise and generate a lot of expert warnings)", &global_sapdiag_highlight_items);

}

/**
 * Helpers for dealing with the port range
 */
static void range_delete_callback (guint32 port, gpointer ptr _U_)
{
	dissector_delete_uint("sapni.port", port, sapdiag_handle);
}

static void range_add_callback (guint32 port, gpointer ptr _U_)
{
	dissector_add_uint("sapni.port", port, sapdiag_handle);
}

/**
 * Register Hand off for the SAP Diag Protocol
 */
void
proto_reg_handoff_sapdiag(void)
{
	static range_t *sapdiag_port_range;
	static gboolean initialized = FALSE;

	if (!initialized) {
		sapdiag_handle = create_dissector_handle(dissect_sapdiag, proto_sapdiag);
		initialized = TRUE;
	} else {
		range_foreach(sapdiag_port_range, range_delete_callback, NULL);
		wmem_free(wmem_epan_scope(), sapdiag_port_range);
	}

	sapdiag_port_range = range_copy(wmem_epan_scope(), global_sapdiag_port_range);
	range_foreach(sapdiag_port_range, range_add_callback, NULL);
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
