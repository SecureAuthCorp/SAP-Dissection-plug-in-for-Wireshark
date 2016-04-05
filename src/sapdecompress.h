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

#ifndef __PACKET_SAPDECOMPRESS_H__
#define __PACKET_SAPDECOMPRESS_H__

#include <epan/value_string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Return code for memory errors */
#define CS_E_MEMORY_ERROR -99

/* SAP Decompression routine return codes */
static const value_string decompress_return_code_vals[] = {
	{ 3, "CS_END_INBUFFER (End of input buffer)" },
	{ 2, "CS_END_OUTBUFFER (End of output buffer)" },
	{ 1, "CS_END_OF_STREAM (End of data)" },
	{ 0, "CS_OK" },
	{ -1, "CS_IEND_OF_STREAM (End of data (internal) )" },
	{ -2, "CS_IEND_OUTBUFFER (End of output buffer)" },
	{ -3, "CS_IEND_INBUFFER (End of input buffer)" },
	{ -10, "CS_E_OUT_BUFFER_LEN (Invalid output length)" },
	{ -11, "CS_E_IN_BUFFER_LEN (Invalid input length)" },
	{ -12, "CS_E_NOSAVINGS" },
	{ -13, "CS_E_INVALID_SUMLEN (Invalid len of stream)" },
	{ -14, "CS_E_IN_EQU_OUT (inbuf == outbuf)" },
	{ -15, "CS_E_INVALID_ADDR (inbuf == NULL,outbuf == NULL)" },
	{ -19, "CS_E_FATAL (Internal Error !)" },
	{ -20, "CS_E_BOTH_ZERO (inlen = outlen = 0)" },
	{ -21, "CS_E_UNKNOWN_ALG (unknown algorithm)" },
	{ -22, "CS_E_UNKNOWN_TYPE (unknown type)" },
	{ -50, "CS_E_FILENOTCOMPRESSED (Input not compressed)" },
	{ -51, "CS_E_MAXBITS_TOO_BIG (maxbits to large)" },
	{ -52, "CS_E_BAD_HUF_TREE (bad hufman tree)" },
	{ -53, "CS_E_NO_STACKMEM (no stack memory in decomp)" },
	{ -54, "CS_E_INVALIDCODE (invalid code)" },
	{ -55, "CS_E_BADLENGTH (bad lengths)" },
	{ -60, "CS_E_STACK_OVERFLOW (stack overflow in decomp)" },
	{ -61, "CS_E_STACK_UNDERFLOW (stack underflow in decomp)" },
	{CS_E_MEMORY_ERROR, "CS_E_MEMORY_ERROR (custom error error)" }
};

int decompress_packet (const guint8 *in, gint in_length, guint8 *out, guint *out_length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_SAPDECOMPRESS_H__ */
