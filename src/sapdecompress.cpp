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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "sapdecompress.h"

#include "hpa101saptype.h"
#include "hpa104CsObject.h"
#include "hpa106cslzc.h"
#include "hpa107cslzh.h"
#include "hpa105CsObjInt.h"

/* #define DEBUG  # Enable this macro if you want some debugging information on the (de)compression functions */
/* #define DEBUG_TRACE # Enable this macro if you want detailed debugging information (hexdumps) on the (de)compression functions */

/* Returns an error strings for compression library return codes */
const char *error_string(int return_code){
	switch (return_code){
	case CS_IEND_OF_STREAM: return ("end of data (internal)");
	case CS_IEND_OUTBUFFER: return ("end of output buffer");
	case CS_IEND_INBUFFER: return ("end of input buffer");
	case CS_E_OUT_BUFFER_LEN: return ("invalid output length");
	case CS_E_IN_BUFFER_LEN: return ("invalid input length");
	case CS_E_NOSAVINGS: return ("no savings");
	case CS_E_INVALID_SUMLEN: return ("invalid len of stream");
	case CS_E_IN_EQU_OUT: return ("inbuf == outbuf");
	case CS_E_INVALID_ADDR: return ("inbuf == NULL,outbuf == NULL");
	case CS_E_FATAL: return ("internal error !");
	case CS_E_BOTH_ZERO: return ("inlen = outlen = 0");
	case CS_E_UNKNOWN_ALG: return ("unknown algorithm");
	case CS_E_UNKNOWN_TYPE: return ("unknown type");
	/* for decompress */
	case CS_E_FILENOTCOMPRESSED: return ("input not compressed");
	case CS_E_MAXBITS_TOO_BIG: return ("maxbits to large");
	case CS_E_BAD_HUF_TREE: return ("bad hufman tree");
	case CS_E_NO_STACKMEM: return ("no stack memory in decomp");
	case CS_E_INVALIDCODE: return ("invalid code");
	case CS_E_BADLENGTH: return ("bad lengths");
	case CS_E_STACK_OVERFLOW: return ("stack overflow in decomp");
	case CS_E_STACK_UNDERFLOW: return ("stack underflow in decomp");
	/* only Windows */
	case CS_NOT_INITIALIZED: return ("storage not allocated");
	/* non error return codes */
	case CS_END_INBUFFER: return ("end of input buffer");
	case CS_END_OUTBUFFER: return ("end of output buffer");
	case CS_END_OF_STREAM: return ("end of data");
	/* unknown error */
	default: return ("unknown error");
	}
}

void hexdump(guint8 *address, gint size)
{
	gint i = 0, j = 0, offset = 0;
	printf("[%08x] ", offset);
	for (; i<size; i++){
		j++; printf("%02x ", address[i]);
		if (j==8) printf(" ");
		if (j==16){
			offset+=j; printf("\n[%08x] ", offset); j=0;
		}
	}
	printf("\n");
}

int decompress_packet (const guint8 *in, gint in_length, guint8 *out, guint *out_length)
{
	class CsObjectInt csObject;
	int rt = 0, finished = false;
	SAP_BYTE *bufin = NULL, *bufin_pos = NULL, *bufout = NULL, *bufout_pos = NULL;
	SAP_INT bufin_length = 0, bufin_rest = 0, bufout_length = 0, bufout_rest = 0, data_length = 0, bytes_read = 0, bytes_decompressed = 0, total_decompressed = 0;

#ifdef DEBUG
	printf("sapdecompress.cpp: Decompressing (%d bytes, reported length of %d bytes)...\n", in_length, *out_length);
#endif

	/* Check for invalid inputs */
	if (in == NULL)
		return (CS_E_INVALID_ADDR);
	if (in_length <= 0)
		return (CS_E_IN_BUFFER_LEN);
	if (out == NULL)
		return (CS_E_INVALID_ADDR);
	if (*out_length <= 0)
		return (CS_E_OUT_BUFFER_LEN);

	/* Allocate buffers */
	bufin_length = bufin_rest = (SAP_INT)in_length;
	bufin = bufin_pos = (SAP_BYTE*) malloc(in_length);
	if (!bufin){
		return (CS_E_MEMORY_ERROR);
	}

	/* Copy the in parameter into the buffer */
	for (int i = 0; i < in_length; i++) {
		bufin[i] = (SAP_BYTE) in[i];
	}

	/* Initialize and obtain the reported uncompressed data length */
	rt = csObject.CsInitDecompr(bufin);
	if (rt != 0){
#ifdef DEBUG
		printf("sapdecompress.cpp: Initialization failed !\n");
#endif
		free(bufin);
		*out_length = 0;
		return (rt);
	}

	/* Check the length in the header vs the reported one */
	data_length = csObject.CsGetLen(bufin);
	if (data_length != (SAP_INT)*out_length){
#ifdef DEBUG
		printf("sapdecompress.cpp: Length reported (%d) doesn't match with the one in the header (%d)\n", *out_length, data_length);
#endif
		free(bufin);
		*out_length = 0;
		return (CS_E_OUT_BUFFER_LEN);
	}

	/* Advance the buffer pointer as we've already read the header */
	bufin_pos += CS_HEAD_SIZE;

#ifdef DEBUG
	printf("sapdecompress.cpp: Initialized, reported length in header: %d bytes\n", data_length);
#endif

	/* Allocate the output buffer. We use the reported output size
	 * as the output buffer size.
	 */
	bufout_length = bufout_rest = *out_length;
	bufout = bufout_pos = (SAP_BYTE*) malloc(bufout_length);
	if (!bufout){
		*out_length = 0;
		free(bufin);
		return (CS_E_MEMORY_ERROR);
	}
	memset(bufout, 0, bufout_length);

#ifdef DEBUG_TRACE
	printf("sapdecompress.cpp: Input buffer %p (%d bytes), output buffer %p (%d bytes)\n", bufin, bufin_length, bufout, bufout_length);
#endif

	while (finished == false && bufin_rest > 0 && bufout_rest > 0) {

#ifdef DEBUG_TRACE
		printf("sapdecompress.cpp: Input position %p (rest %d bytes), output position %p\n", bufin_pos, bufin_rest, bufout_pos);
#endif
		rt = csObject.CsDecompr(bufin_pos, bufin_rest, bufout_pos, bufout_rest, 0, &bytes_read, &bytes_decompressed);

#ifdef DEBUG
		printf("sapdecompress.cpp: Return code %d (%s) (%d bytes read, %d bytes decompressed)\n", rt, error_string(rt), bytes_read, bytes_decompressed);
#endif

		/* Successful decompression, we've finished with the stream */
		if (rt == CS_END_OF_STREAM){
			finished = true;
		}
		/* Some error occurred */
		if (rt != CS_END_INBUFFER && rt != CS_END_OUTBUFFER){
			finished = true;
		}

		/* Advance the input buffer */
		bufin_pos += bytes_read;
		bufin_rest -= bytes_read;
		/* Advance the output buffer */
		bufout_pos += bytes_decompressed;
		bufout_rest -= bytes_decompressed;
		total_decompressed += bytes_decompressed;

	}

	/* Successful decompression */
	if (rt == CS_END_OF_STREAM) {
		*out_length = total_decompressed;

		/* Copy the buffer in the out parameter */
		for (int i = 0; i < total_decompressed; i++)
			(out)[i] = (char) bufout[i];

#ifdef DEBUG_TRACE
		    printf("sapdecompress.cpp: Out buffer:\n");
			hexdump(out, total_decompressed);
#endif

	}

	/* Free the buffers */
	free(bufin); free(bufout);

#ifdef DEBUG
	printf("sapdecompress.cpp: Out Length: %d\n", *out_length);
#endif

	return (rt);
};

