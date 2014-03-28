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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

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
	class CsObjectInt o;
	SAP_INT bytes_read, bytes_decompressed;
	int rt;
	SAP_BYTE *bufin, *bufout;

#ifdef DEBUG
	printf("sapdecompress.cpp: Decompressing (%d bytes, reported length of %d bytes)...\n", in_length, *out_length);
#endif

	/* Allocate buffers */
	bufin = (SAP_BYTE*) malloc(in_length);
	if (!bufin){
		return (CS_E_MEMORY_ERROR);
	}

	bufout = (SAP_BYTE*) malloc(*out_length);
	if (!bufout){
		free(bufin);
		return (CS_E_MEMORY_ERROR);
	}

	/* Copy the in parameter into the buffer */
	for (int i = 0; i < in_length; i++) {
		bufin[i] = (SAP_BYTE) in[i];
	}

	rt=o.CsDecompr(bufin, in_length, bufout, *out_length, CS_INIT_DECOMPRESS, &bytes_read, &bytes_decompressed);

#ifdef DEBUG
	printf("sapdecompress.cpp: Return code %d (%s) (%d bytes)\n", rt, error_string(rt), bytes_decompressed);
#endif

	/* Succesfull decompression */
	if (rt == CS_END_OF_STREAM || rt == CS_END_INBUFFER || rt == CS_END_OUTBUFFER) {
		*out_length = bytes_decompressed;

	    /* Copy the buffer in the out parameter. The out parameter should be already allocated. */
	    for (int i = 0; i < bytes_decompressed; i++)
		    out[i] = (guint8) bufout[i];

#ifdef DEBUG_TRACE
        printf("sapdecompress.cpp: Out buffer:\n");
	    hexdump(out, bytes_decompressed);
#endif
	/* Failed decompression or memory error */
	} else
		*out_length = 0;

	/* Free the buffers */
	free (bufin); free (bufout);

#ifdef DEBUG
	printf("sapdecompress.cpp: Out Length: %d\n", *out_length);
#endif

	return (rt);
};

