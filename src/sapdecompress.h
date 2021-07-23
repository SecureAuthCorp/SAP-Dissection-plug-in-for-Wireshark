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

#ifndef __PACKET_SAPDECOMPRESS_H__
#define __PACKET_SAPDECOMPRESS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Return code for memory errors */
#define CS_E_MEMORY_ERROR -99

/* SAP Decompression routine return codes */
const char *decompress_error_string(int return_code);

/* SAP Decompression routine */
int decompress_packet(const guint8 *in, gint in_length, guint8 *out, guint *out_length);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __PACKET_SAPDECOMPRESS_H__ */
