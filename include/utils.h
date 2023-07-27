/*
 * Passively collect NetNTLM hashes from unencrypted SMBv1, SMBv2, and HTTP traffic
 * Copyright (C) 2023  Sabrina Andersen (NukingDragons)
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef NTLMSSP_RAW_ONLY
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <ifaddrs.h>

// Opens a socket on an interface
int32_t open_raw_socket(int32_t *mtu);

int8_t apply_bpf(int32_t sock, struct sock_filter *filter, uint64_t filter_size);
#endif

char *utf16le_to_ascii(uint8_t *utf16le, uint64_t len);

char *hexlify(uint8_t *data, uint64_t len);

uint8_t *base64_decode(char *base64);
