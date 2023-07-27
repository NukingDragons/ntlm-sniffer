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
#ifndef NTLMSSP_H_INCLUDED
#define NTLMSSP_H_INCLUDED

#include <stdint.h>

// This will hold the relevant information for handling the NetNTLM hashes
struct netntlm_t
{
	// These should only be populated while gathering data for the hash
	// Once it's been completed, it should be removed from the list
	struct netntlm_t *next;
	struct netntlm_t *prev;

	// Timestamp when added to the stack
	// Used for cleaning up based on a timeout
	uint64_t timestamp;

	// Sequence number to keep track of the handshake
	uint32_t seq;

	// Fields of the hash that are needed
	char *domain;
	char *username;
	char *challenge_str;
	char *proof_str;
	char *response_str;

	// Raw fields of the hash
	uint64_t challenge;
	uint8_t proof[16];

	uint8_t *response;
	uint64_t response_size;

	// Other useful data
	char src_ip[16];
	char dst_ip[16];

	uint16_t src_port;
	uint16_t dst_port;

	// The completed hash string
	char *complete_hash;
};

// Callback function type
typedef int8_t (*ntlmssp_callback_t)(struct netntlm_t *netntlm, void *args);

// Raw functions for managing the packets
// This will create a handle for netntlmssp
void *create_ntlmssp_handle(void);

// Cleanup the stack given a timeout
void clean_ntlmssp_handle(void *handle, uint64_t seconds);

// Free the created handle
void free_ntlmssp_handle(void *handle);

// Handle the ntlmssp packet. This is non-blocking and the caller must destroy the handle at the end
int8_t handle_ntlmssp_raw(void *handle, uint8_t *buf, int32_t len, ntlmssp_callback_t callback, void *callback_args);

#ifndef NTLM_RAW_ONLY
// Pre-made BPF that's used in the below function
extern struct sock_filter ntlmssp_bpf[];

// Blocking loop fetching data from the interface using a socket, expecting a raw socket
// Calling the callback whenever a NetNTLM hash has been recovered
int8_t handle_ntlmssp(int32_t sock, int32_t mtu, uint8_t use_bpf, uint64_t stack_timeout, ntlmssp_callback_t callback, void *callback_args);
#endif

#endif
