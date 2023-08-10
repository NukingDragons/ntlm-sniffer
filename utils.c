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

#ifndef NTLM_RAW_ONLY
int8_t fetch_interface(char interface[IF_NAMESIZE + 1])
{
	int8_t r = 0;

	if (interface)
	{
		// Fetch the interface address structures
		struct ifaddrs *addrs = 0;
		getifaddrs(&addrs);

		if (addrs)
		{
			// Find ANY interface name
			for (struct ifaddrs *a = addrs; a; a = a->ifa_next)
			{
				if (strlen(a->ifa_name))
				{
					memset(interface, 0, IF_NAMESIZE + 1);
					strncpy(interface, a->ifa_name, IF_NAMESIZE);
					break;
				}
			}

			freeifaddrs(addrs);
		}
		else
			r = -2;
	}
	else
		r = -1;

	return r;
}

// Opens a socket on an interface
int32_t open_raw_socket(int32_t *mtu)
{
	int32_t r = 0;
	int32_t sock = 0;

		char interface[IF_NAMESIZE + 1];
		r = fetch_interface(interface);

		// Create a raw socket and bind it to an interface
		if (!r
		&& (sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))
		&& !setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, IF_NAMESIZE + 1))
		{
			if (mtu)
			{
				*mtu = 0;

				struct ifreq req;
				memset(&req, 0, sizeof(struct ifreq));
				strncpy(req.ifr_name, interface, IF_NAMESIZE);

				if (!ioctl(sock, SIOCGIFMTU, &req))
					*mtu = req.ifr_mtu;
				else
					r = -2;
			}
		}
		else
			r = -1;

	// An error occured
	if (r < 0
	&& sock)
		close(sock);
	else
		r = sock;

	return r;
}

int8_t apply_bpf(int32_t sock, struct sock_filter *filter, uint64_t filter_size)
{
	// Return an error if the filter doesnt apply
	int8_t r = -2;

	if (sock
	&&  filter
	&&  filter_size)
	{
		struct sock_fprog filter_prog;
		memset(&filter_prog, 0, sizeof(struct sock_fprog));

		filter_prog.len = filter_size;
		filter_prog.filter = filter;

		// Successfully applied the filter
		if (!setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog, sizeof(filter_prog)))
			r = 0;
	}
	else
		r = -1;

	return r;
}
#endif

char *utf16le_to_ascii(uint8_t *utf16le, uint64_t len)
{
	char *r = 0;

	if (utf16le && len)
	{
		r = malloc((len + 2) / 2);

		if (r)
		{
			memset(r, 0, (len + 2) / 2);

			for (uint64_t i = 0,j = 0; i <= (len - 2); i += 2,j++)
				r[j] = utf16le[i];
		}
	}

	return r;
}

char *hexlify(uint8_t *data, uint64_t len)
{
	char *r = 0;

	if (data && len)
	{
		r = malloc((len * 2) + 1);

		if (r)
		{
			memset(r, 0, (len * 2) + 1);

			uint8_t byte = 0;
			for (uint64_t i = 0,j = 0; i < len; i++,j += 2)
			{
				byte = (data[i] & 0xf0) >> 4;

				if (byte >= 0x0 && byte <= 0x9)
					r[j] = byte + '0';
				else if (byte >= 0x0a && byte <= 0x0f)
					r[j] = (byte - 0xa) + 'a';

				byte = (data[i] & 0x0f);

				if (byte >= 0x0 && byte <= 0x9)
					r[j + 1] = byte + '0';
				else if (byte >= 0x0a && byte <= 0x0f)
					r[j + 1] = (byte - 0xa) + 'a';

			}
		}
	}

	return r;
}

uint8_t *base64_decode(char *base64)
{
	uint8_t *r = 0;

	// Characters in the base64
	static char base64_chars[] =
	{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
	};

	if (base64)
	{
		uint64_t len = strlen(base64) * 3 / 4;

		r = malloc(len);

		if (r)
		{
			memset(r, 0, len);

			char buffer[4];

			uint8_t bufindex = 0;
			uint8_t charsindex = 0;
			uint64_t rindex = 0;

			for (uint64_t i = 0; base64[i] != 0; i++)
			{
				// Get the index into the base64_chars array
				for (charsindex = 0; charsindex < 64 && base64_chars[charsindex] != base64[i]; charsindex++);
				
				// Store the current index
				buffer[bufindex++] = charsindex;

				// Decode
				if (bufindex == 4)
				{
					bufindex = 0;

					r[rindex++] = (buffer[0] << 2) + (buffer[1] >> 4);

					if (buffer[2] != 64)
						r[rindex++] = (buffer[1] << 4) + (buffer[2] >> 2);

					if (buffer[3] != 64)
						r[rindex++] = (buffer[2] << 6) + buffer[3];
				}
			}
		}
	}

	return r;
}
