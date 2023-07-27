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
#include <errno.h>
#include <signal.h>

#ifndef NAME
#define NAME "ntlm-sniffer"
#endif

struct args_t
{
	uint8_t help:1;
	uint8_t error:1;

	char *output;
};

#define check_arg(l, s, arg)		(!strcmp(l, arg) || !strcmp(s, arg))

struct args_t parse_args(uint64_t argc, char **argv)
{
	struct args_t args;

	memset(&args, 0, sizeof(struct args_t));

	if (argc >= 1
	&&  argv)
	{
		// Start at 1
		for (uint64_t i = 1; i < argc; i++)
		{
			if (check_arg("--output", "-o", argv[i])
			     &&  i < argc)
				args.output = argv[++i];
			else // Includes --help/-h
			{
				args.help = 1;
				break;
			}
		}
	}
	else
		args.error = 1;

	return args;
}

void usage(char *name)
{
	char *n = (name) ? name : NAME;

	printf("Usage: %s [options]\n"
	       "Options:\n"
	       "\t--help,-h\t\tDisplays this help menu\n"
	       "\t--output,-o\t\tName of the file to drop hashes onto. (Default is stdout)\n", name);
}

// Example Callback
int8_t callback(struct netntlm_t *netntlm, void *args)
{
	int8_t r = 0;

	// Default to stdout
	FILE *fd = stdout;

	// If specified, set the fd
	if (args)
	{
		fd = fopen((char *) args, "a");

		if (!fd)
			r = -1;
	}

	if (!r)
	{
		fprintf(fd, "%s:%hu -> %s:%hu\n%s\n", netntlm->src_ip, netntlm->src_port, netntlm->dst_ip, netntlm->dst_port,
							     netntlm->complete_hash);

		if (fd && fd != stdout)
			fclose(fd);
	}

	return r;
}

// Socket for the connection
// Only reason this is global is for the handle_signal function below
static int32_t sock = 0;

void handle_signal(int sig)
{
	// Kill the socket for the handle_ntlmssp connection
	// So that everything is freed properly
	close(sock);
}

int32_t main(uint64_t argc, char **argv)
{
	struct args_t args = parse_args(argc, argv);

	if (!args.error && !args.help)
	{
		int32_t mtu = 0;
		sock = open_raw_socket(&mtu);
		signal(SIGINT, handle_signal);

		if (sock && handle_ntlmssp(sock, mtu, 1, 20, callback, args.output) < 0)
			printf("Error: %d - \"%s\"\n", errno, strerror(errno));

		close(sock);
	}
	else
		usage(argv[0]);

	return args.error;
}
