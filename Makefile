# Passively collect NetNTLM hashes from unencrypted SMBv1, SMBv2, and HTTP traffic
# Copyright (C) 2023  Sabrina Andersen (NukingDragons)
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

MAKE := make
CC := gcc
AR := ar
CFLAGS := -Iinclude -fPIC

NTLMSSP-SRCS = utils.c \
	       ntlmssp.c

NTLM-SRCS = ntlm-sniffer.c

# PHONY Rules

.PHONY: all raw clean shared raw-shared static raw-static exe exe-static

all: shared static exe exe-static

raw: clean raw-shared raw-static

clean:
	find . -name "*.o" -exec rm {} \; || true
	rm ntlm-sniffer ntlm-sniffer-static libntlmsniffer.so libntlmsniffer.a 2>/dev/null || true

shared: libntlmsniffer.so

raw-shared:
	$(MAKE) -C . shared CFLAGS='$(CFLAGS) -DNTLM_RAW_ONLY'

static: libntlmsniffer.a

raw-static:
	$(MAKE) -C . static CFLAGS='$(CFLAGS) -DNTLM_RAW_ONLY'

exe: ntlm-sniffer 

exe-static: ntlm-sniffer-static

# File based rules

libntlmsniffer.so: $(NTLMSSP-SRCS:.c=.o)
	$(CC) $(CFLAGS) -shared $^ -o $@

libntlmsniffer.a: $(NTLMSSP-SRCS:.c=.o)
	$(AR) -r $@ $^

ntlm-sniffer: $(NTLMSSP-SRCS:.c=.o) $(NTLM-SRCS:.c=.o)
	$(CC) $(CFLAGS) $^ -o $@

ntlm-sniffer-static: $(NTLMSSP-SRCS:.c=.o) $(NTLM-SRCS:.c=.o)
	$(CC) $(CFLAGS) -static $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

