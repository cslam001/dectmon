/*
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <ctype.h>

#include <dect/libdect.h>
#include <dectmon.h>

#define BLOCKSIZE	16

void dect_hexdump(const char *prefix, const uint8_t *buf, size_t size)
{
	unsigned int i, off, plen = 0;
	char hbuf[3 * BLOCKSIZE + 1], abuf[BLOCKSIZE + 1];

	for (i = 0; i < strlen(prefix); i++)
		plen += prefix[i] == '\t' ? 8 : 1;

	for (i = 0; i < size; i++) {
		off = i % BLOCKSIZE;

		sprintf(hbuf + 3 * off, "%.2x ", buf[i]);
		abuf[off] = isascii(buf[i]) && isprint(buf[i]) ? buf[i] : '.';

		if (off == BLOCKSIZE - 1 || i == size - 1) {
			abuf[off + 1] = '\0';
			printf("%s: %-*s    |%s|\n", prefix, 64 - plen, hbuf, abuf);
		}
	}
}
