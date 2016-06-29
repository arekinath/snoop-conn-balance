/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Joyent, Inc.
 */

#include "hash.h"
#include <string.h>

static uint64_t
fnvhash(const uint8_t *data, int len)
{
	int i;
	uint64_t h = 0xcbf29ce484222325ULL;
	for (i = 0; i < len; ++i) {
		h = h * 0x100000001b3ULL;
		h = h ^ data[i];
	}
	return (h);
}

int
shash(const char *target)
{
	return (fnvhash((const uint8_t *)target, strlen(target)) % BUCKETS);
}

int
dhash(uint32_t src, uint16_t qid)
{
	uint8_t data[6];
	memcpy(data, &src, 4);
	memcpy(data + 4, &qid, 2);
	return (fnvhash(data, 6) % BUCKETS);
}

int
bhash(uint32_t src, uint32_t dst)
{
	uint8_t data[8];
	memcpy(data, &src, 4);
	memcpy(data + 4, &dst, 4);
	return (fnvhash(data, 8) % BUCKETS);
}
