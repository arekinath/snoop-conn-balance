/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Joyent, Inc.
 */

#if !defined(_HASH_H)
#define _HASH_H

#include <stdint.h>

#define BUCKETS 512

int shash(const char *target);
int dhash(uint32_t src, uint16_t qid);
int bhash(uint32_t src, uint32_t dst);

#endif
