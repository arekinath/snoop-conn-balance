/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Joyent, Inc.
 */

#if !defined(_PACKET_H)
#define _PACKET_H

void clean_dns(uint32_t time);
void got_tcp_conn(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport);
void print_summary(void);
void parse_dns(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
    const uint8_t *data, int len, uint32_t time);

#endif
