/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2016, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "enums.h"
#include "packet.h"

const char *namefilt = NULL;

struct snoophdr {
	char magic[8];
	uint32_t version;
	uint32_t dltype;
};

struct pkthdr {
	uint32_t len;
	uint32_t snap;
	uint32_t reclen;
	uint32_t drops;
	uint32_t sec;
	uint32_t usec;
};

int
main(int argc, char *argv[])
{
	struct snoophdr filehdr;
	uint8_t *data;
	int dlen;
	uint32_t lastclean = 0;
	FILE *inp = stdin;
	int c;

	while ((c = getopt(argc, argv, "f:F:")) != -1) {
		switch (c) {
		case 'f':
			inp = fopen(optarg, "r");
			if (inp == NULL) {
				perror("fopen");
				return (1);
			}
			break;
		case 'F':
			namefilt = optarg;
			break;
		case '?':
			if (optopt == 'f' || optopt == 'F') {
				fprintf(stderr,
				    "Option -%c requires an argument\n",
				    optopt);
			}
			fprintf(stderr,
			    "Usage: ./connbal [-f inputfile] [-F filter]\n");
			return (1);
		default:
			abort();
		}
	}
	if (optind < argc) {
		fprintf(stderr,
		    "Usage: ./connbal [-f inputfile] [-F filter]\n");
		return (1);
	}

	if (fread(&filehdr, sizeof (filehdr), 1, inp) != 1) {
		fprintf(stderr, "failed to read snoop header\n");
		return (2);
	}
	filehdr.version = ntohl(filehdr.version);
	filehdr.dltype = ntohl(filehdr.dltype);
	if (strncmp(filehdr.magic, "snoop", 8) != 0 ||
	    filehdr.version != 2) {
		fprintf(stderr, "input is not a snoop capture\n");
		return (2);
	}
	if (filehdr.dltype != 0x04) {
		fprintf(stderr,
		    "only ethernet type snoop captures supported\n");
		return (2);
	}

	dlen = 512;
	data = malloc(dlen);

	while (1) {
		struct pkthdr hdr;
		int iplen, plen, off;
		uint32_t src, dst;
		uint16_t sport, dport;
		uint16_t mactype;
		uint8_t proto;

		if (fread(&hdr, sizeof (hdr), 1, inp) != 1) {
			if (feof(inp)) {
				break;
			}
			fprintf(stderr, "failed to read capture record\n");
			return (2);
		}
		hdr.reclen = ntohl(hdr.reclen);
		plen = hdr.reclen - sizeof (hdr);
		while (plen > dlen) {
			dlen *= 2;
			free(data);
			data = malloc(dlen);
		}
		if (fread(data, hdr.reclen - sizeof (hdr), 1, inp) != 1) {
			fprintf(stderr, "failed to read capture data\n");
			return (2);
		}
		hdr.len = ntohl(hdr.len);
		hdr.snap = ntohl(hdr.snap);
		hdr.drops = ntohl(hdr.drops);
		hdr.sec = ntohl(hdr.sec);
		hdr.usec = ntohl(hdr.usec);

		if (hdr.sec - lastclean > 10) {
			clean_dns(hdr.sec);
			lastclean = hdr.sec;
		}

		off = 0;
		off += 6; /* src mac */
		off += 6; /* dest mac */

		memcpy(&mactype, data + off, 2);
		off += 2;
		mactype = ntohs(mactype);
		if (mactype == MAC_DOT1Q) {
			off += 2; /* ignore vlan id for now */
			memcpy(&mactype, data + off, 2);
			off += 2;
			mactype = ntohs(mactype);
		}

		if (mactype != MAC_IP4)
			continue;

		if ((data[off] & 0xf0) >> 4 != 4)
			continue;
		iplen = (data[off] & 0x0f) * 4;

		memcpy(&src, data + off + 12, 4);
		src = ntohl(src);
		memcpy(&dst, data + off + 16, 4);
		dst = ntohl(dst);

		proto = data[off + 9];

		off += iplen;
		
		if (proto == PR_UDP) {
			memcpy(&sport, data + off, 2);
			sport = ntohs(sport);
			memcpy(&dport, data + off + 2, 2);
			dport = ntohs(dport);
			off += 4;
			off += 4; /* length + checksum */

			if (sport == 53 || dport == 53) {
				parse_dns(src, dst, sport, dport,
				    data + off, hdr.snap - off, hdr.sec);
			}
		} else if (proto == PR_TCP) {
			memcpy(&sport, data + off, 2);
			sport = ntohs(sport);
			memcpy(&dport, data + off + 2, 2);
			dport = ntohs(dport);

			if (data[off + 13] == TCPFL_SYN) {
				got_tcp_conn(src, dst, sport, dport);
			}
		}
	}

	print_summary();

	return (0);
}
