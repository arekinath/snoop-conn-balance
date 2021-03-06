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
#include "hash.h"
#include "packet.h"

extern const char *namefilt;

struct tcpconn {
	struct tcpconn *next;
	uint32_t src;
	uint32_t dst;
	uint16_t sport;
	uint16_t dport;
};
/*
 * Hash table of known TCP connections, only used for -a.
 */
struct tcpconn *tcpconns[BUCKETS] = { NULL };

struct dnsreq {
	struct dnsreq *next;
	uint16_t qid;			/* DNS query id */
	uint32_t src;			/* source IP of original req */
	uint32_t dst;
	uint16_t sport;
	uint32_t ctime;			/* value of snoop hdr.sec at creation */
	char name[256];
};
/*
 * All DNS requests that are currently outstanding that match our filters,
 * hashed on src,qid.
 */
struct dnsreq *dnsreqs[BUCKETS] = { NULL };

struct srvrec {
	struct srvrec *next;
	char target[256];
	char name[256];
	uint16_t ports[16];
};
/*
 * All SRV records we've seen, hashed on target name. We probably should expire
 * these or something, but for now we just remember SRV targets we've seen
 * forever.
 */
struct srvrec *srvrecs[BUCKETS] = { NULL };

struct backend {
	struct backend *next;
	uint32_t src;
	uint32_t dst;
	uint64_t rcount;
	char name[256];
	uint16_t ports[16];		/* unused slots are 0 */
	uint64_t counts[16];		/* conn count, same index as ports */
	uint64_t rcounts[16];		/* # of times returned in DNS results */
};
/*
 * Actual backends that have been seen in DNS, which we are now tracking
 * connections to.
 */
struct backend *backends[BUCKETS] = { NULL };

/*
 * Add a port to a port set (like b->ports on a struct backend).
 */
int
add_port(uint16_t *ports, uint16_t port)
{
	int i;
	for (i = 0; i < 16; ++i) {
		if (ports[i] == port)
			return (i);
	}
	for (i = 0; i < 16; ++i) {
		if (ports[i] == 0) {
			ports[i] = port;
			return (i);
		}
	}
	return (-1);
}

void
saw_srv_target(const char *target, uint16_t port, const char *name)
{
	int h, i, j;
	struct srvrec *s;

	h = shash(target);
	for (s = srvrecs[h]; s != NULL; s = s->next) {
		if (strcmp(target, s->target) == 0) {
			if (add_port(s->ports, port) == -1) {
				fprintf(stderr, "warning: too many ports seen"
				    "for SRV target '%s'\n", s->target);
			}
			return;
		}
	}

	s = calloc(sizeof (*s), 1);
	strlcpy(s->target, target, sizeof (s->target));
	strlcpy(s->name, name, sizeof (s->name));
	s->ports[0] = port;
	s->next = srvrecs[h];
	srvrecs[h] = s;
}

struct srvrec *
find_srv_target(const char *target)
{
	int h;
	struct srvrec *s;

	h = shash(target);
	for (s = srvrecs[h]; s != NULL; s = s->next) {
		if (strcmp(target, s->target) == 0) {
			return (s);
		}
	}
	return (NULL);
}

void
make_backend(uint32_t src, uint32_t dst, const char *name, struct srvrec *srv)
{
	int h, i, j;
	struct backend *b;

	h = bhash(src, dst);

	for (b = backends[h]; b != NULL; b = b->next) {
		if (b->src == src && b->dst == dst) {
			if (srv == NULL) {
				b->rcount++;
				return;
			}
			for (i = 0; i < 16; ++i) {
				j = add_port(b->ports, srv->ports[i]);
				if (j == -1) {
					fprintf(stderr, "warning: backend "
					    "for %s is out of ports\n", name);
					return;
				}
				b->rcounts[j]++;
			}
			return;
		}
	}
	
	b = calloc(sizeof (*b), 1);
	strlcpy(b->name, (srv == NULL ? name : srv->name), sizeof (b->name));
	b->src = src;
	b->dst = dst;
	b->next = backends[h];
	if (srv != NULL) {
		memcpy(b->ports, srv->ports, sizeof (b->ports));
		for (i = 0; i < 16 && b->ports[i] != 0; ++i)
			b->rcounts[i] = 1;
	} else {
		b->rcount = 1;
	}
	backends[h] = b;
}

void
got_tcp_fin(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
{
	int h;
	struct tcpconn *pc, *c;

	h = thash(src, dst, sport, dport);
	for (pc = NULL, c = tcpconns[h]; c != NULL; pc = c, c = c->next) {
		if (c->src == src && c->dst == dst && c->sport == sport &&
		    c->dport == dport) {
			if (pc == NULL)
				tcpconns[h] = c->next;
			else
				pc->next = c->next;
			return;
		}
	}

	h = thash(dst, src, dport, sport);
	for (pc = NULL, c = tcpconns[h]; c != NULL; pc = c, c = c->next) {
		if (c->src == dst && c->dst == src && c->sport == dport &&
		    c->dport == sport) {
			if (pc == NULL)
				tcpconns[h] = c->next;
			else
				pc->next = c->next;
			return;
		}
	}
}

void
got_tcp(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
{
	int h;
	struct tcpconn *c;

	h = thash(src, dst, sport, dport);
	for (c = tcpconns[h]; c != NULL; c = c->next) {
		if (c->src == src && c->dst == dst && c->sport == sport &&
		    c->dport == dport) {
			return;
		}
	}

	h = thash(dst, src, dport, sport);
	for (c = tcpconns[h]; c != NULL; c = c->next) {
		if (c->src == dst && c->dst == src && c->sport == dport &&
		    c->dport == sport) {
			return;
		}
	}

	h = thash(src, dst, sport, dport);
	c = calloc(sizeof (*c), 1);
	c->src = src;
	c->dst = dst;
	c->sport = sport;
	c->dport = dport;
	c->next = tcpconns[h];
	tcpconns[h] = c;

	got_tcp_syn(src, dst, sport, dport);
	got_tcp_syn(dst, src, dport, sport);
}

/*
 * Called by connbal.c when any new TCP connection attempt is seen.
 */
void
got_tcp_syn(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
{
	int h, i;
	struct backend *b;

	h = bhash(src, dst);

	for (b = backends[h]; b != NULL; b = b->next) {
		if (b->src == src && b->dst == dst) {
			i = add_port(b->ports, dport);
			if (i == -1) {
				fprintf(stderr, "warning: backend is out of "
				    "ports\n");
				return;
			}
			b->counts[i]++;
			return;
		}
	}
}

void
print_summary(void)
{
	int h, i;
	struct backend *b;
	for (h = 0; h < BUCKETS; ++h) {
		for (b = backends[h]; b != NULL; b = b->next) {
			uint8_t srcb[4], dstb[4];
			memcpy(srcb, &b->src, 4);
			memcpy(dstb, &b->dst, 4);
			for (i = 0; i < 16; ++i) {
				if (b->ports[i] == 0)
					continue;
				fprintf(stdout, "%03u.%03u.%03u.%03u\t"
				    "%03u.%03u.%03u.%03u:%u\t"
				    "%llu\t%llu\t%s\n",
				    srcb[3], srcb[2], srcb[1], srcb[0],
				    dstb[3], dstb[2], dstb[1], dstb[0],
				    b->ports[i], b->counts[i],
				    (b->rcount > 0) ? b->rcount : b->rcounts[i],
				    b->name);
			}
			if (b->ports[0] == 0) {
				fprintf(stdout, "%03u.%03u.%03u.%03u\t"
				    "%03u.%03u.%03u.%03u:?\t"
				    "0\t%llu\t%s\n",
				    srcb[3], srcb[2], srcb[1], srcb[0],
				    dstb[3], dstb[2], dstb[1], dstb[0],
				    b->rcount, b->name);
			}
		}
	}
}

/*
 * Reads in a DNS nsName string. These consist of a set of length-prefixed
 * labels. If the length prefix has certain high bits set, it is a back-pointer
 * referring to another nsName earlier in the packet.
 *
 * Returns 0 on success.
 */
int
read_nsname(const uint8_t *data, int *offset, int len, char *out, int olen)
{
	int r = *offset, w = 0;
	uint8_t n;
	while (r < len && w < olen - 1) {
		n = data[r++];
		if (n == 0x00) {
			break;

		} else if ((n & NSM_MASK) == NSM_STRING) {
			memcpy(out + w, data + r, n);
			w += n; r += n;
			out[w++] = '.';

		} else if ((n & NSM_MASK) == NSM_PTR) {
			uint16_t ptr = data[r++];
			int recuroff;
			ptr = ptr | ((n & ~NSM_MASK) << 8);
			if (ptr > r) {
				return (1);
			}
			recuroff = ptr;
			if (read_nsname(data, &recuroff, len, out + w,
			    olen - w) != 0) {
				return (1);
			}
			*offset = r;
			return (0);

		} else {
			return (1);
		}
	}
	out[w++] = '\0';
	*offset = r;
	return (0);
}

/* Clean out expired DNS requests. */
void
clean_dns(uint32_t time)
{
	int h;
	struct dnsreq *pr, *nr, *r;

	for (h = 0; h < BUCKETS; ++h) {
		for (pr = NULL, r = dnsreqs[h]; r != NULL; pr = r, r = nr) {
			nr = r->next;
			if (time - r->ctime >= 10) {
				if (pr == NULL) {
					dnsreqs[h] = r->next;
					free(r);
					r = NULL;
					nr = dnsreqs[h];
				} else {
					pr->next = r->next;
					free(r);
					r = NULL;
					nr = pr->next;
				}
			} 
		}
	}
}

/* Parse a snooped DNS packet and index its contents. */
void
parse_dns(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
    const uint8_t *data, int len, uint32_t time)
{
	uint16_t qid, qc, ac, nc, ec, tac;
	int h, off = 0;
	enum nspos pos = NSP_QUESTION;

	if (len < 12) {
		fprintf(stderr, "warning: snaplen too low\n");
		return;
	}

	/*
	 * Read in the header of the packet, containing the counts of records
	 * in the sections to follow (qc, ac, nc, ec).
	 */
	memcpy(&qid, data + off, 2);
	qid = ntohs(qid);
	off += 2;
	off += 2; /* flags */
	memcpy(&qc, data + off, 2);
	qc = ntohs(qc);
	off += 2;
	memcpy(&ac, data + off, 2);
	ac = ntohs(ac);
	tac = ac;
	off += 2;
	if (qc > 1 || ac > 1000) {
		fprintf(stderr, "warning: weird looking dns packet "
		    "says %d q, %d ans\n", qc, ac);
		return;
	}
	memcpy(&nc, data + off, 2);
	nc = ntohs(nc);
	off += 2;
	memcpy(&ec, data + off, 2);
	ec = ntohs(ec);
	off += 2;

	/*
	 * If this is outgoing to the NS and has one question in it, it could
	 * be a request we want to track.
	 */
	if (dport == 53 && qc == 1) {
		struct dnsreq *r = NULL;
		uint16_t qtype, qclass;
		r = calloc(sizeof (*r), 1);
		r->qid = qid;
		r->src = src;
		r->dst = dst;
		r->sport = sport;
		r->ctime = time;
		if (read_nsname(data, &off, len, r->name, 256)) {
			free(r);
			return;
		}
		memcpy(&qtype, data + off, 2);
		off += 2;
		memcpy(&qclass, data + off, 2);
		off += 2;
		qtype = ntohs(qtype);
		qclass = ntohs(qclass);
		if (qclass != NSC_IN || (qtype != NST_A && qtype != NST_SRV)) {
			free(r);
			return;
		}
		if (namefilt != NULL && strstr(r->name, namefilt) == NULL) {
			free(r);
			return;
		}
		h = dhash(src, qid);
		r->next = dnsreqs[h];
		dnsreqs[h] = r;

	/*
	 * If it's incoming *from* the NS and has some answers in it, it could
	 * also be interesting, but only if it matches up with an interesting
	 * request we started tracking earlier.
	 */
	} else if (sport == 53 && ac != 0) {
		struct dnsreq *r = NULL, *nr = NULL;
		struct srvrec *srv = NULL;
		char name[256];
		int didsrv = 0;

		if (read_nsname(data, &off, len, name, 256)) {
			return;
		}
		off += 4; /* type, qclass */

		/* Find a matching tracked DNS request. */
		h = dhash(dst, qid);
		for (nr = dnsreqs[h]; nr != NULL; r = nr, nr = r->next) {
			if (nr->qid == qid && nr->dst == src &&
			    nr->src == dst && nr->sport == dport &&
			    strcmp(name, nr->name) == 0) {
				break;
			}
		}
		if (nr == NULL) {
			return;
		}

		/* Unlink it from the list. */
		if (r == NULL)
			dnsreqs[h] = nr->next;
		else
			r->next = nr->next;

		srv = find_srv_target(name);
		pos = NSP_ANSWER;

		/* Parse all the answers and additional records */
		while (off < len) {
			uint16_t rtype, rclass, rlen;

			if (pos == NSP_ANSWER && ac <= 0)
				pos = NSP_AUTHORITY;
			if (pos == NSP_AUTHORITY && nc <= 0)
				pos = NSP_ADDITIONAL;
			if (pos == NSP_ADDITIONAL && ec <= 0)
				break;

			if (read_nsname(data, &off, len, name, 256)) {
				free(nr);
				return;
			}
			memcpy(&rtype, data + off, 2);
			rtype = ntohs(rtype);
			off += 2;
			memcpy(&rclass, data + off, 2);
			rclass = ntohs(rclass);
			off += 2;
			off += 4; /* rttl */
			memcpy(&rlen, data + off, 2);
			rlen = ntohs(rlen);
			off += 2;

			if (rtype == NST_OPT)
				goto next;

			if (rclass != NSC_IN) {
				free(nr);
				return;
			}
			/*
			 * For non-answers, use the name in the record itself
			 * to decide if this is an SRV target.
			 */
			if (pos != NSP_ANSWER) {
				srv = find_srv_target(name);
			}

			if (pos == NSP_AUTHORITY)
				goto next;

			if (rtype == NST_CNAME && tac <= 2 && srv == NULL) {
				free(nr);
				return;
			}

			if (rtype == NST_A && (
			    (pos == NSP_ANSWER && tac > 1) || srv != NULL)) {
				uint32_t addr;
				memcpy(&addr, data + off, 4);
				addr = ntohl(addr);
				make_backend(dst, addr, name, srv);

			} else if (rtype == NST_SRV) {
				uint16_t port;
				char target[256];
				int inoff = off;
				inoff += 4; /* priority, weight */
				memcpy(&port, data + inoff, 2);
				port = ntohs(port);
				inoff += 2;
				if (read_nsname(data, &inoff, len, target,
				    sizeof (target))) {
					free(nr);
					return;
				}
				saw_srv_target(target, port, name);
				didsrv = 1;
			}

next:
			off += rlen;
			if (pos == NSP_ANSWER)
				--ac;
			else if (pos == NSP_AUTHORITY)
				--nc;
			else if (pos == NSP_ADDITIONAL)
				--ec;
		}
		
		free(nr);
	}
}
