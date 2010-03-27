/*
 * Copyright (c) 2010 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef _MDNS_H_
#define	_MDNS_H_

#include <sys/queue.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#include <event.h>
#include <string.h>

#define	MDNSD_SOCKET		"/var/run/mdnsd.sock"
#define ALL_MDNS_DEVICES	"224.0.0.251"
#define MDNS_TIMEOUT 		3
#define MAX_CHARSTR		256 /* we swap the length byter per the null byte */

/* XXX remove CTL infix */
enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_END,
	IMSG_CTL_LOOKUP,
	IMSG_CTL_LOOKUP_ADDR,
	IMSG_CTL_LOOKUP_HINFO,
	IMSG_DEMOTE
};

/* Accepted RR: A, HINFO, CNAME, PTR, SRV, TXT, NS  */
struct hinfo {
	char	cpu[MAX_CHARSTR];
	char	os[MAX_CHARSTR];
};

int	mdns_lkup(const char *, struct in_addr *);
int	mdns_lkup_addr(struct in_addr *, char *, size_t);
int	mdns_lkup_hinfo(const char *, struct hinfo *);

#endif	/* _MDNS_H_ */
