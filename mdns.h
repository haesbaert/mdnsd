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
#define QUERY_TTL		1
#define RESPONSE_TTL		255
#define MDNS_PORT		5353
#define HDR_LEN			12	
#define MINQRY_LEN		6 /* 4 (qtype + qclass) +1 (null) + 1 (label len) */
#define HDR_QR_MASK		0x8000
#define MAX_PACKET		10000
#define MAX_LABELS		128
#define MAX_CHARSTR		256 /* we swap the length byter per the null byte */
#define TTL_HNAME		120

#define CACHEFLUSH_MSK		0x8000
#define CLASS_MSK		~0x8000
#define UNIRESP_MSK		0x8000
#define NAMECOMP_MSK		0xc000
#define NAMEADDR_MSK		~0xc000
#define QR_MSK                 	0x8000
#define TC_MSK                 	0x200

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

struct question {
	LIST_ENTRY(question)	entry;
	char			dname[MAXHOSTNAMELEN];
	u_int16_t		qtype;
	u_int16_t		qclass;
	int			uniresp;
	int 			probe;
};

struct rr {
	LIST_ENTRY(rr)		entry;
	char			dname[MAXHOSTNAMELEN];
	u_int16_t		type;
	int			cacheflush;	
	u_int16_t		class;
	u_int32_t		ttl;
	u_int16_t		rdlen;
	union {
		struct in_addr	A;
		char		CNAME[MAXHOSTNAMELEN];
		char		PTR[MAXHOSTNAMELEN];
		char		NS[MAXHOSTNAMELEN];
		char		TXT[MAX_CHARSTR];
		
		struct {
			uint16_t	priority;
			uint16_t	weight;
			uint16_t	port;
			char		dname[MAXHOSTNAMELEN];
		} SRV;
		struct hinfo 	HINFO;

	} rdata;
	int		active;	   	/* should we try to renew this ? */
	int		revision;	/* at 80% of ttl, then 90% and 95% */
	struct event 	rev_timer; 	/* cache revision timer */
	
};

struct pkt {
	/* mdns header */
	u_int8_t 	qr;
	u_int8_t	tc;
	
	u_int16_t	qdcount;
	u_int16_t	ancount;
	u_int16_t	nscount;
	u_int16_t	arcount;
	
	LIST_HEAD(, question) qlist;
	LIST_HEAD(, rr)       anlist;
	LIST_HEAD(, rr)       nslist;
	LIST_HEAD(, rr)       arlist;
};

#define RR_UNIQ(rr) (rr->cacheflush)
#define QEQUIV(qa, qb)					\
	((qa->qtype  == qb->qtype)	&&		\
	    (qb->qclass == qb->qclass)	&&		\
	    (strcmp(qa->dname, qb->dname) == 0))
#define ANSWERS(q, rr)						\
	(((q->qtype == T_ANY) || (q->qtype == rr->type))  &&	\
	    q->qclass == rr->class                        &&	\
	    strcmp(q->dname, rr->dname) == 0)

ssize_t	charstr(char [MAX_CHARSTR], u_int8_t *, uint16_t);
void	labelstr(char domain[MAXHOSTNAMELEN], u_char *l[], ssize_t nl);

/* exported functions to be used in libc/mdns program */
int	mdns_lkup(const char *, struct in_addr *);
int	mdns_lkup_addr(struct in_addr *, char *, size_t);
int	mdns_lkup_hinfo(const char *, struct hinfo *);

#endif	/* _MDNS_H_ */
