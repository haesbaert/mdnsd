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

#include <arpa/nameser.h>
#include <netinet/in.h>

#include <string.h>

/* TODO REMOVE THE STUPID MDNS PREFIX */
#define ALL_MDNS_DEVICES	"224.0.0.251"

#define MDNS_QUERY_TTL		1
#define MDNS_RESPONSE_TTL	255
#define MDNS_PORT		5353
#define MDNS_HDR_LEN		12	
#define MDNS_MINQRY_LEN		6 /* 4 (qtype + qclass) +1 (null) + 1 (label len) */
#define MDNS_HDR_QR_MASK	0x8000
#define MDNS_MAX_PACKET		10000
#define MDNS_MAX_LABELS		128
#define MDNS_MAX_CHARSTR	256 /* we swap the length byter per the null byte */
#define MDNS_TTL_HNAME		120

#define CACHEFLUSH_MSK		0x8000
#define CLASS_MSK		~0x8000
#define UNIRESP_MSK		0x8000
#define NAMECOMP_MSK		0xc000
#define NAMEADDR_MSK		~0xc000
#define QR_MSK                 	0x8000
#define TC_MSK                 	0x200

/* Accepted RR: A, HINFO, CNAME, PTR, SRV, TXT, NS  */
struct hinfo {
	char	cpu[MDNS_MAX_CHARSTR];
	char	os[MDNS_MAX_CHARSTR];
};

struct mdns_question {
	LIST_ENTRY(mdns_question)	 entry;
	
	char		dname[MAXHOSTNAMELEN];
	u_int16_t	qtype;
	u_int16_t	qclass;
	int		uniresp;
	int 		probe;
};

struct mdns_rr {
	LIST_ENTRY(mdns_rr)	entry;
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
		char		TXT[MDNS_MAX_CHARSTR];
		
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

struct mdns_pkt {
	/* mdns header */
	u_int8_t 	qr;
	u_int8_t	tc;
	
	u_int16_t	qdcount;
	u_int16_t	ancount;
	u_int16_t	nscount;
	u_int16_t	arcount;
	
	LIST_HEAD(, mdns_question) qlist;
	LIST_HEAD(, mdns_rr) anlist;
	LIST_HEAD(, mdns_rr) nslist;
	LIST_HEAD(, mdns_rr) arlist;
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

ssize_t	charstr(char [MDNS_MAX_CHARSTR], u_int8_t *, uint16_t);
void	labelstr(char domain[MAXHOSTNAMELEN], u_char *l[], ssize_t nl);

#endif	/* _MDNS_H_ */
