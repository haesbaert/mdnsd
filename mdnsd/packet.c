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

/*
 * This file needs a refactoring, pkt_parse and serialize functions rely on
 * pktcomp being always accurate, most of functions here are not re-entrant and
 * depend on state that they shouldn't, like serialize_dname which must have the
 * current packet buffer as input. Also, name compression uses a different
 * logic when receiving/sending, they should be made equal.
 * I'll rewrite all of it when I have the time.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <net/if_dl.h>

#include <errno.h>
#include <event.h>
#include <stdlib.h>
#include <string.h>

#include "mdnsd.h"
#include "log.h"

#define CACHEFLUSH_MSK	0x8000
#define CLASS_MSK	~0x8000
#define UNIRESP_MSK	0x8000
#define NAMECOMP_BYTE_MSK 0xc0 	/* TODO unify this someday */
#define NAMECOMP_MSK	0xc000
#define NAMEADDR_MSK	~0xc000
#define MAXLABELS	128
#define MAXPACKET	10000
#define HDR_LEN		12
#define MINQRY_LEN	6 /* 4 (qtype + qclass) +1 (null) + 1 (label len) */
/* Defer truncated packets from 400ms-500ms */
#define RANDOM_DEFERTIME			\
	(arc4random_uniform((u_int32_t) 100000)	\
	    + 400000)

int		 pkt_parse_header(u_int8_t **, u_int16_t *, struct pkt *);
ssize_t		 pkt_parse_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN]);
int		 pkt_parse_rr(u_int8_t **, u_int16_t *, struct rr *);
int		 pkt_parse_question(u_int8_t **, u_int16_t *, struct pkt *);
int		 pkt_handle_qst(struct pkt *);
int		 pkt_should_answer_qst(struct pkt *, struct question *);
ssize_t		 serialize_rr(struct rr *, u_int8_t *, u_int16_t);
ssize_t		 serialize_qst(struct question *, u_int8_t *, u_int16_t);
ssize_t		 serialize_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN], int);
ssize_t		 serialize_rdata(struct rr *, u_int8_t *, u_int16_t);
int		 rr_parse_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN]);
ssize_t		 charstr(char [MAXCHARSTR], u_int8_t *, u_int16_t);
void		 header_htons(HEADER *);
void		 header_ntohs(HEADER *);
int		 pktcomp_add(char [MAXHOSTNAMELEN], u_int16_t);
struct namecomp *pktcomp_lookup(char [MAXHOSTNAMELEN]);

extern struct mdnsd_conf *conf;

/* Used in name compression */
struct namecomp {
	LIST_ENTRY(namecomp) 	entry;
	char			dname[MAXHOSTNAMELEN];
	u_int16_t		offset;
};

struct {
	LIST_HEAD(, namecomp) 	namecomp_list;
	u_int8_t		*start;
	u_int16_t	 	len;
} pktcomp;

/* Deferred packets, Known Answer Supression packets with TC bit */
TAILQ_HEAD(, pkt) deferred_queue;

void
packet_init(void)
{
	LIST_INIT(&pktcomp.namecomp_list);
	TAILQ_INIT(&deferred_queue);
}

/* Send and receive packets */
int
send_packet(struct iface *iface, void *pkt, size_t len, struct sockaddr_in *dst)
{
	/* set outgoing interface for multicast traffic */
	if (IN_MULTICAST(ntohl(dst->sin_addr.s_addr)))
		if (if_set_mcast(iface) == -1) {
			log_warn("send_packet: error setting multicast "
			    "interface, %s", iface->name);
			return (-1);
		}

	if (sendto(iface->fd, pkt, len, 0,
	    (struct sockaddr *)dst, sizeof(*dst)) == -1) {
		log_warn("send_packet: error sending packet on interface "
                         "%s, len %zd", iface->name, len);
		return (-1);
	}

	return (0);
}

void
recv_packet(int fd, short event, void *bula)
{
	union {
		struct cmsghdr hdr;
		char	buf[CMSG_SPACE(sizeof(struct sockaddr_dl)) +
		    CMSG_SPACE(sizeof(struct in_addr))];
	} cmsgbuf;
	struct sockaddr_in	 ipsrc;
	struct in_addr		 ipdst, mdns_addr;
	struct iovec		 iov;
	struct msghdr		 msg;
	struct cmsghdr		*cmsg;
	struct sockaddr_dl	*dst = NULL;
	struct iface		*iface;
	static u_int8_t		 buf[MAXPACKET];
	struct rr		*rr;
	struct pkt		*pkt;
	struct timeval 		 tv;
	u_int8_t		*pbuf;
	u_int16_t		 i, len;
	ssize_t			 r;
		
	if (event != EV_READ)
		return;
	
	inet_aton(ALL_MDNS_DEVICES, &mdns_addr);
	bzero(&msg, sizeof(msg));
	bzero(buf, sizeof(buf));
	bzero(&ipdst, sizeof(ipdst));
	pbuf = buf;

	iov.iov_base = buf;
	iov.iov_len = MAXPACKET;
	msg.msg_name = &ipsrc;
	msg.msg_namelen = sizeof(ipsrc);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	if ((r = recvmsg(fd, &msg, 0)) == -1) {
		if (errno != EINTR && errno != EAGAIN)
			log_warn("recv_packet: read error: %s",
			    strerror(errno));
		return;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_RECVIF) {
			dst = (struct sockaddr_dl *)CMSG_DATA(cmsg);
			continue;
		}
		if (cmsg->cmsg_level == IPPROTO_IP &&
		    cmsg->cmsg_type == IP_RECVDSTADDR) {
			ipdst = *(struct in_addr *)CMSG_DATA(cmsg);
			continue;
		}

	}
	/*
	 * We need a valid dst to lookup receiving interface, see below.
	 * Ipdst must be filled so we can check for unicast answers, see below.
	 */
	if (dst == NULL || ipdst.s_addr == 0)
		return;

	len = (u_int16_t)r;
	
	/* Check the packet is not from one of the local interfaces */
	LIST_FOREACH(iface, &conf->iface_list, entry) 
		if (iface->addr.s_addr == ipsrc.sin_addr.s_addr)
			return;

	if ((pkt = calloc(1, sizeof(*pkt))) == NULL)
		fatal("calloc");
	pkt_init(pkt);
	pktcomp_reset(0, buf, len);
	pkt->ipsrc = ipsrc;
	/*
	 * Parse header, we'll use the HEADER structure in nameser.h
	 */
	if (pkt_parse_header(&pbuf, &len, pkt) == -1) {
		pkt_cleanup(pkt);
		free(pkt);
		return;
	}
	
	/*
	 * Multicastdns draft 4. Source Address check.
	 * If a response packet was sent to an unicast address, check if the
	 * source ip address in the packet matches one of our subnets, if not,
	 * drop it.
	 */
	if (pkt->h.qr == MDNS_RESPONSE && ipdst.s_addr != mdns_addr.s_addr) {
		/* if_find_iface will try to match source address */
		if ((iface = if_find_iface(dst->sdl_index,
		    pkt->ipsrc.sin_addr)) == NULL) {
			log_warn("recv_packet: "
			    "cannot find a matching interface (1)");
			pkt_cleanup(pkt);
			free(pkt);
			return;
		}
	}
	else /* Disregard source ip address, just find a matching iface */
		if ((iface = if_find_index(dst->sdl_index)) == NULL) {
			log_warn("recv_packet: "
			    "cannot find a matching interface (2)");
			pkt_cleanup(pkt);
			free(pkt);
			return;
		}
	/* Save the received interface */
	pkt->iface = iface;
	
	/* Check if this is a legacy dns packet */
	if (ntohs(pkt->ipsrc.sin_port) != MDNS_PORT)
		pkt->flags |= PKT_FLAG_LEGACY;
	
	/* Parse question section */
	if (pkt->h.qr == MDNS_QUERY)
		for (i = 0; i < pkt->h.qdcount; i++)
			if (pkt_parse_question(&pbuf, &len, pkt) == -1) {
				pkt_cleanup(pkt);
				free(pkt);
				return;
			}
	/* Parse RR sections */
	for (i = 0; i < pkt->h.ancount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		if (pkt_parse_rr(&pbuf, &len, rr) == -1) {
			log_warnx("Can't parse AN RR");
			free(rr);
			pkt_cleanup(pkt);
			free(pkt);
			return;
		}
		LIST_INSERT_HEAD(&pkt->anlist, rr, pentry);
	}
	for (i = 0; i < pkt->h.nscount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		if (pkt_parse_rr(&pbuf, &len, rr) == -1) {
			log_warnx("Can't parse NS RR");
			free(rr);
			pkt_cleanup(pkt);
			free(pkt);
			return;
		}
		LIST_INSERT_HEAD(&pkt->nslist, rr, pentry);
	}
	for (i = 0; i < pkt->h.arcount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		if (pkt_parse_rr(&pbuf, &len, rr) == -1) {
			log_warnx("Can't parse AR RR");
			free(rr);
			pkt_cleanup(pkt);
			free(pkt);
			return;
		}

		LIST_INSERT_HEAD(&pkt->arlist, rr, pentry);
	}
	
	/* XXX: If we droped an RR our packet counts may be wrong. */
	
	if (len != 0) {
		log_warnx("Couldn't read all packet, %u bytes left", len);
		log_warnx("ancount %d, nscount %d, arcount %d",
		    pkt->h.ancount, pkt->h.nscount, pkt->h.arcount);
		pkt_cleanup(pkt);
		free(pkt);
		return;
	}
	
	/*
	 * Packet parsing done, our pkt structure is complete.
	 */

	/*
	 * Check if the packet is the continuation of a previous truncated
	 * packet, see below. A query packet with no questions and with answers
	 * in is a continuation. Merge this answer with the previous packet.
	 */
	evtimer_set(&pkt->timer, pkt_process, pkt);
	if (pkt->h.qr == MDNS_QUERY &&
	    pkt->h.qdcount == 0 && pkt->h.arcount == 0 &&
	    pkt->h.nscount == 0 && pkt->h.ancount > 0) {
		struct pkt *dpkt, *match = NULL;
		
		TAILQ_FOREACH(dpkt, &deferred_queue, entry) {
			/* XXX: Should we compare source port as well ? */
			if (dpkt->ipsrc.sin_addr.s_addr !=
			    pkt->ipsrc.sin_addr.s_addr)
				continue;
			/* Found a match */
			match = dpkt;
			break;
		}
		if (match != NULL) {
			if (evtimer_pending(&match->timer, NULL))
				evtimer_del(&match->timer);
			TAILQ_REMOVE(&deferred_queue, match, entry);
			/* Merge pkt into match */
			while ((rr = LIST_FIRST(&pkt->anlist)) != NULL) {
				LIST_REMOVE(rr, pentry);
				pkt->h.ancount--;
				pkt_add_anrr(match, rr);
			}
			pkt_cleanup(pkt);
			free(pkt);
			pkt = match;
		}
		else
			log_warnx("Got a continuation packet from %s:%s "
			    "but no match", inet_ntoa(pkt->ipsrc.sin_addr),
			    ntohs(pkt->ipsrc.sin_port));
	}
	
	/*
	 * Mdns Draft 7.2 Multi-Packet Known Answer Supression
	 * A Multicast DNS Responder seeing a Multicast DNS Query with the TC
	 * bit set defers its response for a time period randomly selected in
	 * the interval 400-500ms. This gives the Multicast DNS Querier time to
	 * send additional Known Answer packets before the Responder responds.
	 * If the Responder sees any of its answers listed in the Known Answer
	 * lists of subsequent packets from the querying host, it SHOULD delete
	 * that answer from the list of answers it is planning to give, provided
	 * that no other host on the network is also waiting to receive the same
	 * answer record.  Check if this packet was truncated, due to too many
	 * Known Answer Supression entries, if so, defer processing
	 */
	
	if (pkt->h.qr == MDNS_QUERY && pkt->h.tc) {
		TAILQ_INSERT_TAIL(&deferred_queue, pkt, entry);
		timerclear(&tv);
		tv.tv_usec = RANDOM_DEFERTIME;
		evtimer_add(&pkt->timer, &tv);
		return;
	}
	
	/* Use 0 as event as our processing wasn't deferred */
	pkt_process(-1, 0, pkt);
}

void
pkt_process(int unused, short event, void *v_pkt)
{
	struct pkt	*pkt = v_pkt;
	struct rr	*rr;
	
	if (event == EV_TIMEOUT) {
		log_debug("pkt deferred from %s:%u",
		    inet_ntoa(pkt->ipsrc.sin_addr), ntohs(pkt->ipsrc.sin_port));
		TAILQ_REMOVE(&deferred_queue, pkt, entry);
	}
		
	if (pkt_handle_qst(pkt) == -1) {
		log_warnx("pkt_handleqst() error");
		pkt_cleanup(pkt);
		free(pkt);
		return;
	}
	
		
	/* Clear all authority section */
	/* Mark all probe questions, so we don't try to answer them below */
	while((rr = LIST_FIRST(&pkt->nslist)) != NULL) {
		LIST_REMOVE(rr, pentry);
		free(rr);
	}

	/* Process all answers */
	/*
	 * The answer section for query packets is not authoritative,
	 * it's used in known answer supression, so, if it's a query,
	 * discard all answers.
	 */
	switch (pkt->h.qr) {
	case MDNS_QUERY:
		while ((rr = LIST_FIRST(&pkt->anlist)) != NULL) {
			LIST_REMOVE(rr, pentry);
			free(rr);
		}
		while ((rr = LIST_FIRST(&pkt->arlist)) != NULL) {
			LIST_REMOVE(rr, pentry);
			free(rr);
		}
		break;
	case MDNS_RESPONSE:
		while ((rr = LIST_FIRST(&pkt->anlist)) != NULL) {
			LIST_REMOVE(rr, pentry);
			cache_process(rr);
		}
		/* Process additional section */
		while ((rr = LIST_FIRST(&pkt->arlist)) != NULL) {
			LIST_REMOVE(rr, pentry);
			cache_process(rr);
		}
		break;
	}
	
	/* Sanity check, every section must be empty. */
	if (!LIST_EMPTY(&pkt->qlist))
		log_warnx("Unprocessed question in Question Section");
	if (!LIST_EMPTY(&pkt->anlist))
		log_warnx("Unprocessed rr in Answer Section");
	if (!LIST_EMPTY(&pkt->nslist))
		log_warnx("Unprocessed rr in Authority Section");
	if (!LIST_EMPTY(&pkt->arlist))
		log_warnx("Unprocessed rr in Additional Section");
	
	pkt_cleanup(pkt);
	free(pkt);
	
}

int
pkt_send_if(struct pkt *pkt, struct iface *iface, struct sockaddr_in *pdst)
{
	struct sockaddr_in	 all_mdns;
	static u_int8_t		 buf[MAXPACKET];
	struct question		*qst;
	struct rr		*rr;
	HEADER			*h;
	u_int8_t		*pbuf;
	ssize_t			 n, left;

	inet_aton(ALL_MDNS_DEVICES, &all_mdns.sin_addr);
	all_mdns.sin_port   = htons(MDNS_PORT);
	all_mdns.sin_family = AF_INET;
	all_mdns.sin_len    = sizeof(struct sockaddr_in);

	/* If dst not specified, send to mcast addr */
	if (pdst == NULL)
		pdst = &all_mdns;
	if (iface->mtu > MAXPACKET) {
		log_warnx("pkt_send_if: insane mtu");
		return (-1);
	}
	bzero(buf, sizeof(buf));
	left = iface->mtu - 28;
	h    = (HEADER *) buf;
	pbuf = buf;
	pktcomp_reset(0, buf, left);
	/*
	 * Every packet must have a header, we assume pkt_send_if will only be
	 * called for full packets, that is, packets that require a header.
	 */
	if (left < HDR_LEN) {
		log_warnx("pkt_send_if: left < HDR_LEN");
		return (-1);
	}
	/* Copy header, field by field as we do our own calculations in
	 * qdcount, ancount and etc... */
	if (pkt->flags & PKT_FLAG_LEGACY) {
		h->id = pkt->h.id;
		h->aa = 1;
	}
	h->qr  = pkt->h.qr;
	left  -= HDR_LEN;
	pbuf  += HDR_LEN;
	/* Append all questions, they must fit a single packet. */
	LIST_FOREACH(qst, &pkt->qlist, entry) {
		n = serialize_qst(qst, pbuf, left);
		if (n == -1 || n > left) {
			log_warnx("pkt_send_if: "
			    "can't serialize question section");
			return (-1);
		}
		h->qdcount++;
		pbuf += n;
		left -= n;
	}
	/*
	 * This is where the shit happens, if we are querying and our known
	 * answers section won't fit in a single packet, we fragment. The
	 * following could be a recursive call, passing a flag telling us if
	 * we're in a "fragmented" state or not, but if so, we would need to
	 * make buf non-static, allocating MAX_PACKET for each fragmenting
	 * packet. This might seem like premature optimization but it's also
	 * easier to maintain.
	 */
	LIST_FOREACH(rr, &pkt->anlist, pentry) {
		int in_retry;

		in_retry = 0;
	retry:
		n = serialize_rr(rr, pbuf, left);
		/* Unexpected n */
		if (n > left) {
			log_warnx("No space left on packet for an section.");
			return (-1);
		}
		/*
		 * Fragmentation only for queries, on answer is an
		 * error, actually only for queries with known answer
		 * supression.
		 */
		if (n == -1 && h->qr == MDNS_RESPONSE) {
			log_warnx("Can't fragment for response packets");
			return (-1);
		}
		/*
		 * Won't fit, send what we have, restart the ball.
		 */
		if (n == -1) {
			/* Set truncation bit and close packet */
			h->tc = 1;
			header_htons(h);
			if (send_packet(iface, buf, pbuf - buf, pdst) == -1)
				return (-1);
			/* Reset states */
			bzero(buf, sizeof(buf));
			left = iface->mtu;
			pbuf = buf;
			/* XXX: alignment bug? */
			h    = (HEADER *) buf;
			n    = 0;
			pktcomp_reset(0, buf, left);
			/* Copy header */
			if (pkt->flags & PKT_FLAG_LEGACY)
				h->id = pkt->h.id;
			h->qr  = pkt->h.qr;
			left  -= HDR_LEN;
			pbuf  += HDR_LEN;
			/* Avoid a possible stupid infinite loop */
			if (in_retry) {
				log_warnx("pkt_send_if: failing on retry");
				return (-1);
			}
			in_retry = 1;
			goto retry;
		}
		h->ancount++;
		pbuf += n;
		left -= n;
	}
	
	/* Append all authorities, they must fit a single packet. */
	LIST_FOREACH(rr, &pkt->nslist, pentry) {
		n = serialize_rr(rr, pbuf, left);
		if (n == -1 || n > left) {
			return (-1);
		}
		h->nscount++;
		pbuf += n;
		left -= n;
	}
	
	/* Append all additionals, they must fit a single packet. */
	LIST_FOREACH(rr, &pkt->arlist, pentry) {
		n = serialize_rr(rr, pbuf, left);
		if (n == -1 || n > left) {
			return (-1);
		}
		h->arcount++;
		pbuf += n;
		left -= n;
	}

	/* Close packet and send. */
	header_htons(h);
	if (send_packet(iface, buf, pbuf - buf, pdst) == -1)
		return (-1);
	return (0);
}

int
pkt_send_allif(struct pkt *pkt)
{
	struct iface	*iface = NULL;
	int		 succ  = 0;
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		if (pkt_send_if(pkt, iface, NULL) == -1)
			log_warnx("Can't send packet through %s", iface->name);
		else
			succ++;
	}
	/* If we couldn't send to a single iface, consider an error */
	if (succ == 0)
		return (-1);
	return (0);
}

void
pkt_init(struct pkt *pkt)
{
	bzero(pkt, sizeof(*pkt));
	LIST_INIT(&pkt->qlist);
	LIST_INIT(&pkt->anlist);
	LIST_INIT(&pkt->nslist);
	LIST_INIT(&pkt->arlist);
}

void
pkt_cleanup(struct pkt *pkt)
{
	struct rr	*rr;
	struct question *qst;
	
	while ((qst = LIST_FIRST(&pkt->qlist)) != NULL) {
		LIST_REMOVE(qst, entry);
		free(qst);
	}
	while ((rr = LIST_FIRST(&pkt->anlist)) != NULL) {
		LIST_REMOVE(rr, pentry);
		free(rr);
	}
	while ((rr = LIST_FIRST(&pkt->nslist)) != NULL) {
		LIST_REMOVE(rr, pentry);
		free(rr);
	}
	while ((rr = LIST_FIRST(&pkt->arlist)) != NULL) {
		LIST_REMOVE(rr, pentry);
		free(rr);
	}
}

/* packet building */
void
pkt_add_question(struct pkt *pkt, struct question *qst)
{
	LIST_INSERT_HEAD(&pkt->qlist, qst, entry);
	pkt->h.qdcount++;
}

void
pkt_add_anrr(struct pkt *pkt, struct rr *rr)
{
	LIST_INSERT_HEAD(&pkt->anlist, rr, pentry);
	pkt->h.ancount++;
}

void
pkt_add_nsrr(struct pkt *pkt, struct rr *rr)
{
	LIST_INSERT_HEAD(&pkt->nslist, rr, pentry);
	pkt->h.nscount++;
}

void
pkt_add_arrr(struct pkt *pkt, struct rr *rr)
{
	LIST_INSERT_HEAD(&pkt->arlist, rr, pentry);
	pkt->h.arcount++;
}

int
rr_set(struct rr *rr, char dname[MAXHOSTNAMELEN],
    u_int16_t type, u_int16_t class, u_int32_t ttl,
    int cacheflush, void *rdata, size_t rdlen)
{
	bzero(rr, sizeof(*rr));

	rr->rrs.type = type;
	rr->rrs.class = class;
	rr->ttl = ttl;
	rr->cacheflush = cacheflush;
	strlcpy(rr->rrs.dname, dname, sizeof(rr->rrs.dname));
	
	if (rdata != NULL) {
		if (rdlen > sizeof(rr->rdata)) {
			log_debug("rr_set: Invalid rdlen %zd", rdlen);
			return (-1);
		}
		memcpy(&rr->rdata, rdata, rdlen);
	}

	return (0);
}

int
rr_rdata_cmp(struct rr *rra, struct rr *rrb)
{
	if (rra->rrs.type != rrb->rrs.type)
		return (-1);
	if (rra->rrs.class != rrb->rrs.class)
		return (-1);
	
	switch (rra->rrs.type) {
	case T_A:
		return (rra->rdata.A.s_addr == rrb->rdata.A.s_addr);
		break;		/* NOTREACHED */
	case T_CNAME:
	case T_PTR:
	case T_NS:
	case T_TXT:
		return strcmp((char *) &rra->rdata, (char *) &rrb->rdata);
		break;		/* NOTREACHED */
	case T_SRV:
		if (rra->rdata.SRV.priority > rrb->rdata.SRV.priority)
			return (1);
		if (rra->rdata.SRV.priority < rrb->rdata.SRV.priority)
			return (-1);
		if (rra->rdata.SRV.weight > rrb->rdata.SRV.weight)
			return (1);
		if (rra->rdata.SRV.weight < rrb->rdata.SRV.weight)
			return (-1);
		if (rra->rdata.SRV.port > rrb->rdata.SRV.port)
			return (1);
		if (rra->rdata.SRV.port < rrb->rdata.SRV.port)
			return (-1);
		return strcmp(rra->rdata.SRV.target, rrb->rdata.SRV.target);
	case T_HINFO:
		if (strcmp(rra->rdata.HINFO.cpu, rrb->rdata.HINFO.cpu) != 0)
			return (strcmp(rra->rdata.HINFO.cpu,
			    rrb->rdata.HINFO.cpu));
		if (strcmp(rra->rdata.HINFO.os, rrb->rdata.HINFO.os) != 0)
			return (strcmp(rra->rdata.HINFO.os,
			    rrb->rdata.HINFO.os));
	default:
		log_warnx("Unknown rr->type (%d), can't compare",
		    rra->rrs.type);
		fatalx("Fatal, won't accept bogus comparisons");
		break;
	}
}

u_int32_t
rr_ttl_left(struct rr *rr)
{
	struct timespec tnow;
	struct timespec tr;
	    
	if (clock_gettime(CLOCK_MONOTONIC, &tnow))
		fatal("clock_gettime");
	timespecsub(&tnow, &rr->age, &tr);
	
	return (rr->ttl - (u_int32_t)tr.tv_sec);
}

struct rr *
rr_dup(struct rr *rr)
{
	struct rr *rdup;

	if ((rdup = malloc(sizeof(*rdup))) == NULL)
		fatal("malloc");
	memcpy(rdup, rr, sizeof(*rdup));
	
	return (rdup);
}

int
pkt_parse_header(u_int8_t **pbuf, u_int16_t *len, struct pkt *pkt)
{
	u_int8_t *buf = *pbuf;

	/* MDNS header sanity check */
	if (*len < HDR_LEN) {
		log_debug("pkt_parse_header: bad packet size %u", len);
		return (-1);
	}
	pkt->h = *((HEADER *) buf);
	header_ntohs(&pkt->h);
	*len  -= HDR_LEN;
	*pbuf += HDR_LEN;

	return (0);
}

int
pkt_parse_question(u_int8_t **pbuf, u_int16_t *len, struct pkt *pkt)
{
	u_int16_t	 us;
	struct question *qst;
	ssize_t		 n;

	/* MDNS question sanity check */
	if (*len < MINQRY_LEN) {
		log_debug("pkt_parse_question: bad query packet size %u", *len);
		return (-1);
	}

	if ((qst = calloc(1, sizeof(*qst))) == NULL)
		fatal("calloc");
	
	n = pkt_parse_dname(*pbuf, *len, qst->rrs.dname);
	if (n == -1) {
		free(qst);
		return (-1);
	}

	*pbuf += n;
	*len  -= n;

	GETSHORT(qst->rrs.type, *pbuf);
	*len -= INT16SZ;

	GETSHORT(us, *pbuf);
	*len -= INT16SZ;

	/* Deal with legacy packets */
	if (pkt->flags & PKT_FLAG_LEGACY) {
		qst->flags |= QST_FLAG_UNIRESP;
		qst->rrs.class = us;
	} else { /* Normal MDNS packets */
		if (us & UNIRESP_MSK) 
			qst->flags |= QST_FLAG_UNIRESP;
		/* Get the class */
		qst->rrs.class = us & CLASS_MSK;
	}

	/* This really sucks, we can't know if the class is valid prior to
	 * parsing the labels, I mean, we could but would be ugly */
	if (qst->rrs.class != C_ANY && qst->rrs.class != C_IN) {
		log_warnx("pkt_parse_question: Invalid packet qclass %u",
		    qst->rrs.class);
		free(qst);
		return (-1);
	}

	LIST_INSERT_HEAD(&pkt->qlist, qst, entry);

	return (0);
}

ssize_t
pkt_parse_dname(u_int8_t *buf, u_int16_t len, char dname[MAXHOSTNAMELEN])
{
	size_t i;
	u_int8_t lablen;
	int jumped = 0;
	u_int16_t oldlen = len;
	size_t slen;
	u_char label[MAXLABELLEN];

	/* be extra safe */
	bzero(dname, MAXHOSTNAMELEN);

	for (i = 0; i < MAXLABELS; i++) {
		/* check if head is a pointer */
		if (*buf & NAMECOMP_BYTE_MSK) {
			u_int16_t us, ncoff;

			GETSHORT(us, buf);
			if (!jumped)
				len -= INT16SZ;
			ncoff = us & NAMEADDR_MSK;
			/*
			 * Prevent the following:
			 * 1. Pointers should only point backward.
			 * 2. No pointer should point past buf.
			 */
			if (ncoff > pktcomp.len - len) {
				log_warnx("Invalid NC pointer");
				return (-1);
			}
			buf = pktcomp.start + ncoff;
			jumped = 1;
		}
		
		/*
		 * XXX No support for multiple pointers yet.
		 */
		if (*buf & NAMECOMP_BYTE_MSK) {
			log_warnx("I can't cope with multiple compression"
			    " pointers");
			return (-1);
		}

		lablen = *buf++;

		if (lablen > sizeof(label) ||
		    buf + lablen > pktcomp.start + pktcomp.len) {
			log_warnx("Invalid lablen, too big");
			return (-1);
		}
			
		if (!jumped)
			len--;

		if (lablen == 0) {
			/* remove the trailling dot */
			slen = strlen(dname);
			if (slen > 0)
				dname[slen - 1] = '\0';
			break;
		}

		if (lablen > (MAXHOSTNAMELEN - strlen(dname)) ||
		    lablen > MAXLABELLEN - 1) {
			log_warnx("label won't fit");
			return (-1);
		}
		memcpy(label, buf, lablen);
		label[lablen] = '\0';
		/* strlcat needs a proper C string in src */
		if (strlcat(dname, label, MAXHOSTNAMELEN) >= MAXHOSTNAMELEN)  {
			log_warnx("domain-name truncated");
			return (-1);
		}

		/* should we leave the dot on the last tag ? */
		if (strlcat(dname, ".", MAXHOSTNAMELEN) >= MAXHOSTNAMELEN) {
			log_warnx("domain-name truncated");
			return (-1);
		}

		buf += lablen;
		if (!jumped)
			len -= lablen;
	}

	if (i == MAXLABELS) {
		log_warnx("max labels reached");
		return (-1);
	}

	return (oldlen - len);
}


/* XXX: This function lacks some comments */
int
pkt_parse_rr(u_int8_t **pbuf, u_int16_t *len, struct rr *rr)
{
	u_int16_t us, rdlen, tmplen;
	u_int32_t ul;
	ssize_t n;
	char *buf;

	n = pkt_parse_dname(*pbuf, *len, rr->rrs.dname);
	if (n == -1)
		return (-1);
	*pbuf += n;
	*len  -= n;
	/* Make sure rr packet len is ok */
	if (*len < 8) {
		log_debug("Unexpected packet len");
		return (-1);
	}
	GETSHORT(rr->rrs.type, *pbuf);
	*len -= INT16SZ;
	GETSHORT(us, *pbuf);
	*len -= INT16SZ;
	rr->cacheflush = !!(us & CACHEFLUSH_MSK);
	rr->rrs.class  = us & CLASS_MSK;
	if (rr->rrs.class != C_ANY && rr->rrs.class != C_IN) {
		log_debug("pkt_parse_rr: %s (%s) Invalid packet class %u",
		    rr_type_name(rr->rrs.type), rr->rrs.dname, rr->rrs.class);
		return (-1);
	}
	GETLONG(rr->ttl, *pbuf);
	*len -= INT32SZ;
	GETSHORT(rdlen, *pbuf);
	*len -= INT16SZ;
	if (*len < rdlen) {
		log_debug("Invalid rr data length, *len = %u, rdlen = %u",
		    *len, rdlen);
		return (-1);
	}
	switch (rr->rrs.type) {
	case T_A:
		buf = *pbuf;
		if (rdlen != INT32SZ) {
			log_debug("Invalid A record rdlen %u", rdlen);
			return (-1);
		}
		GETLONG(ul, buf);
		rr->rdata.A.s_addr = htonl(ul);
		break;
	case T_HINFO:
		if ((n = charstr(rr->rdata.HINFO.cpu, *pbuf, rdlen)) == -1)
			return (-1);
		if ((n = charstr(rr->rdata.HINFO.os, *pbuf + n,
		    rdlen - n)) == -1)
			return (-1);
		break;
	case T_CNAME:
		if (rr_parse_dname(*pbuf, *len,
		    rr->rdata.CNAME) == -1)
			return (-1);
		break;
	case T_PTR:
		if (rr_parse_dname(*pbuf, *len,
		    rr->rdata.PTR) == -1)
			return (-1);
		break;
	case T_TXT:
		if ((n = charstr(rr->rdata.TXT, *pbuf, rdlen)) == -1)
			return (-1);
		break;
	case T_NS:
		if (rr_parse_dname(*pbuf, *len,
		    rr->rdata.NS) == -1)
			return (-1);
		break;
	case T_SRV:
		buf = *pbuf;
		tmplen = *len;
		GETSHORT(rr->rdata.SRV.priority, buf);
		tmplen -= INT16SZ;
		GETSHORT(rr->rdata.SRV.weight, buf);
		tmplen -= INT16SZ;
		GETSHORT(rr->rdata.SRV.port, buf);
		tmplen -= INT16SZ;
		if (rr_parse_dname(buf, tmplen, rr->rdata.SRV.target) == -1)
			return (-1);
		break;
	case T_AAAA:
	case T_NSEC:
		break;
	default:
		log_debug("Unknown record type %u", rr->rrs.type);
		return (-1);
		break;
	}

	*len  -= rdlen;
	*pbuf += rdlen;

	return (0);
}

int
pkt_handle_qst(struct pkt *pkt)
{
	struct question		*qst, *lqst;
	struct rr		*rr;
	struct pkt		 sendpkt;
	struct sockaddr_in	 dst, *pdst;

	/* TODO: Mdns draft 6.3 Duplicate Question Suppression */
	
	pkt_init(&sendpkt);
	sendpkt.h.qr = MDNS_RESPONSE;
	sendpkt.iface = pkt->iface;
	bzero(&dst, sizeof(dst));
	pdst = NULL;
	
	/* If legacy packet, we must copy id and answer as unicast dns  */
	if (pkt->flags & PKT_FLAG_LEGACY) {
		sendpkt.flags = pkt->flags;
		sendpkt.h.id = pkt->h.id;
		dst = pkt->ipsrc;
		pdst = &dst;
	}
		
	while ((qst = LIST_FIRST(&pkt->qlist)) != NULL) {
		/*
		 * Discard questions which shouldn't be handled, can be a
		 * probing query or we may be already listed in the known answer
		 * supression list.
		 */
		if (!pkt_should_answer_qst(pkt, qst)) {
			LIST_REMOVE(qst, entry);
			free(qst);
			continue;
		}
		
		/*
		 * XXX: This assumes that every question came from the same
		 * packet, hence, the same source. It also assumes QU questions
		 * may not be mixed up with QM questions, maybe this flag should
		 * be moved to pkt.
		 */
		if (qst->flags & QST_FLAG_UNIRESP) {
			dst = pkt->ipsrc;
			pdst = &dst;
		}

		/*
		 * XXX: O(n), make this a tree some day.
		 */
		LIST_FOREACH(rr, &pkt->iface->auth_rr_list, centry) {
			if (!ANSWERS(&qst->rrs, &rr->rrs))
				continue;
			
			/* Make a copy since we may modify if PKT_F_LEGACY */
			rr = rr_dup(rr);
			/*
			 * If this is a legacy question, get a copy rr, remove
			 * the cacheflush bit and copy the qid from question.
			 */
			if (pkt->flags & PKT_FLAG_LEGACY) {
				/* Include a copy of question */
				if ((lqst = calloc(1, sizeof(*lqst))) == NULL)
					fatal("calloc");
				/* No flags, since we don't want any bits set */
				lqst->flags = 0;
				lqst->rrs   = qst->rrs;
				pkt_add_question(&sendpkt, lqst);
				rr->cacheflush = 0;
				/* Draft says up to 10 */
				rr->ttl = 8;
			} 
			/* Add to response packet */
			pkt_add_anrr(&sendpkt, rr);
		}
		
		LIST_REMOVE(qst, entry);
		free(qst);
	}
	
	/*
	 * If we have answers, send it.
	 */
	if (sendpkt.h.ancount > 0)
		if (pkt_send_if(&sendpkt, sendpkt.iface, pdst) == -1)
			log_warnx("Can't send packet to"
			    "%s", pkt->iface->name);
	
	/* Cleanup our pkt since the RRs were dupped */
	pkt_cleanup(&sendpkt);

	return (0);
}

int
pkt_should_answer_qst(struct pkt *pkt, struct question *qst)
{
	struct rr *rr, *rrans;
	
	/*
	 * If this packet isn't a query, don't even think of answering.
	 */
	if (pkt->h.qr == MDNS_RESPONSE)
		return (0);
	/*
	 * If this is a legacy pkt, we must answer
	 */
	if (pkt->flags & PKT_FLAG_LEGACY)
		return (1);
	/*
	 * If this question belongs to a probe packet, that is, if an answer to
	 * this question resides in the packet authority section, we're not
	 * supposed to answer.
	 */
	LIST_FOREACH(rr, &pkt->nslist, pentry)
		if (ANSWERS(&qst->rrs, &rr->rrs))
			return (0);
	/*
	 * Check if the answer we would give isn't already in the known answer
	 * supression list, that is, check that the answer isn't in the answer
	 * section with a ttl at least half the original value. 
	 */
	rrans = auth_lookup_rr(pkt->iface, &qst->rrs);
	/* We've no answers for it, we should try to answer, but we
	 * already know we can't so return 0, this is a speed hack. */
	if (rrans == NULL)
		return (0);
	/* So we have an answer, see if we're listed in the known answer
	   supression list */
	LIST_FOREACH(rr, &pkt->anlist, pentry) {
		/* will compare type/class/data */
		if (rr_rdata_cmp(rr, rrans) != 0)
			continue;
		if (rr->ttl < (rrans->ttl / 2))
			return (1);
		else
			return (0);
	}
	
	return (1);
}

int
rr_parse_dname(u_int8_t *buf, u_int16_t len, char dname[MAXHOSTNAMELEN])
{
	if (pkt_parse_dname(buf, len, dname) == -1) {
		log_warnx("rr_parse_dname: pkt_parse_dname error");
		return (-1);
	}

	return (0);
}

ssize_t
serialize_dname(u_int8_t *buf, u_int16_t len, char dname[MAXHOSTNAMELEN],
    int compress)
{
	char *end;
	char *dbuf = dname;
	u_int8_t tlen;
	u_int8_t *pbuf = buf;
	struct namecomp *nc;
	
	/* Try to compress this name */
	
	if (compress &&
	    (nc = pktcomp_lookup(dname)) != NULL) {
		PUTSHORT(nc->offset, pbuf);
		len -= INT16SZ;
		return (pbuf - buf);
	}
	
	do {
		if ((end = strchr(dbuf, '.')) == NULL) {
			if ((end = strchr(dbuf, '\0')) == NULL)
				fatalx("serialize_dname: bad dname");
		}

		tlen  = end - dbuf;
		*pbuf++ = tlen;
		if (tlen > len)
			return (-1);
		memcpy(pbuf, dbuf, tlen);
		len  -= tlen;
		pbuf += tlen;
		dbuf  = end + 1;
	} while (*end != '\0');

	if (len == 0)
		return (-1);
	*pbuf++ = '\0';		/* null terminate dname */
	len--;
	
	/*
	 * Add dname to name compression, buf - pktcomp->start, should give us
	 * the correct offset in the current packet.
	 */
	if (compress)
		if (pktcomp_add(dname, (u_int16_t) (buf - pktcomp.start))
		    == -1)
			log_warnx("pktcomp_add error: %s", dname);
	
	return (pbuf - buf);
}

ssize_t
serialize_rdata(struct rr *rr, u_int8_t *buf, u_int16_t len)
{
	u_int8_t	*prdlen, *pbuf = buf;
	ssize_t		 n;
	u_int16_t	 rdlen = 0;
	u_int8_t	 cpulen, oslen;

	switch (rr->rrs.type) {
	case T_HINFO:
		cpulen = strlen(rr->rdata.HINFO.cpu);
		oslen = strlen(rr->rdata.HINFO.os);
		rdlen = cpulen + oslen + 2;	/* 2 length octets */
		if (len < rdlen)
			return (-1);
		PUTSHORT(rdlen, pbuf);
		len -= 2;
		/* fill cpu */
		*pbuf++ = cpulen;
		len--;
		memcpy(pbuf, rr->rdata.HINFO.cpu, cpulen);
		pbuf += cpulen;
		len  -= cpulen;
		/* fill os */
		*pbuf++ = oslen;
		len--;
		memcpy(pbuf, rr->rdata.HINFO.os, oslen);
		pbuf += oslen;
		len  -= oslen;
		break;
	case T_PTR:
	case T_TXT:
		prdlen = pbuf;
		/* jump over rdlen */
		pbuf += INT16SZ;
		len  -= INT16SZ;
		/* NOTE rr->rdata.PTR == rr->rdata.TXT */
		if ((n = serialize_dname(pbuf, len,
		    rr->rdata.PTR, 1)) == -1)
			return (-1);
		rdlen = n;
		pbuf += rdlen;
		len  -= rdlen;
		PUTSHORT(rdlen, prdlen);
		break;
	case T_A:
		rdlen = INT32SZ;
		if (len < (rdlen + INT16SZ)) /* INT16SZ is rdlen itself */
			return (-1);
		PUTSHORT(rdlen, pbuf);
		len -= 2;
		memcpy(pbuf, &rr->rdata, rdlen);
		pbuf += rdlen;
		len  -= rdlen;
		break;
	case T_SRV:
		prdlen = pbuf;
		/* jump over rdlen */
		if (len < INT16SZ)
			return (-1);
		pbuf += INT16SZ;
		len  -= INT16SZ;
		if (len < INT16SZ * 3)
			return (-1);
		PUTSHORT(rr->rdata.SRV.priority, pbuf);
		len   -= INT16SZ;
		rdlen += INT16SZ;
		PUTSHORT(rr->rdata.SRV.weight, pbuf);
		len   -= INT16SZ;
		rdlen += INT16SZ;
		PUTSHORT(rr->rdata.SRV.port, pbuf);
		len   -= INT16SZ;
		rdlen += INT16SZ;
		if ((n = serialize_dname(pbuf, len,
		    rr->rdata.SRV.target, 0)) == -1)
			return (-1);
		rdlen += n;
		pbuf  += n;
		len   -= n;
		PUTSHORT(rdlen, prdlen);
		break;
	default:
		log_warnx("serialize_rdata: Don't know how to serialize %s (%d)",
		    rr_type_name(rr->rrs.type), rr->rrs.type);
		return (-1);
		break;		/* NOTREACHED */
	}
	return (pbuf - buf);
}

ssize_t
serialize_rr(struct rr *rr, u_int8_t *buf, u_int16_t len)
{
	u_int8_t	*pbuf = buf;
	u_int16_t	 us   = 0;
	ssize_t		 n;

	n = serialize_dname(pbuf, len, rr->rrs.dname, 1);
	if (n == -1 || n > len)
		return (-1);
	pbuf += n;
	len  -= n;
	if (len == 0)
		return (-1);

	if (len < 8) /* must fit type, class, ttl */
		return (-1);
	PUTSHORT(rr->rrs.type, pbuf);
	us = rr->rrs.class;
	if (rr->cacheflush)
		us |= CACHEFLUSH_MSK;
	PUTSHORT(us, pbuf);
	PUTLONG(rr->ttl, pbuf);
	len -= 8;

	n = serialize_rdata(rr, pbuf, len);
	if (n == -1 || n > len)
		return (-1);
	pbuf += n;
	len  -= n;

	return (pbuf - buf);
}

ssize_t
serialize_qst(struct question *qst, u_int8_t *buf, u_int16_t len)
{
	u_int8_t *pbuf = buf;
	u_int16_t qclass;
	ssize_t n;

	n = serialize_dname(pbuf, len, qst->rrs.dname, 1);
	if (n == -1 || n > len)
		return (-1);
	pbuf += n;
	len  -= n;
	if (len == 0)
		return (-1);

	if (len < 4)	/* must fit type, class */
		return (-1);
	PUTSHORT(qst->rrs.type, pbuf);
	
	qclass = qst->rrs.class;
	if (qst->flags & QST_FLAG_UNIRESP)
		qclass = qst->rrs.class | UNIRESP_MSK;
	PUTSHORT(qclass, pbuf);

	return (pbuf - buf);
}

void
header_htons(HEADER *h)
{
	h->qdcount = htons(h->qdcount);
	h->ancount = htons(h->ancount);
	h->nscount = htons(h->nscount);
	h->arcount = htons(h->arcount);
}

void
header_ntohs(HEADER *h)
{
	h->qdcount = ntohs(h->qdcount);
	h->ancount = ntohs(h->ancount);
	h->nscount = ntohs(h->nscount);
	h->arcount = ntohs(h->arcount);
}

/* Packet compression */
void
pktcomp_reset(int first, u_int8_t *start, u_int16_t len)
{
	struct namecomp *nc;
	
	while ((nc = LIST_FIRST(&pktcomp.namecomp_list)) != NULL) {
		LIST_REMOVE(nc, entry);
		free(nc);
	}
	pktcomp.start = start;
	pktcomp.len = len;
}

int
pktcomp_add(char dname[MAXHOSTNAMELEN], u_int16_t offset)
{
	struct namecomp *nc;

	if ((nc = calloc(1, sizeof(*nc))) == NULL)
		fatal("calloc");
	strlcpy(nc->dname, dname, sizeof(nc->dname));
	nc->offset = offset | NAMECOMP_MSK;
	LIST_INSERT_HEAD(&pktcomp.namecomp_list, nc, entry);
	
	return (0);
}

struct namecomp *
pktcomp_lookup(char dname[MAXHOSTNAMELEN])
{
	struct namecomp *nc;
	
	LIST_FOREACH(nc, &pktcomp.namecomp_list, entry) {
		if (strcmp(nc->dname, dname) == 0)
			return (nc);
	}
	
	return (NULL);
}

/* Util */
ssize_t
charstr(char dest[MAXCHARSTR], u_int8_t *buf, u_int16_t len)
{
	u_int8_t tocpy;

	tocpy = *buf++;

	if (tocpy > len) {
		log_debug("tocpy: %u > len: %u", tocpy, len);
		return (-1);
	}

	/* This isn't a case for strlcpy */
	memcpy(dest, buf, tocpy);
	dest[tocpy] = '\0';	/* Assure null terminated */

	return (tocpy + 1);
}

