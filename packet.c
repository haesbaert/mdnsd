/*
 * Copyright (c) 2010 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2006 Michele Marchetto <mydecay@openbeer.it>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
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
#include "mdns.h"
#include "log.h"

/* extern struct mdnsd_conf *conf; */
struct mdnsd_conf *conf;

/* used in name compression */
struct {
	u_int8_t *start;
	u_int16_t len;
} pktcomp;

static struct iface	*find_iface(unsigned int, struct in_addr);

static void	pkt_init(struct mdns_pkt *);
static int	pkt_parse_header(u_int8_t **, u_int16_t *, struct mdns_pkt *);
static int	pkt_parse_labels(u_int8_t **, u_int16_t *, u_char *[], size_t);
static int	pkt_parse_question(u_int8_t **, u_int16_t *, struct mdns_pkt *);
static int	pkt_parse_allrr(u_int8_t **, u_int16_t *, struct mdns_pkt *);
static int	pkt_parse_rr(u_int8_t **, u_int16_t *, struct mdns_pkt *,
    struct mdns_rr *);
static void	free_labels(u_char *[], size_t);
static int	rr_parse_hinfo(struct mdns_rr *, u_int8_t *);
static int	rr_parse_a(struct mdns_rr *, u_int8_t *);
static int	rr_parse_cname(struct mdns_rr *, u_int8_t *, u_int16_t);
	

/* send and receive packets */
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
		log_warn("send_packet: error sending packet on interface %s",
		    iface->name);
		return (-1);
	}

	return (0);
}

void
recv_packet(int fd, short event, void *bula)
{
	union {
		struct cmsghdr hdr;
		char	buf[CMSG_SPACE(sizeof(struct sockaddr_dl))];
	} cmsgbuf;
	struct sockaddr_in	 src;
	struct iovec		 iov;
	struct msghdr		 msg;
	struct cmsghdr		*cmsg;
	struct sockaddr_dl	*dst = NULL;
	struct iface		*iface;
	struct mdns_pkt		 pkt;
	static u_int8_t		buf[MDNS_MAX_PACKET];
	ssize_t			 r;
	u_int16_t		 len, srcport;
	static int pktnum = 0;
	
	if (event != EV_READ)
		return;

	bzero(&msg, sizeof(msg));
	bzero(buf, sizeof(buf));

	iov.iov_base = buf;
	iov.iov_len = MDNS_MAX_PACKET;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
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
			break;
		}
	}

	if (dst == NULL)
		return;
	
	len = (u_int16_t)r;

	/* Check the packet is not from one of the local interfaces */
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		if (iface->addr.s_addr == src.sin_addr.s_addr)
			return;
	}

	/* find a matching interface */
	if ((iface = find_iface(dst->sdl_index, src.sin_addr)) == NULL) {
		log_warn("recv_packet: cannot find a matching interface");
		return;
	}
	
/* 	log_debug("read %zd bytes from iface %s", r, iface->name); */

	srcport = ntohs(src.sin_port);
	
/* 	log_debug("buf is at %p", buf); */
	log_debug("###### PACKET %d #####", ++pktnum);
	if (pkt_parse(buf, len, &pkt) == -1)
		return;
	
	/* finish me */
}

static struct iface *
find_iface(unsigned int ifindex, struct in_addr src)
{
	struct iface	*iface = NULL;

	/* returned interface needs to be active */
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		if (ifindex				      != 0 && ifindex == iface->ifindex &&
		    (iface->addr.s_addr & iface->mask.s_addr) == 
		    (src.s_addr & iface->mask.s_addr))
			/*
			 * XXX may fail on P2P links because src and dst don't
			 * have to share a common subnet on the otherhand
			 * checking something like this will help to support
			 * multiple networks configured on one interface.
			 */
			return (iface);
	}

	return (NULL);
}

static void
pkt_init(struct mdns_pkt *pkt)
{
	bzero(pkt, sizeof(*pkt));
	SIMPLEQ_INIT(&pkt->qlist);
	SIMPLEQ_INIT(&pkt->anlist);
	SIMPLEQ_INIT(&pkt->nslist);
	SIMPLEQ_INIT(&pkt->arlist);
}

int
pkt_parse(u_int8_t *buf, uint16_t len, struct mdns_pkt *pkt)
{
	u_int16_t		 i;
	struct mdns_question	*mq;
	
	pkt_init(pkt);
	pktcomp.start = buf;
	pktcomp.len = len;
	
	log_debug("pktcomp.start + 0xfb = 0x%x", *(pktcomp.start + 0xfb));
	if (pkt_parse_header(&buf, &len, pkt) == -1)
		return -1;
	
	/* Parse question section */
	for (i = 0; i < pkt->qdcount; i++)
		if (pkt_parse_question(&buf, &len, pkt) == -1)
			return -1;
	
	/* Question count sanity check */
	i = 0;
	SIMPLEQ_FOREACH(mq, &pkt->qlist, entry)
		i++;

	if (i != pkt->qdcount) {
		log_debug("found less questions than advertised");
		/* clean up */
		while ((mq = SIMPLEQ_FIRST(&pkt->qlist)) != NULL) {
			SIMPLEQ_REMOVE_HEAD(&pkt->qlist, entry);
			free_labels(mq->labels, mq->nlabels);
			free(mq);
		}
		
		return -1;
	}
	
	if (pkt->qdcount > 0)
		log_debug_pkt(pkt);
	
	/* Parse RR sections */
	if (pkt_parse_allrr(&buf, &len, pkt) == -1)
		return -1;
	
	return 0;
}

static int
pkt_parse_header(u_int8_t **pbuf, u_int16_t *len, struct mdns_pkt *pkt)
{
	HEADER *qh;
	u_int8_t *buf = *pbuf;
	
	/* MDNS header sanity check */
	if (*len < MDNS_HDR_LEN) {
		log_debug("recv_packet: bad packet size %u", len);
		return -1;
	}
	
	qh = (HEADER *) buf;

	pkt->id = ntohs(qh->id);
	pkt->qr = qh->qr;
	pkt->tc = qh->tc;
	pkt->qdcount = ntohs(qh->qdcount);
	pkt->ancount = ntohs(qh->ancount);
	pkt->nscount = ntohs(qh->nscount);
	pkt->arcount = ntohs(qh->arcount);
	
	*len -= MDNS_HDR_LEN;
	*pbuf += MDNS_HDR_LEN;

	return 0;
}

static int
pkt_parse_question(u_int8_t **pbuf, u_int16_t *len, struct mdns_pkt *pkt)
{
	u_int16_t i, us;
	struct mdns_question *mq;
	u_int8_t *buf = *pbuf;
	
	/* MDNS question sanity check */
	if (*len < MDNS_MINQRY_LEN) {
		log_debug("pkt_parse_question: bad query packet size %u", *len);
		return -1;
	}
	
	if ((mq = calloc(1, sizeof(*mq))) == NULL)
		fatal("calloc");
	
	mq->nlabels = pkt_parse_labels(pbuf, len, mq->labels, MDNS_MAX_LABELS);
	if (mq->nlabels == -1) {
		free(mq);
		return -1;
	}
	
	GETSHORT(mq->qtype, *pbuf);
	*len -= INT16SZ;
	log_debug("qtype = %u", mq->qtype);
	
	GETSHORT(us, *pbuf);
	*len -= INT16SZ;
	
	mq->uniresp = !!(us & UNIRESP_MSK);
	mq->qclass = us & CLASS_MSK;

	log_debug("uniresp = %d", mq->uniresp);
	log_debug("qclass = %u", mq->qclass);
	
	*pbuf = buf;
	/* This really sucks, we can't know if the class is valid prior to
	 * parsing the labels, I mean, we could but would be ugly */
	if (mq->qclass != C_ANY && mq->qclass != C_IN) {
		log_debug("pkt_parse_question: Invalid packet qclass %u", mq->qclass);
		free_labels(mq->labels, mq->nlabels);
		free(mq);
		return -1;
	}
	
	for (i = 0; i < mq->nlabels; i++) {
		strlcat(mq->name, (const u_char *)mq->labels[i],
		    sizeof(mq->name));
		if (i != mq->nlabels)
			strlcat(mq->name, ".", sizeof(mq->name));
	}

	SIMPLEQ_INSERT_TAIL(&pkt->qlist, mq, entry);
	
	return 0;
}

/* 
 * RFC defines no max number of labels, but 128 is enough isn't ?
 * but, each label must be no greater than MAXLABEL and their sum can'
 * be higher than MAXHOSTNAMELEN.
 */
static int
pkt_fetch_ptr(u_int8_t *head, u_int16_t len, u_char *labels[], size_t n)
{
	u_int16_t	 us = 0;
	u_int16_t	 llen;
	size_t		 i;
	u_char		*buf;
	
	
	for (i = 0; i < n; i++) {
		if (!(*head & 0xc0)) /* make sure head is a pointer */
			break;
		
		GETSHORT(us, head);
		buf =  pktcomp.start + (us & NAMEADDR_MSK);
	
		llen = *buf++;
		
		if (llen > MAXLABEL) {
			log_debug("llen insane: %u us = 0x%x", llen, us);
			return -1;
		}
		
		if (llen == 0)	/* The end */
			break;
		
		if ((labels[i] = malloc(llen + 1)) == NULL)
			fatal("malloc");
		bzero(labels[i], llen + 1); /* NULL terminated */
		memcpy(labels[i], buf, llen);
		
		buf += llen;
		head = buf;
/* 		log_debug("proximo byte = 0x%x ", *buf); */
	}

	return 0;
}
	
static int
pkt_parse_labels(u_int8_t **pbuf, u_int16_t *len, u_char *labels[], size_t n)
{
	size_t		 i;
	u_int16_t	 llen, tlen;
	u_int8_t	*lptr;
	u_int8_t	*start = *pbuf;
	u_int8_t	*buf = *pbuf;
	
	for (i = 0, tlen = 0; i < n; i++) {
		if (*buf & 0xc0) {
			if (pkt_fetch_ptr(buf, *len, &labels[n - i],
			    n - i) == -1)
				return -1;
			buf  += INT16SZ; /* jump over ptr */
			*len -= INT16SZ;
			break;
		}
		
		llen = *buf++;
		tlen += llen;
		if (llen == 0) 	/* The end */
			break;
		
		/* *len is already wrong here, revise everything ! */
		if (tlen > MAXHOSTNAMELEN || llen > *len) {
			log_debug("len insane, llen: %u tlen: %u *len: %u", llen,
			    tlen, *len);
			return -1;
		}
		
		if ((lptr = malloc(llen + 1)) == NULL)
			fatal("malloc");
		bzero(lptr, llen + 1); /* NULL terminated */
		memcpy(lptr, buf, llen);
		labels[i] = lptr;
		
		buf  += llen;
		*len -= llen;

	}
	
	*pbuf += buf - start;
/* 	*len  -= buf - start; */
	
	return 0;
}

static int
pkt_parse_allrr(u_int8_t **pbuf, u_int16_t *len, struct mdns_pkt *pkt)
{
	u_int16_t i;
	struct mdns_rr rr;
	
	for (i = 0; i < pkt->ancount; i++) {
		bzero(&rr, sizeof(rr));
		log_debug("\n");
		if (pkt_parse_rr(pbuf, len, pkt, &rr) == -1) {
			log_debug("Can't parse RR");
			return -1;
		}
	}
	
	/* TODO parse rest of rr */
	return 0;
}

static int
pkt_parse_rr(u_int8_t **pbuf, u_int16_t *len, struct mdns_pkt *pkt,
    struct mdns_rr *rr)
{
	u_int16_t us;
	int r = 0;

	rr->nlabels = pkt_parse_labels(pbuf, len, rr->labels, MDNS_MAX_LABELS);
	if (rr->nlabels == -1) 
		return -1;
	
	/* Make sure rr packet len is ok */
	if (*len < 8) {
		log_debug("Unexpected packet len");
		return -1;
	}
	
	GETSHORT(rr->type, *pbuf);
	*len -= INT16SZ;

	GETSHORT(us, *pbuf);
	*len -= INT16SZ;
	
	rr->cacheflush = !!(us & CACHEFLUSH_MSK);
	rr->class = us & CLASS_MSK;
	
	if (rr->class != C_ANY && rr->class != C_IN) {
		free_labels(rr->labels, rr->nlabels);
		log_debug("pkt_parse_rr: Invalid packet class %u", rr->class);
		return -1;
	}

	GETLONG(rr->ttl, *pbuf);
	*len -= INT32SZ;
	log_debug("rr->ttl = %u 0x%x", rr->ttl, rr->ttl);


	GETSHORT(rr->rdlen, *pbuf);
	*len -= INT16SZ;
	log_debug("rr->rdlen = %u", rr->rdlen);
	
	if (*len < rr->rdlen) {
		log_debug("Invalid rr data length, *len = %u, rdlen = %u",
		    *len,rr->rdlen);
		return -1;
	}

	switch (rr->type) {
	case T_A:
		if (rr_parse_a(rr, *pbuf) == -1)
			return -1;
		log_debug("A record");
		break;
	case T_HINFO:
		log_debug("HINFO record");
		if (rr_parse_hinfo(rr, *pbuf) == -1)
			return -1;
		break;
	case T_CNAME:
		log_debug("got a CNAME record");
		if (rr_parse_cname(rr, *pbuf, *len) == -1)
			return -1;
		break;
	case T_PTR:
		log_debug("got a PTR record");
		break;
	case T_TXT:
		log_debug("got a TXT record");
		break;
	case T_NS:
		log_debug("got a NS record");
		break;
	case T_SRV:
		log_debug("got a SRV record");
		break;
	case T_AAAA:
		log_debug("got a AAAA record");
		break;
	default:
		log_debug("Unknown record type %u", rr->type);
		r = -1;
		break;
	}
	
	*len -= rr->rdlen;
	*pbuf += rr->rdlen;
	
	return r;
}

static void
free_labels(u_char *labels[], size_t n)
{
	size_t j;
	
	for (j = 0; j < n; j++) {
		free(labels[j]);
		labels[j] = NULL; /* Avoid a possible double free */
	}
}

void *
rrdata(struct mdns_rr *rr)
{
	switch (rr->type) {
	case T_A:
		return &rr->rdata.A;
		break;
	case T_HINFO:
		return &rr->rdata.HINFO;
		break;
	case T_CNAME:
		return &rr->rdata.CNAME;
		break;
	case T_PTR:
		return &rr->rdata.PTR;
		break;
	case T_SRV:
		return &rr->rdata.SRV;
		break;
	case T_TXT:
		return &rr->rdata.TXT;
		break;
	case T_NS:
		return &rr->rdata.NS;
		break;
	default:
		log_debug("Unknown type %d", rr->type);
		return NULL;
	}
}

static int
rr_parse_hinfo(struct mdns_rr *rr, u_int8_t *buf)
{
	ssize_t n;
	
	if ((n = charstr(rr->rdata.HINFO.cpu, buf, rr->rdlen)) == -1)
		return -1;
	log_debug("   cpu: %s", rr->rdata.HINFO.cpu);

	if ((n = charstr(rr->rdata.HINFO.os, buf + n, rr->rdlen - n)) == -1)
		return -1;
	log_debug("   os: %s",  rr->rdata.HINFO.os);
	
	return 0;
}
	
static int
rr_parse_a(struct mdns_rr *rr, u_int8_t *buf)
{
	u_int32_t ul;
	
	if (rr->rdlen != INT32SZ) {
		log_debug("Invalid A record rdlen %u", rr->rdlen);
		return -1;
	}
	
	GETLONG(ul, buf);
	rr->rdata.A.addr.s_addr = htonl(ul);
	
	log_debug("A record: %s", inet_ntoa(rr->rdata.A.addr));
	return 0;
	
}

static int
rr_parse_cname(struct mdns_rr *rr, u_int8_t *buf, u_int16_t len)
{

/* 	if (pkt_fetch_ptr(*buf, len, rr->rdata.CNAME.labels, */
/* 	    rr->rdata.CNAME.nlabels) == -1) { */
/* 		log_debug("Invalid CNAME record"); */
/* 		return -1; */
/* 	} */
		
	
	return 0;
	
}

ssize_t
charstr(char dest[MDNS_MAX_CHARSTR], u_int8_t *buf, uint16_t len)
{
	u_int8_t tocpy;
	
	tocpy = *buf++;
	
	if (tocpy > len) {
		log_debug("tocpy: %u > len: %u", tocpy, len);
		return -1;
	}
	
	/* This isn't a case for strlcpy */
	memcpy(dest, buf, tocpy);
	dest[tocpy] = '\0'; 	/* Assure null terminated */
	
	return tocpy + 1;
}
