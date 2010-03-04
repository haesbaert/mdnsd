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

extern struct mdnsd_conf *conf;
/* struct mdnsd_conf *conf; */

/* used in name compression */
struct {
	u_int8_t *start;
	u_int16_t len;
} pktcomp;

static struct iface	*find_iface(unsigned int, struct in_addr);

static int	pkt_parse(u_int8_t *, uint16_t, struct mdns_pkt *);
static int	pkt_parse_header(u_int8_t **, u_int16_t *, struct mdns_pkt *);
static ssize_t	pkt_parse_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN]);
static int	pkt_parse_question(u_int8_t **, u_int16_t *, struct mdns_pkt *);
static int	pkt_parse_rr(u_int8_t **, u_int16_t *, struct mdns_pkt *,
    struct mdns_rr *);
static int	pkt_process(struct mdns_pkt *);
static int	pkt_tryanswerq(struct mdns_pkt *);

static ssize_t  serialize_dname(char [MAXHOSTNAMELEN], u_int8_t *, u_int16_t);
static ssize_t	serialize_rr(struct mdns_rr *, u_int8_t *, u_int16_t);
static ssize_t	serialize_question(struct mdns_question *, u_int8_t *,
    u_int16_t);
static ssize_t	serialize_hinfo(struct mdns_rr *, u_int8_t *, u_int16_t);
static int	rr_parse_hinfo(struct mdns_rr *, u_int8_t *);
static int	rr_parse_a(struct mdns_rr *, u_int8_t *);
static int	rr_parse_txt(struct mdns_rr *, u_int8_t *);
static int	rr_parse_srv(struct mdns_rr *, u_int8_t *, uint16_t);
static int	rr_parse_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN]);
/* util */
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
		log_warn("send_packet: error sending packet on interface %s, len %zd",
		    iface->name, len);
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
	static u_int8_t		 buf[MDNS_MAX_PACKET];
	ssize_t			 r;
	u_int16_t		 len, srcport;
/* 	static int pktnum = 0; */
	
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
	
	srcport = ntohs(src.sin_port);
	
	if (pkt_parse(buf, len, &pkt) == -1)
		return;
	
	pkt_process(&pkt);
	/* process all shit */
}

int
pkt_send_allif(struct mdns_pkt *pkt)
{
	struct sockaddr_in	 dst;
	struct iface		*iface = NULL;
	u_int8_t		 buf[MDNS_MAX_PACKET];
	ssize_t			 n;
	
	inet_aton(ALL_MDNS_DEVICES, &dst.sin_addr);
	dst.sin_port   = htons(MDNS_PORT);
	dst.sin_family = AF_INET;
	dst.sin_len    = sizeof(struct sockaddr_in);

	LIST_FOREACH(iface, &conf->iface_list, entry) {
			bzero(buf, sizeof(buf));
			if ((n = pkt_serialize(pkt, buf, sizeof(buf))) == -1)
				return -1;
			if (send_packet(iface, buf, n, &dst) == -1)
				return -1;
	}
	
	return 0;
}

void
pkt_init(struct mdns_pkt *pkt)
{
	bzero(pkt, sizeof(*pkt));
	LIST_INIT(&pkt->qlist);
	LIST_INIT(&pkt->anlist);
	LIST_INIT(&pkt->nslist);
	LIST_INIT(&pkt->arlist);
}

/* packet building */
int
pkt_add_question(struct mdns_pkt *pkt, struct mdns_question *mq)
{
	/* can't have questions and answers in the same packet */
	if (pkt->ancount || pkt->nscount || pkt->arcount)
		return -1;
	LIST_INSERT_HEAD(&pkt->qlist, mq, entry);
	pkt->qdcount++;
	pkt->qr = 0;
	
	return 0;
}

int
pkt_add_anrr(struct mdns_pkt *pkt, struct mdns_rr *rr)
{
	if (pkt->qdcount)
		return -1;
	LIST_INSERT_HEAD(&pkt->anlist, rr, entry);
	pkt->ancount++;
	pkt->qr = 1;
	
	return 0;
}

int
pkt_add_nsrr(struct mdns_pkt *pkt, struct mdns_rr *rr)
{
	LIST_INSERT_HEAD(&pkt->nslist, rr, entry);
	pkt->nscount++;
	pkt->qr = 1;
	
	return 0;
}

int
pkt_add_arrr(struct mdns_pkt *pkt, struct mdns_rr *rr)
{
	if (pkt->qdcount)
		return -1;
	LIST_INSERT_HEAD(&pkt->arlist, rr, entry);
	pkt->arcount++;
	pkt->qr = 1;
	
	return 0;
}

int
question_set(struct mdns_question *mq, char dname[MAXHOSTNAMELEN],
    u_int16_t qtype, u_int16_t qclass, int uniresp, int probe)
{
	bzero(mq, sizeof(*mq));
	
	if (qclass != C_IN)
		return -1;
	mq->qclass  = qclass;
	mq->qtype   = qtype;
	mq->uniresp = uniresp;
	mq->probe   = probe;
	strlcpy(mq->dname, dname, sizeof(mq->dname));
	
	return 0;
}

int
rr_set(struct mdns_rr *rr, char dname[MAXHOSTNAMELEN],
    u_int16_t type, u_int16_t class, u_int32_t ttl,
    int cacheflush, void *rdata, size_t rdlen)
{
	bzero(rr, sizeof(*rr));

	rr->type = type;
	rr->class = class;
	rr->ttl = ttl;
	rr->cacheflush = cacheflush;
	if (rdlen > sizeof(rr->rdata)) {
		log_debug("rr_set: Invalid rdlen %zd", rdlen);
		return -1;
	}
	memcpy(&rr->rdata, rdata, rdlen);
	rr->rdlen = rdlen;
	strlcpy(rr->dname, dname, sizeof(rr->dname));
	
	return 0;
}

static struct iface *
find_iface(unsigned int ifindex, struct in_addr src)
{
	struct iface	*iface = NULL;

	/* returned interface needs to be active */
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		if (ifindex != 0 && ifindex == iface->ifindex &&
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

/* TODO: insert all sections at end, don't use LIST_INSERT_HEAD */
static int
pkt_parse(u_int8_t *buf, uint16_t len, struct mdns_pkt *pkt)
{
	u_int16_t		 i;
	struct mdns_question	*mq;
	struct mdns_rr		*rr;
	
	/* don't use pkt_init here, this is fine */
	pkt_init(pkt);
	pktcomp.start = buf;
	pktcomp.len = len;
	
	if (pkt_parse_header(&buf, &len, pkt) == -1)
		return -1;
	
	/* Parse question section */
	for (i = 0; i < pkt->qdcount; i++)
		if (pkt_parse_question(&buf, &len, pkt) == -1)
			return -1;
	
	/* Question count sanity check */
	i = 0;
	LIST_FOREACH(mq, &pkt->qlist, entry)
		i++;

	if (i != pkt->qdcount) {
		log_debug("found less questions than advertised");
		return -1;
	}
	
	/* Parse RR sections */
	for (i = 0; i < pkt->ancount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		if (pkt_parse_rr(&buf, &len, pkt, rr) == -1) {
			log_debug("Can't parse RR");
			free(rr);
			return -1;
		}
		LIST_INSERT_HEAD(&pkt->anlist, rr, entry);
	}
	
	for (i = 0; i < pkt->nscount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		if (pkt_parse_rr(&buf, &len, pkt, rr) == -1) {
			log_debug("Can't parse RR");
			free(rr);
			return -1;
		}
		LIST_INSERT_HEAD(&pkt->nslist, rr, entry);
	}

	for (i = 0; i < pkt->arcount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		if (pkt_parse_rr(&buf, &len, pkt, rr) == -1) {
			log_debug("Can't parse RR");
			free(rr);
			return -1;
		}
		
		LIST_INSERT_HEAD(&pkt->arlist, rr, entry);
	}

	if (len != 0) {
		log_debug("Couldn't read all packet, %u bytes left", len);
		return -1;
	}
		
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
	u_int16_t us;
	struct mdns_question *mq;
	ssize_t n;
	
	/* MDNS question sanity check */
	if (*len < MDNS_MINQRY_LEN) {
		log_debug("pkt_parse_question: bad query packet size %u", *len);
		return -1;
	}
	
	if ((mq = calloc(1, sizeof(*mq))) == NULL)
		fatal("calloc");
	
	n = pkt_parse_dname(*pbuf, *len, mq->dname);
	if (n == -1) {
		free(mq);
		return -1;
	}
	
	*pbuf += n;
	*len  -= n;
		
	GETSHORT(mq->qtype, *pbuf);
	*len -= INT16SZ;
	
	GETSHORT(us, *pbuf);
	*len -= INT16SZ;
	
	mq->uniresp = !!(us & UNIRESP_MSK);
	mq->qclass = us & CLASS_MSK;

	/* This really sucks, we can't know if the class is valid prior to
	 * parsing the labels, I mean, we could but would be ugly */
	if (mq->qclass != C_ANY && mq->qclass != C_IN) {
		log_debug("pkt_parse_question: Invalid packet qclass %u", mq->qclass);
		free(mq);
		return -1;
	}
	
	LIST_INSERT_HEAD(&pkt->qlist, mq, entry);
	
	return 0;
}

static ssize_t
pkt_parse_dname(u_int8_t *buf, u_int16_t len, char dname[MAXHOSTNAMELEN])
{
	size_t i;
	uint8_t lablen;
	int jumped = 0;
	uint16_t oldlen = len;
	u_char label[MAXLABEL + 1];
	
	/* be extra safe */
	bzero(dname, MAXHOSTNAMELEN);
	
	for (i = 0; i < MDNS_MAX_LABELS; i++) {
		/* check if head is a pointer */
		if (*buf & 0xc0) {
			u_int16_t us;
			
			GETSHORT(us, buf);
			if (!jumped)
				len -= INT16SZ;
			buf = pktcomp.start + (us & NAMEADDR_MSK);
			jumped = 1;
		}
		
		lablen = *buf++;
		
		if (!jumped)
			len--;
		
		if (lablen == 0)
			break;
		
		if (lablen > (MAXHOSTNAMELEN - strlen(dname)) ||
		    lablen > MAXLABEL) {
			log_debug("label won't fit");
			return -1;
		}
		memcpy(label, buf, lablen);
		label[lablen] = '\0';
		/* strlcat needs a proper C string in src */
		if (strlcat(dname, label, MAXHOSTNAMELEN) > MAXHOSTNAMELEN)  {
			log_debug("domain-name truncated");
			return -1;
		}
		
		/* should we leave the dot on the last tag ? */
		if (strlcat(dname, ".", MAXHOSTNAMELEN) > MAXHOSTNAMELEN) {
			log_debug("domain-name truncated");
			return -1;
		}
		
		buf += lablen;
		if (!jumped)
			len -= lablen;
	}
	
	if (i == MDNS_MAX_LABELS) {
		log_debug("max labels reached");
		return -1;
	}
	
	/* remove the trailling dot */
	if (len > 0)
		dname[strlen(dname) - 1] = '\0';

/* 	log_debug("oldlen: %u, len: %u", oldlen, len); */
	return oldlen - len;
}


static int
pkt_parse_rr(u_int8_t **pbuf, u_int16_t *len, struct mdns_pkt *pkt,
    struct mdns_rr *rr)
{
	u_int16_t us;
	ssize_t n;

	n = pkt_parse_dname(*pbuf, *len, rr->dname);
	if (n == -1)
		return -1;
	
	*pbuf += n;
	*len  -= n;
	
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
		log_debug("pkt_parse_rr: Invalid packet class %u", rr->class);
		return -1;
	}

	GETLONG(rr->ttl, *pbuf);
	*len -= INT32SZ;
	GETSHORT(rr->rdlen, *pbuf);
	*len -= INT16SZ;
	if (*len < rr->rdlen) {
		log_debug("Invalid rr data length, *len = %u, rdlen = %u",
		    *len,rr->rdlen);
		return -1;
	}

	switch (rr->type) {
	case T_A:
		if (rr_parse_a(rr, *pbuf) == -1)
			return -1;
		break;
	case T_HINFO:
		if (rr_parse_hinfo(rr, *pbuf) == -1)
			return -1;
		break;
	case T_CNAME:
		if (rr_parse_dname(*pbuf, *len,
		    rr->rdata.CNAME) == -1)
			return -1;
		break;
	case T_PTR:
		if (rr_parse_dname(*pbuf, *len,
		    rr->rdata.PTR) == -1)
			return -1;
		break;
	case T_TXT:
		if (rr_parse_txt(rr, *pbuf) == -1)
			return -1;
		break;
	case T_NS:
		if (rr_parse_dname(*pbuf, *len,
		    rr->rdata.NS) == -1)
			return -1;
		break;
	case T_SRV:
/* 		log_debug("SRV record"); */
/* 		if (rr->dname.nlabels < 3) { */
/* 			log_debug("SRV record expects a dname with" */
/* 			    "at least 3 labels, got %d", rr->dname.nlabels); */
/* 			return -1; */
/* 		} */
		if (rr_parse_srv(rr, *pbuf, *len) == -1)
			return -1;
		break;
	case T_AAAA:
		break;
	default:
		log_debug("Unknown record type %u 0x%x", rr->type, rr->type);
		return -1;
		break;
	}
	
	*len -= rr->rdlen;
	*pbuf += rr->rdlen;
	
	return 0;
}

static int
pkt_process(struct mdns_pkt *pkt)
{
	struct mdns_rr *rr;
	struct mdns_question *q;
	
	/* mark all probe questions, so we don't try to answer them below */
	while((rr = LIST_FIRST(&pkt->nslist)) != NULL) {
		LIST_FOREACH(q, &pkt->qlist, entry) {
			if (ANSWERS(q, rr))
				q->probe = 1;
		}
		LIST_REMOVE(rr, entry);
		free(rr);
	}
	
	/* process all questions */
	if (pkt_tryanswerq(pkt) == -1)
		log_warn("pkt_tryanswerq: error");
	
	/* process all answers */
	while ((rr = LIST_FIRST(&pkt->anlist)) != NULL) {
		LIST_REMOVE(rr, entry);
		cache_process(rr);
	}
	
	/* process additional section */
	/* TODO */
	
	return 0;
}

static int
pkt_tryanswerq(struct mdns_pkt *pkt)
{
	struct mdns_question	*q;
	struct mdns_rr		*rr;
	struct mdns_pkt		 sendpkt;
	
	pkt_init(&sendpkt);
	/* arghhh the following is too fucking ugly, please correct me */
	while ((q = LIST_FIRST(&pkt->qlist)) != NULL) {
		if (!q->probe) {
			log_debug("try answer: %s (type %s)", q->dname,
			    rr_type_name(q->qtype));
			/* look into published rr if we have it */
			rr = publish_lookupall(q->dname, q->qtype, q->qclass);
			if (rr != NULL && ANSWERS(q, rr)) {
				if (pkt_add_anrr(&sendpkt, rr) == -1)
					log_warn("Can't answer question for"
					    "%s %s",
					    q->dname, rr_type_name(q->qtype));
				if (pkt_send_allif(&sendpkt) == -1)
					log_debug("can't send packet to all interfaces");
			}
				
		}
		LIST_REMOVE(q, entry);
		free(q);
	}
	

	return 0;
}

static int
rr_parse_hinfo(struct mdns_rr *rr, u_int8_t *buf)
{
	ssize_t n;
	
	if ((n = charstr(rr->rdata.HINFO.cpu, buf, rr->rdlen)) == -1)
		return -1;
	if ((n = charstr(rr->rdata.HINFO.os, buf + n, rr->rdlen - n)) == -1)
		return -1;
	
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
	rr->rdata.A.s_addr = htonl(ul);
	
	return 0;
	
}

static int
rr_parse_txt(struct mdns_rr *rr, u_int8_t *buf)
{
	ssize_t n;
	
	if ((n = charstr(rr->rdata.TXT, buf, rr->rdlen)) == -1)
		return -1;

	return 0;
}

static int
rr_parse_srv(struct mdns_rr *rr, u_int8_t *buf, uint16_t len)
{
	GETSHORT(rr->rdata.SRV.priority, buf);
	len -= INT16SZ;
	GETSHORT(rr->rdata.SRV.weight, buf);
	len -= INT16SZ;
	GETSHORT(rr->rdata.SRV.port, buf);
	len -= INT16SZ;

	if (rr_parse_dname(buf, len, rr->rdata.SRV.dname) == -1)
		return -1;
	
	return 0;
}

static int
rr_parse_dname(u_int8_t *buf, u_int16_t len, char dname[MAXHOSTNAMELEN])
{
	if (pkt_parse_dname(buf, len, dname) == -1) {
		log_debug("Invalid record");
		return -1;
	}
	
	return 0;
}

/* TODO: make this static when done */
int
pkt_serialize(struct mdns_pkt *pkt, u_int8_t *buf, u_int16_t len)
{
	u_int16_t		 aux  = 0;
	u_int8_t		*pbuf = buf;
	struct mdns_question	*mq;
	struct mdns_rr		*rr;
	ssize_t			 n;
	
	if (len < MDNS_HDR_LEN) {
		log_debug("pkt_serialize: len < MDNS_HDR_LEN");
		return -1;
	}
	
	PUTSHORT(aux, pbuf); 	/* id must be 0 */
	if (pkt->qr)
		aux |= QR_MSK;
	if (pkt->tc)
		aux |= TC_MSK;
	PUTSHORT(aux, pbuf);
	PUTSHORT(pkt->qdcount, pbuf);
	PUTSHORT(pkt->ancount, pbuf);
	PUTSHORT(pkt->nscount, pbuf);
	PUTSHORT(pkt->arcount, pbuf);
	
	len -= pbuf - buf;
	    
	LIST_FOREACH(mq, &pkt->qlist, entry) {
		n = serialize_question(mq, pbuf, len);
		if (n == -1 || n > len)
			return -1;
		pbuf += n;
		len  -= n;
	}
	
	LIST_FOREACH(rr, &pkt->anlist, entry) {
		n = serialize_rr(rr, pbuf, len);
		if (n == -1 || n > len)
			return -1;
		pbuf += n;
		len  -= n;
	}

	LIST_FOREACH(rr, &pkt->nslist, entry) {
		n = serialize_rr(rr, pbuf, len);
		if (n == -1 || n > len)
			return -1;
		pbuf += n;
		len  -= n;
	}

	LIST_FOREACH(rr, &pkt->arlist, entry) {
		n = serialize_rr(rr, pbuf, len);
		if (n == -1 || n > len)
			return -1;
		pbuf += n;
		len  -= n;
	}

	return pbuf - buf;
}

static ssize_t
serialize_dname(char dname[MAXHOSTNAMELEN], u_int8_t *buf, u_int16_t len)
{
	char *end;
	char *dbuf = dname;
	u_int8_t tlen;
	u_int8_t *pbuf = buf;
	
	do {
		if ((end = strchr(dbuf, '.')) == NULL) {
			if ((end = strchr(dbuf, '\0')) == NULL)
				fatalx("serialize_dname: bad dname");
		}

		tlen = end - dbuf;
		*pbuf++ = tlen;
		if (tlen > len)
			return -1;
		memcpy(pbuf, dbuf, tlen);
		len -= tlen;
		pbuf += tlen;
		dbuf = end + 1;
	} while (*end != '\0');
	
	if (len == 0)
		return -1;
	
	/* put null octet */
/* 	*pbuf++ = '\0'; */
/* 	len--; */
	
	return pbuf - buf;
}


static ssize_t
serialize_hinfo(struct mdns_rr *rr, u_int8_t *buf, u_int16_t len)
{
	ssize_t		 n;
	u_int8_t	*pbuf  = buf;
	u_int8_t	 cpulen, oslen;
	u_int16_t	 rdlen = 0;
	char		 cpu[MAXHOSTNAMELEN];
	char		 os[MAXHOSTNAMELEN];
	
	bzero(cpu, sizeof(cpu));
	if ((n = serialize_dname(rr->rdata.HINFO.cpu, cpu, sizeof(cpu))) == -1)
		return -1;
	rdlen  += n;
	cpulen	= n;
	
	bzero(os, sizeof(os));
	if ((n = serialize_dname(rr->rdata.HINFO.os, os, sizeof(os))) == -1)
		return -1;
	rdlen += n;
	oslen  = n;
		
	if (rdlen > len)
		return -1;
	PUTSHORT(rdlen, pbuf);
	
	memcpy(pbuf, cpu, cpulen);
	pbuf += cpulen;
	
	memcpy(pbuf, os, oslen);
	pbuf += oslen;

	return pbuf - buf;
}
	
static ssize_t
serialize_rr(struct mdns_rr *rr, u_int8_t *buf, u_int16_t len)
{
	u_int8_t	*pbuf = buf;
	u_int16_t	 us   = 0;
	ssize_t		 n;
 
	n = serialize_dname(rr->dname, pbuf, len);
	if (n == -1 || n > len)
		return -1;
	pbuf += n;
	len  -= n;
	if (len == 0)
		return -1;
	*pbuf++ = '\0';		/* null terminate dname */
	len--;

	if (len < 10) /* must fit type, class, ttl and rdlength */
		return -1;
	PUTSHORT(rr->type, pbuf);
	us = rr->class;
	if (rr->cacheflush)
		us |= CACHEFLUSH_MSK;
	PUTSHORT(us, pbuf);
	PUTLONG(rr->ttl, pbuf);
	
	/* by now only hinfo has a special treatment */
	if (rr->type == T_HINFO) {
		if ((n = serialize_hinfo(rr, pbuf, len)) == -1)
			return -1;
		pbuf += n;
		len  -= n;
	} else {
		PUTSHORT(rr->rdlen, pbuf);
		if (rr->rdlen > len)
			return -1;
		memcpy(pbuf, &rr->rdata, rr->rdlen);
		pbuf += rr->rdlen;
		len -= rr->rdlen;
	}

	return pbuf - buf;
}

static ssize_t
serialize_question(struct mdns_question *mq, u_int8_t *buf, u_int16_t len)
{
	u_int8_t *pbuf = buf;
	ssize_t n;
	
	n = serialize_dname(mq->dname, pbuf, len);
	if (n == -1 || n > len)
		return -1;
	pbuf += n;
	len  -= n;
	if (len == 0)
		return -1;
	*pbuf++ = '\0';		/* null terminate dname */
	len--;

	if (len < 4) 	/* must fit type, class */
		return -1;
	PUTSHORT(mq->qtype, pbuf);
	PUTSHORT(mq->qclass, pbuf);
	
	return pbuf - buf;
}

