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

static void	pkt_init(struct mdns_pkt *);
static int	pkt_parse(u_int8_t *, uint16_t, struct mdns_pkt *);
static int	pkt_parse_header(u_int8_t **, u_int16_t *, struct mdns_pkt *);
static ssize_t	pkt_parse_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN]);
static int	pkt_parse_question(u_int8_t **, u_int16_t *, struct mdns_pkt *);
static int	pkt_parse_rr(u_int8_t **, u_int16_t *, struct mdns_pkt *,
    struct mdns_rr *);
static int	pkt_process(struct mdns_pkt *);
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
	
/* 	log_debug("buf is at %p", buf); */
/* 	log_debug("###### PACKET %d #####", ++pktnum); */
	
	if (pkt_parse(buf, len, &pkt) == -1)
		return;
	
	pkt_process(&pkt);
/* 	rrc_dump(); */

	/* process all shit */
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

static void
pkt_init(struct mdns_pkt *pkt)
{
	bzero(pkt, sizeof(*pkt));
	LIST_INIT(&pkt->qlist);
	LIST_INIT(&pkt->anlist);
	LIST_INIT(&pkt->nslist);
	LIST_INIT(&pkt->arlist);
}

/* TODO: insert all sections at end, don't use LIST_INSERT_HEAD */
static int
pkt_parse(u_int8_t *buf, uint16_t len, struct mdns_pkt *pkt)
{
	u_int16_t		 i;
	struct mdns_question	*mq;
	struct mdns_rr		*rr;
	
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
/* 		log_debug("==BEGIN AN RR=="); */
		if (pkt_parse_rr(&buf, &len, pkt, rr) == -1) {
			log_debug("Can't parse RR");
			free(rr);
			return -1;
		}
		LIST_INSERT_HEAD(&pkt->anlist, rr, entry);

/* 		log_debug("==END AN RR=="); */

	}
	
	for (i = 0; i < pkt->nscount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
/* 		log_debug("==BEGIN NS RR=="); */
		if (pkt_parse_rr(&buf, &len, pkt, rr) == -1) {
			log_debug("Can't parse RR");
			free(rr);
			return -1;
		}
		LIST_INSERT_HEAD(&pkt->nslist, rr, entry);
		
/* 		log_debug("==END NS RR=="); */

	}

	for (i = 0; i < pkt->arcount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
/* 		log_debug("==BEGIN AR RR=="); */
		if (pkt_parse_rr(&buf, &len, pkt, rr) == -1) {
			log_debug("Can't parse RR");
/* 			rr_free(rr); */
			free(rr);
			return -1;
		}
		
		LIST_INSERT_HEAD(&pkt->arlist, rr, entry);

/* 		log_debug("==END AR RR=="); */

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
/* 	log_debug("rr->ttl = %u 0x%x", rr->ttl, rr->ttl); */


	GETSHORT(rr->rdlen, *pbuf);
	*len -= INT16SZ;
/* 	log_debug("rr->rdlen = %u", rr->rdlen); */
	
	if (*len < rr->rdlen) {
		log_debug("Invalid rr data length, *len = %u, rdlen = %u",
		    *len,rr->rdlen);
		return -1;
	}

	switch (rr->type) {
	case T_A:
/* 		log_debug("A record"); */
		if (rr_parse_a(rr, *pbuf) == -1)
			return -1;
		break;
	case T_HINFO:
/* 		log_debug("HINFO record"); */
		if (rr_parse_hinfo(rr, *pbuf) == -1)
			return -1;
		break;
	case T_CNAME:
/* 		log_debug("CNAME record"); */
		if (rr_parse_dname(*pbuf, *len,
		    rr->rdata.CNAME) == -1)
			return -1;
		break;
	case T_PTR:
/* 		log_debug("PTR record"); */
		if (rr_parse_dname(*pbuf, *len,
		    rr->rdata.PTR) == -1)
			return -1;
		break;
	case T_TXT:
/* 		log_debug("TXT record"); */
		if (rr_parse_txt(rr, *pbuf) == -1)
			return -1;
		break;
	case T_NS:
/* 		log_debug("NS record"); */
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
/* 		log_debug("got a AAAA record"); */
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


#define ANSWERS(q, rr)						\
	(((q->qtype == T_ANY) || (q->qtype == rr->type))  &&	\
	    q->qclass == rr->class                       &&	\
	    strcmp(q->dname, rr->dname) == 0)

static int
pkt_process(struct mdns_pkt *pkt)
{
	struct mdns_rr *rr;
	struct mdns_question *q;
	
	/* mark all probe questions, so we don't try to answer them below */
	LIST_FOREACH(rr, &pkt->nslist, entry) {
		LIST_FOREACH(q, &pkt->qlist, entry) {
			if (ANSWERS(q, rr)) {
/* 				log_debug("probe for %s", q->dname); */
				q->probe = 1;
			}
		}
		LIST_REMOVE(rr, entry);
		free(rr);
	}
	
	/* process all questions */
	while ((q = LIST_FIRST(&pkt->qlist)) != NULL) {
/* 		if (!q->probe) */
/* 			log_debug("should try answer: %s (type %s)", q->dname, */
/* 			    rr_type_name(q->qtype)); */
		LIST_REMOVE(q, entry);
		free(rr);
		/* TODO: try to answer questions :-D */
	}
	
	/* process all answers */
	while ((rr = LIST_FIRST(&pkt->anlist)) != NULL) {
		LIST_REMOVE(rr, entry);
		rrc_process(rr);
	}
	
	/* process additional section */
	/* TODO */
	
	return 0;
}

static int
rr_parse_hinfo(struct mdns_rr *rr, u_int8_t *buf)
{
	ssize_t n;
	
	if ((n = charstr(rr->rdata.HINFO.cpu, buf, rr->rdlen)) == -1)
		return -1;
/* 	log_debug("   cpu: %s", rr->rdata.HINFO.cpu); */

	if ((n = charstr(rr->rdata.HINFO.os, buf + n, rr->rdlen - n)) == -1)
		return -1;
/* 	log_debug("   os: %s",  rr->rdata.HINFO.os); */
	
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
	
/* 	log_debug("A record: %s", inet_ntoa(rr->rdata.A)); */
	return 0;
	
}

static int
rr_parse_txt(struct mdns_rr *rr, u_int8_t *buf)
{
	ssize_t n;
	
	if ((n = charstr(rr->rdata.TXT, buf, rr->rdlen)) == -1)
		return -1;
/* 	log_debug("TXT: %s", rr->rdata.TXT); */

	return 0;
}

static int
rr_parse_srv(struct mdns_rr *rr, u_int8_t *buf, uint16_t len)
{
	GETSHORT(rr->rdata.SRV.priority, buf);
	len -= INT16SZ;
/* 	log_debug("SRV priority: %u", rr->rdata.SRV.priority); */
	
	GETSHORT(rr->rdata.SRV.weight, buf);
	len -= INT16SZ;
/* 	log_debug("SRV weight: %u", rr->rdata.SRV.weight); */

	GETSHORT(rr->rdata.SRV.port, buf);
	len -= INT16SZ;
/* 	log_debug("SRV port: %u", rr->rdata.SRV.port); */

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

