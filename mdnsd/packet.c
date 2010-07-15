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

/*
 * This file needs a refactoring, pkt_parse and serialize functions rely on
 * pktcomp being always accurate, most of functions here are not re-entrant and
 * depend on state that they shouldn't, like serialize_dname which must have the
 * current packet buffer as input. Also, name compression is uses a different
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

static struct iface	*find_iface(unsigned int, struct in_addr);

static int      pkt_parse(u_int8_t *, u_int16_t, struct in_addr, struct iface *);
static int	pkt_parse_header(u_int8_t **, u_int16_t *, struct pkt *);
static ssize_t	pkt_parse_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN]);
static int	pkt_parse_question(u_int8_t **, u_int16_t *, struct pkt *);
static int	pkt_parse_rr(u_int8_t **, u_int16_t *, struct rr *);
static int	pkt_tryanswerq(struct pkt *);
static ssize_t	serialize_rr(struct rr *, u_int8_t *, u_int16_t);
static ssize_t	serialize_question(struct question *, u_int8_t *,
    u_int16_t);
static ssize_t	serialize_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN]);
static ssize_t	serialize_rdata(struct rr *, u_int8_t *, u_int16_t);
static int	rr_parse_dname(u_int8_t *, u_int16_t, char [MAXHOSTNAMELEN]);
static ssize_t  charstr(char [MAX_CHARSTR], u_int8_t *, u_int16_t);
static void	header_htons(HEADER *);
static void	header_ntohs(HEADER *);
static int	pktcomp_add(char [MAXHOSTNAMELEN], u_int16_t);
static struct namecomp *pktcomp_lookup(char [MAXHOSTNAMELEN]);

extern struct mdnsd_conf *conf;

/* Used in name compression */
struct namecomp {
	LIST_ENTRY(namecomp) 	entry;
	char			dname[MAXHOSTNAMELEN];
	u_int16_t		offset;
};

static struct {
	LIST_HEAD(, namecomp) 	namecomp_list;
	u_int8_t		*start;
	u_int16_t	 	len;
} pktcomp;

/* Util */
static ssize_t
charstr(char dest[MAX_CHARSTR], u_int8_t *buf, u_int16_t len)
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
	static u_int8_t		 buf[MAX_PACKET];
	ssize_t			 r;
	u_int16_t		 len, srcport;

	if (event != EV_READ)
		return;

	bzero(&msg, sizeof(msg));
	bzero(buf, sizeof(buf));

	iov.iov_base = buf;
	iov.iov_len = MAX_PACKET;
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

	if (pkt_parse(buf, len, src.sin_addr, iface) == -1) {
		log_warnx("pkt_parse returned -1");
		return;
	}
}

int
pkt_send_if(struct pkt *pkt, struct iface *iface)
{
	struct sockaddr_in	 dst;
	static u_int8_t		 buf[MAX_PACKET];
	struct question		*mq;
	struct rr		*rr;
	HEADER			*h;
	u_int8_t		*pbuf;
	ssize_t			 n, left;

	inet_aton(ALL_MDNS_DEVICES, &dst.sin_addr);
	dst.sin_port   = htons(MDNS_PORT);
	dst.sin_family = AF_INET;
	dst.sin_len    = sizeof(struct sockaddr_in);
	if (iface->mtu > MAX_PACKET) {
		log_warnx("pkt_send_if: insane mtu");
		return (-1);
	}
	bzero(buf, sizeof(buf));
	left = iface->mtu * 0.9;
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
	/* Copy header. */
	h->qr  = pkt->h.qr;
	left  -= HDR_LEN;
	pbuf  += HDR_LEN;
	/* Append all questions, they must fit a single packet. */
	LIST_FOREACH(mq, &pkt->qlist, entry) {
		n = serialize_question(mq, pbuf, left);
		if (n == -1 || n > left) {
			log_warnx("pkt_send_if: "
			    "can't serialize question section");
			return (-1);
		}
		h->qdcount++;
		pbuf += n;
		left -= n;
	}
	/* Append all answers, they must fit a single packet. */
	LIST_FOREACH(rr, &pkt->anlist, pentry) {
		n = serialize_rr(rr, pbuf, left);
		if (n == -1 || n > left)
			return (-1);
		h->ancount++;
		pbuf += n;
		left -= n;
	}
	/* Append all authorities, they must fit a single packet. */
	LIST_FOREACH(rr, &pkt->nslist, pentry) {
		n = serialize_rr(rr, pbuf, left);
		if (n == -1 || n > left)
			return (-1);
		h->nscount++;
		pbuf += n;
		left -= n;
	}
	/*
	 * This is where the shit happens, if we are querying and our additional
	 * section won't fit in a single packet, we fragment. The following
	 * could be a recursive call, passing a flag telling us if we're in a
	 * "fragmented" state or not, but if so, we would need to make buf
	 * non-static, allocating MAX_PACKET for each fragmenting packet. This
	 * might seem like premature optimization but it's also easier to
	 * maintain.
	 */
	LIST_FOREACH(rr, &pkt->arlist, pentry) {
		int in_retry;

		in_retry = 0;
	retry:
		n = serialize_rr(rr, pbuf, left);
		/* Unexpected n */
		if (n > left)
			return (-1);
		/*
		 * Fragmentation only for queries, on answer is an
		 * error, actually only for queries with known answer
		 * supression.
		 */
		if (n == -1 && h->qr)
			return (-1);
		/*
		 * Won't fit, send what we have, restart the ball.
		 */
		if (n == -1) {
			/* Set truncation bit and close packet */
			h->tc = 1;
			header_htons(h);
			if (send_packet(iface, buf, pbuf - buf, &dst) == -1)
				return (-1);
			/* Reset states */
			bzero(buf, sizeof(buf));
			left = iface->mtu;
			pbuf = buf;
			h    = (HEADER *) buf;
			n    = 0;
			pktcomp_reset(0, buf, left);
			/* Copy header */
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
		h->arcount++;
		pbuf += n;
		left -= n;
	}
	/* Close packet and send. */
	header_htons(h);
	if (send_packet(iface, buf, pbuf - buf, &dst) == -1)
		return (-1);
	return (0);
}

int
pkt_send_allif(struct pkt *pkt)
{
	struct iface	*iface = NULL;
	int		 succ  = 0;
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		if (pkt_send_if(pkt, iface) == -1)
			log_warnx("Can't send packet though %s", iface->name);
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

/* packet building */
int
pkt_add_question(struct pkt *pkt, struct question *mq)
{
	/* can't have questions and answers in the same packet */
	if (pkt->h.ancount || pkt->h.nscount || pkt->h.arcount)
		return (-1);
	LIST_INSERT_HEAD(&pkt->qlist, mq, entry);
	pkt->h.qdcount++;
	pkt->h.qr = 0;

	return (0);
}

int
pkt_add_anrr(struct pkt *pkt, struct rr *rr)
{
	if (pkt->h.qdcount)
		return (-1);
	LIST_INSERT_HEAD(&pkt->anlist, rr, pentry);
	pkt->h.ancount++;
	pkt->h.qr = 1;

	return (0);
}

int
pkt_add_nsrr(struct pkt *pkt, struct rr *rr)
{
	LIST_INSERT_HEAD(&pkt->nslist, rr, pentry);
	pkt->h.nscount++;

	return (0);
}

int
pkt_add_arrr(struct pkt *pkt, struct rr *rr)
{
	LIST_INSERT_HEAD(&pkt->arlist, rr, pentry);
	pkt->h.arcount++;

	return (0);
}

int
question_set(struct question *mq, char dname[MAXHOSTNAMELEN],
    u_int16_t qtype, u_int16_t qclass, int uniresp, int probe)
{
	bzero(mq, sizeof(*mq));

	if (qclass != C_IN)
		return (-1);
	mq->qclass  = qclass;
	mq->qtype   = qtype;
	mq->uniresp = uniresp;
	mq->probe   = probe;
	strlcpy(mq->dname, dname, sizeof(mq->dname));

	return (0);
}

int
rr_set(struct rr *rr, char dname[MAXHOSTNAMELEN],
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
		return (-1);
	}
	memcpy(&rr->rdata, rdata, rdlen);
	strlcpy(rr->dname, dname, sizeof(rr->dname));

	return (0);
}

int
rr_rdata_cmp(struct rr *rra, struct rr *rrb)
{
	size_t na, nb;

	if (rra->type != rrb->type) {
		log_warnx("Can't compare rdata for different types");
		return (-1);
	}
	switch (rra->type) {
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
		return strcmp(rra->rdata.SRV.dname, rrb->rdata.SRV.dname);
	case T_HINFO:
		na = strlen(rra->rdata.HINFO.cpu);
		nb = strlen(rrb->rdata.HINFO.cpu);
		if (strcmp(rra->rdata.HINFO.cpu, rrb->rdata.HINFO.cpu) != 0)
			return (strcmp(rra->rdata.HINFO.cpu,
			    rrb->rdata.HINFO.cpu));
		if (strcmp(rra->rdata.HINFO.os, rrb->rdata.HINFO.os) != 0)
			return (strcmp(rra->rdata.HINFO.os,
			    rrb->rdata.HINFO.os));
	default:
		log_warnx("Unknown rr->type (%d), can't compare", rra->type);
		fatalx("Fatal, won't accept bogus comparisons");
		break;
	}
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

/* TODO: When we have an error parsing, we leak memory. */
static int
pkt_parse(u_int8_t *buf, u_int16_t len, struct in_addr saddr, struct iface *ifa)
{
	u_int16_t	 i;
	struct question	*mq;
	struct rr	*rr;
	struct pkt	 pkt;

	pkt_init(&pkt);
	pktcomp_reset(0, buf, len);
	if (pkt_parse_header(&buf, &len, &pkt) == -1)
		return (-1);
	
	/*
	 * Multicastdns draft 4. Source Address check.
	 * If a response packet was sent to an unicast address, check if the
	 * source ip address in the packed matches one of our subnets, if not,
	 * drop it.
	 */
	/* TODO */
	
	/* Parse question section */
	if (!pkt.h.qr)
		for (i = 0; i < pkt.h.qdcount; i++)
			if (pkt_parse_question(&buf, &len, &pkt) == -1)
				return (-1);
	/* Parse RR sections */
	if (pkt.h.qr)
		for (i = 0; i < pkt.h.ancount; i++) {
			if ((rr = calloc(1, sizeof(*rr))) == NULL)
				fatal("calloc");
			if (pkt_parse_rr(&buf, &len, rr) == -1) {
				log_warnx("Can't parse AN RR");
				free(rr);
				return (-1);
			}
			LIST_INSERT_HEAD(&pkt.anlist, rr, pentry);
		}
	for (i = 0; i < pkt.h.nscount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		if (pkt_parse_rr(&buf, &len, rr) == -1) {
			log_warnx("Can't parse NS RR");
			free(rr);
			return (-1);
		}
		LIST_INSERT_HEAD(&pkt.nslist, rr, pentry);
	}
	for (i = 0; i < pkt.h.arcount; i++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		if (pkt_parse_rr(&buf, &len, rr) == -1) {
			log_warnx("Can't parse AR RR");
			free(rr);
			return (-1);
		}

		LIST_INSERT_HEAD(&pkt.arlist, rr, pentry);
	}
	
	
	if (len != 0) {
		log_warnx("Couldn't read all packet, %u bytes left", len);
		/* XXX: memory leak */
		return (-1);
	}
	
	/*
	 * Packet parsing done, start processing.
	 */
	
	/* Mark all probe questions, so we don't try to answer them below */
	while((rr = LIST_FIRST(&pkt.nslist)) != NULL) {
		LIST_FOREACH(mq, &pkt.qlist, entry) {
			if (ANSWERS(mq, rr))
				mq->probe = 1;
		}
		LIST_REMOVE(rr, pentry);
		free(rr);
	}

	/* Process all questions */
	if (pkt_tryanswerq(&pkt) == -1)
		log_warnx("pkt_tryanswerq: error");

	/* process all answers */
	while ((rr = LIST_FIRST(&pkt.anlist)) != NULL) {
		LIST_REMOVE(rr, pentry);
		cache_process(rr);
	}

	/* process additional section */
	/* TODO */

	return (0);
}

static int
pkt_parse_header(u_int8_t **pbuf, u_int16_t *len, struct pkt *pkt)
{
	u_int8_t *buf = *pbuf;

	/* MDNS header sanity check */
	if (*len < HDR_LEN) {
		log_debug("recv_packet: bad packet size %u", len);
		return (-1);
	}
	pkt->h = *((HEADER *) buf);
	header_ntohs(&pkt->h);
	*len  -= HDR_LEN;
	*pbuf += HDR_LEN;

	return (0);
}

static int
pkt_parse_question(u_int8_t **pbuf, u_int16_t *len, struct pkt *pkt)
{
	u_int16_t us;
	struct question *mq;
	ssize_t n;

	/* MDNS question sanity check */
	if (*len < MINQRY_LEN) {
		log_debug("pkt_parse_question: bad query packet size %u", *len);
		return (-1);
	}

	if ((mq = calloc(1, sizeof(*mq))) == NULL)
		fatal("calloc");

	n = pkt_parse_dname(*pbuf, *len, mq->dname);
	if (n == -1) {
		free(mq);
		return (-1);
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
		return (-1);
	}

	LIST_INSERT_HEAD(&pkt->qlist, mq, entry);

	return (0);
}

static ssize_t
pkt_parse_dname(u_int8_t *buf, u_int16_t len, char dname[MAXHOSTNAMELEN])
{
	size_t i;
	u_int8_t lablen;
	int jumped = 0;
	u_int16_t oldlen = len;
	u_char label[MAXLABEL + 1];

	/* be extra safe */
	bzero(dname, MAXHOSTNAMELEN);

	for (i = 0; i < MAX_LABELS; i++) {
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
			return (-1);
		}
		memcpy(label, buf, lablen);
		label[lablen] = '\0';
		/* strlcat needs a proper C string in src */
		if (strlcat(dname, label, MAXHOSTNAMELEN) >= MAXHOSTNAMELEN)  {
			log_debug("domain-name truncated");
			return (-1);
		}

		/* should we leave the dot on the last tag ? */
		if (strlcat(dname, ".", MAXHOSTNAMELEN) >= MAXHOSTNAMELEN) {
			log_debug("domain-name truncated");
			return (-1);
		}

		buf += lablen;
		if (!jumped)
			len -= lablen;
	}

	if (i == MAX_LABELS) {
		log_debug("max labels reached");
		return (-1);
	}

	/* remove the trailling dot */
	dname[strlen(dname) - 1] = '\0';

	return (oldlen - len);
}


/* XXX: This function lacks some comments */
static int
pkt_parse_rr(u_int8_t **pbuf, u_int16_t *len, struct rr *rr)
{
	u_int16_t us, rdlen, tmplen;
	u_int32_t ul;
	ssize_t n;
	char *buf;

	n = pkt_parse_dname(*pbuf, *len, rr->dname);
	if (n == -1)
		return (-1);
	*pbuf += n;
	*len  -= n;
	/* Make sure rr packet len is ok */
	if (*len < 8) {
		log_debug("Unexpected packet len");
		return (-1);
	}
	GETSHORT(rr->type, *pbuf);
	*len -= INT16SZ;
	GETSHORT(us, *pbuf);
	*len -= INT16SZ;
	rr->cacheflush = !!(us & CACHEFLUSH_MSK);
	rr->class      = us & CLASS_MSK;
	if (rr->class != C_ANY && rr->class != C_IN) {
		log_debug("pkt_parse_rr: %s (%s) Invalid packet class %u",
		    rr_type_name(rr->type), rr->dname, rr->class);
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
	switch (rr->type) {
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
		if (rr_parse_dname(buf, tmplen, rr->rdata.SRV.dname) == -1)
			return (-1);
		break;
	case T_AAAA:
		break;
	default:
		log_debug("Unknown record type %u 0x%x", rr->type, rr->type);
		return (-1);
		break;
	}

	*len  -= rdlen;
	*pbuf += rdlen;

	return (0);
}

static int
pkt_tryanswerq(struct pkt *pkt)
{
	struct question	*q;
	struct rr	*rr;
	struct pkt	 sendpkt;

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
					log_debug("can't send packet to"
					    "all interfaces");
			}

		}
		LIST_REMOVE(q, entry);
		free(q);
	}

	return (0);
}

static int
rr_parse_dname(u_int8_t *buf, u_int16_t len, char dname[MAXHOSTNAMELEN])
{
	if (pkt_parse_dname(buf, len, dname) == -1) {
		log_debug("Invalid record");
		return (-1);
	}

	return (0);
}

static ssize_t
serialize_dname(u_int8_t *buf, u_int16_t len, char dname[MAXHOSTNAMELEN])
{
	char *end;
	char *dbuf = dname;
	u_int8_t tlen;
	u_int8_t *pbuf = buf;
	struct namecomp *nc;
	
	/* Try to compress this name */
	if ((nc = pktcomp_lookup(dname)) != NULL) {
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
	if (pktcomp_add(dname, (u_int16_t) (buf - pktcomp.start)) == -1)
		log_warnx("pktcomp_add error: %s", dname);
	
	return (pbuf - buf);
}

static ssize_t
serialize_rdata(struct rr *rr, u_int8_t *buf, u_int16_t len)
{
	u_int8_t	*pbuf = buf;
	ssize_t		 n;
	u_int16_t	 rdlen = 0, *prdlen;
	u_int8_t	 cpulen, oslen;

	switch (rr->type) {
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
		prdlen = (u_int16_t *) pbuf;
		/* jump over rdlen */
		pbuf += INT16SZ;
		len  -= INT16SZ;
		if ((n = serialize_dname(pbuf, len,
		    rr->rdata.PTR)) == -1)
			return (-1);
		rdlen = n;
		pbuf += rdlen;
		len  -= rdlen;
		*prdlen = htons(rdlen);
		break;
	case T_A:
		rdlen = INT32SZ;
		if (len < (rdlen + 2)) /* +2 is rdlen itself */
			return (-1);
		PUTSHORT(rdlen, pbuf);
		len -= 2;
		memcpy(pbuf, &rr->rdata, rdlen);
		pbuf += rdlen;
		len  -= rdlen;
		break;
	default:
		log_warnx("serialize_rdata: Don't know how to serialize %s (%d)",
		    rr_type_name(rr->type), rr->type);
		return (-1);
		break;		/* NOTREACHED */
	}
	return (pbuf - buf);
}

static ssize_t
serialize_rr(struct rr *rr, u_int8_t *buf, u_int16_t len)
{
	u_int8_t	*pbuf = buf;
	u_int16_t	 us   = 0;
	ssize_t		 n;

	n = serialize_dname(pbuf, len, rr->dname);
	if (n == -1 || n > len)
		return (-1);
	pbuf += n;
	len  -= n;
	if (len == 0)
		return (-1);

	if (len < 8) /* must fit type, class, ttl */
		return (-1);
	PUTSHORT(rr->type, pbuf);
	us = rr->class;
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

static ssize_t
serialize_question(struct question *mq, u_int8_t *buf, u_int16_t len)
{
	u_int8_t *pbuf = buf;
	ssize_t n;

	n = serialize_dname(pbuf, len, mq->dname);
	if (n == -1 || n > len)
		return (-1);
	pbuf += n;
	len  -= n;
	if (len == 0)
		return (-1);

	if (len < 4)	/* must fit type, class */
		return (-1);
	PUTSHORT(mq->qtype, pbuf);
	PUTSHORT(mq->qclass, pbuf);

	return (pbuf - buf);
}

static void
header_htons(HEADER *h)
{
	h->qdcount = htons(h->qdcount);
	h->ancount = htons(h->ancount);
	h->nscount = htons(h->nscount);
	h->arcount = htons(h->arcount);
}

static void
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
	
	if (first)
		LIST_INIT(&pktcomp.namecomp_list);
	while ((nc = LIST_FIRST(&pktcomp.namecomp_list)) != NULL) {
		LIST_REMOVE(nc, entry);
		free(nc);
	}
	pktcomp.start = start;
	pktcomp.len = len;
}

static int
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

static struct namecomp *
pktcomp_lookup(char dname[MAXHOSTNAMELEN])
{
	struct namecomp *nc;
	
	LIST_FOREACH(nc, &pktcomp.namecomp_list, entry) {
		if (strcmp(nc->dname, dname) == 0)
			return (nc);
	}
	
	return (NULL);
}
