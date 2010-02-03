/*	$OpenBSD: packet.c,v 1.10 2008/03/24 16:11:05 deraadt Exp $ */

/*
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
static u_int8_t pkt_buf[READ_BUF_SIZE];

struct iface	*find_iface(unsigned int, struct in_addr);

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
	u_int8_t		*buf;
	ssize_t			 r;
	u_int16_t		 srcport;
	HEADER			*qh;

	if (event != EV_READ)
		return;

	/* setup buffer */
	buf = pkt_buf;

	bzero(&msg, sizeof(msg));

	iov.iov_base = buf;
	iov.iov_len = READ_BUF_SIZE;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	if ((r = recvmsg(fd, &msg, 0)) == -1) {
		if (errno != EINTR && errno != EAGAIN)
			log_debug("recv_packet: read error: %s",
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
	
	/* Check the packet is not from one of the local interfaces */
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		if (iface->addr.s_addr == src.sin_addr.s_addr)
			return;
	}

	/* find a matching interface */
	if ((iface = find_iface(dst->sdl_index, src.sin_addr)) == NULL) {
		log_debug("recv_packet: cannot find a matching interface");
		return;
	}
	
	log_debug("read %zd bytes from iface %s", r, iface->name);

	srcport = ntohs(src.sin_port);
	
	qh = (HEADER *) pkt_buf;
	log_debug("id: %u", ntohs(qh->id));
	log_debug("qr: %u", qh->qr);
	log_debug("opcode: %u", qh->opcode);
	log_debug("aa: %u", qh->aa);
	log_debug("tc: %u", qh->tc);
	log_debug("rd: %u", qh->rd);
	log_debug("ra: %u", qh->ra);
	log_debug("unused: %u", qh->unused);
	log_debug("ad: %u", qh->ad);
	log_debug("cd: %u", qh->cd);
	log_debug("rcode: %u", qh->rcode);
	log_debug("qdcount: %u", ntohs(qh->qdcount));
	log_debug("ancount: %u", ntohs(qh->ancount));
	log_debug("nscount: %u", ntohs(qh->nscount));
	log_debug("arcount: %u", ntohs(qh->arcount));
	log_debug("===============================================");
	
	/* take a look at recv_request and send_request */

}

struct iface *
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
