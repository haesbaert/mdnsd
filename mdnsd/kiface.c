/*
 * Copyright (c) 2010 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

/* The following is a very stripped down version of ripd's kroute.c */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdnsd.h"
#include "log.h"

#define RT_BUF_SIZE		16384
#define MAX_RTSOCK_BUF		128 * 1024

void	get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
void	kev_dispatch_msg(int, short, void *);

struct {
	int fd;
	struct event ev;
} kev_state;


#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(sa->sa_len));
		} else
			rti_info[i] = NULL;
	}
}

void
kev_init(void)
{
	int		opt = 0, rcvbuf, default_rcvbuf;
	int		rtfilter;
	socklen_t	optlen;

	if ((kev_state.fd = socket(AF_ROUTE, SOCK_RAW, 0)) == -1)
		fatal("kev_init: socket");

	log_debug("opened raw socket with kernel on fd %d", kev_state.fd);

	/* not interested in my own messages */
	if (setsockopt(kev_state.fd, SOL_SOCKET, SO_USELOOPBACK,
	    &opt, sizeof(opt)) == -1)
		log_warn("kev: setsockopt");	/* not fatal ? why ? */

	/* filter only for messages that can be handled */
	rtfilter = ROUTE_FILTER(RTM_IFINFO) | ROUTE_FILTER(RTM_NEWADDR) | ROUTE_FILTER(RTM_DELADDR);
	if (setsockopt(kev_state.fd, AF_ROUTE, ROUTE_MSGFILTER, &rtfilter, sizeof(rtfilter)) == -1)
		log_warn("kev: route_msgfilter");

	/* grow receive buffer, don't wanna miss messages */
	optlen = sizeof(default_rcvbuf);
	if (getsockopt(kev_state.fd, SOL_SOCKET, SO_RCVBUF,
	    &default_rcvbuf, &optlen) == -1)
		log_warn("kev_init getsockopt SOL_SOCKET SO_RCVBUF");
	else
		for (rcvbuf = MAX_RTSOCK_BUF;
		     rcvbuf > default_rcvbuf &&
			 setsockopt(kev_state.fd, SOL_SOCKET, SO_RCVBUF,
			     &rcvbuf, sizeof(rcvbuf)) == -1 && errno == ENOBUFS;
		     rcvbuf /= 2)
			;	/* nothing */

	event_set(&kev_state.ev, kev_state.fd, EV_READ | EV_PERSIST,
	    kev_dispatch_msg, NULL);
	event_add(&kev_state.ev, NULL);
}

/* ARGSNOTUSED */
void
kev_dispatch_msg(int fd, short event, void *bula)
{
	char			 buf[RT_BUF_SIZE];
	char			*next, *lim;
	ssize_t			 n;
	struct rt_msghdr	*rtm;
	struct if_msghdr	 ifm;
	struct iface		*iface;
	struct sockaddr		*sa, *rti_info[RTAX_MAX];

	if ((n = read(kev_state.fd, &buf, sizeof(buf))) == -1)
		fatal("kev_dispatch_rtmsg: read error");

	if (n == 0)
		fatalx("kernel event socket closed");

	lim = buf + n;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		memcpy(&ifm, next, sizeof(ifm));
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;

		iface = if_find_index(ifm.ifm_index);
		if (iface == NULL) /* this interface isn't configured */
			continue;

		sa = (struct sockaddr *)(buf + rtm->rtm_hdrlen);
		get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

		switch (rtm->rtm_type) {
		case RTM_IFINFO:
			log_debug("RTM_IFINFO");
			if (LINK_STATE_IS_UP(ifm.ifm_data.ifi_link_state))
				if_fsm(iface, IF_EVT_UP);
			else
				if_fsm(iface, IF_EVT_DOWN);
			break;
		case RTM_IFANNOUNCE:
			log_debug("RTM_IFANNOUNCE");
			break;
		case RTM_NEWADDR:
			if_newaddr(rti_info[RTAX_IFA], rti_info[RTAX_DST], rti_info[RTAX_NETMASK], iface);
			log_debug("RTM_NEWADDR");
			break;
		case RTM_DELADDR:
			if_deladdr(rti_info[RTAX_IFA], iface);
			log_debug("RTM_DELADDR");
			break;
		default:
			/* ignore for now */
			break;
		}
	}
}

void
kev_cleanup(void)
{
	/* TODO */
}
