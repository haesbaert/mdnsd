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
#include <event.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdnsd.h"
#include "log.h"

struct {
	int fd;
	struct event ev;
} kev_state;

void	kev_dispatch_msg(int, short, void *);


void
kev_init(void)
{
	int		opt = 0, rcvbuf, default_rcvbuf;
	socklen_t	optlen;

	if ((kev_state.fd = socket(AF_ROUTE, SOCK_RAW, 0)) == -1)
		fatal("kev_init: socket");

	log_debug("opened raw socket with kernel on fd %d", kev_state.fd);
	
	/* not interested in my own messages */
	if (setsockopt(kev_state.fd, SOL_SOCKET, SO_USELOOPBACK,
	    &opt, sizeof(opt)) == -1)
		log_warn("kev: setsockopt");	/* not fatal ? why ? */

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

	if ((n = read(kev_state.fd, &buf, sizeof(buf))) == -1)
		fatal("kev_dispatch_rtmsg: read error");

	if (n == 0)
		fatalx("event socket closed");

	lim = buf + n;
	for (next = buf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;
		if (rtm->rtm_version != RTM_VERSION)
			continue;

		switch (rtm->rtm_type) {
		case RTM_IFINFO:
			log_warnx("RTM_IFINFO");
/* 			memcpy(&ifm, next, sizeof(ifm)); */
/* 			if_change(ifm.ifm_index, ifm.ifm_flags, */
/* 			    &ifm.ifm_data); */
			break;
		case RTM_IFANNOUNCE:
			log_warnx("RTM_IFANNOUNCE");
/* 			if_announce(next); */
			break;
		default:
			/* ignore for now */
			break;
		}
	}
}
