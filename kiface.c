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

struct kif_node {
	RB_ENTRY(kif_node)	 entry;
	struct kif		 k;
};

void	get_rtaddrs(int, struct sockaddr *, struct sockaddr **);
int	kif_compare(struct kif_node *, struct kif_node *);
int	kif_insert(struct kif_node *);
int	fetchifs(int);
void	kev_dispatch_msg(int, short, void *);
void	kev_ifinfo(struct if_data *, struct iface *);

struct {
	int fd;
	struct event ev;
} kev_state;


RB_HEAD(kif_tree, kif_node) kit;
RB_PROTOTYPE(kif_tree, kif_node, entry, kif_compare)
RB_GENERATE(kif_tree, kif_node, entry, kif_compare)

int
kif_init(void)
{
	RB_INIT(&kit);

	if (fetchifs(0) == -1)
		return (-1);

	return (0);
}

struct kif *
kif_findname(char *ifname)
{
	struct kif_node	*kif;

	RB_FOREACH(kif, kif_tree, &kit)
	    if (!strcmp(ifname, kif->k.ifname))
		    return (&kif->k);

	return (NULL);
}

int
kif_insert(struct kif_node *kif)
{
	if (RB_INSERT(kif_tree, &kit, kif) != NULL) {
		log_warnx("RB_INSERT(kif_tree, &kit, kif)");
		free(kif);
		return (-1);
	}

	return (0);
}

int
kif_compare(struct kif_node *a, struct kif_node *b)
{
	return (b->k.ifindex - a->k.ifindex);
}

#define	ROUNDUP(a, size)						\
	(((a) & ((size) - 1)) ? (1 + ((a) | ((size) - 1))) : (a))

void
kif_cleanup(void)
{
	/* TODO */
}

void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
	int	i;

	for (i = 0; i < RTAX_MAX; i++) {
		if (addrs & (1 << i)) {
			rti_info[i] = sa;
			sa = (struct sockaddr *)((char *)(sa) +
			    ROUNDUP(sa->sa_len, sizeof(long)));
		} else
			rti_info[i] = NULL;
	}
}

int
fetchifs(int ifindex)
{
	size_t			 len;
	int			 mib[6];
	char			*buf, *next, *lim;
	struct if_msghdr	 ifm;
	struct kif_node		*kif;
	struct sockaddr		*sa, *rti_info[RTAX_MAX];
	struct sockaddr_dl	*sdl;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_IFLIST;
	mib[5] = ifindex;

	if (sysctl(mib, 6, NULL, &len, NULL, 0) == -1) {
		log_warn("sysctl");
		return (-1);
	}
	if ((buf = malloc(len)) == NULL) {
		log_warn("fetchif");
		return (-1);
	}
	if (sysctl(mib, 6, buf, &len, NULL, 0) == -1) {
		log_warn("sysctl");
		free(buf);
		return (-1);
	}

	lim = buf + len;
	for (next = buf; next < lim; next += ifm.ifm_msglen) {
		memcpy(&ifm, next, sizeof(ifm));
		if (ifm.ifm_version != RTM_VERSION)
			continue;
		if (ifm.ifm_type != RTM_IFINFO)
			continue;

		sa = (struct sockaddr *)(next + sizeof(ifm));
		get_rtaddrs(ifm.ifm_addrs, sa, rti_info);

 		if ((kif = calloc(1, sizeof(struct kif_node))) == NULL) {
			log_warn("fetchifs");
			free(buf);
			return (-1);
		}

		kif->k.ifindex = ifm.ifm_index;
		kif->k.flags = ifm.ifm_flags;
		kif->k.link_state = ifm.ifm_data.ifi_link_state;
		kif->k.media_type = ifm.ifm_data.ifi_type;
		kif->k.baudrate = ifm.ifm_data.ifi_baudrate;
		kif->k.mtu = ifm.ifm_data.ifi_mtu;
/* 		kif->k.nh_reachable = (kif->k.flags & IFF_UP) && */
/* 		    (LINK_STATE_IS_UP(ifm.ifm_data.ifi_link_state) || */
/* 			(ifm.ifm_data.ifi_link_state == LINK_STATE_UNKNOWN && */
/* 			ifm.ifm_data.ifi_type != IFT_CARP)); */
		if ((sa = rti_info[RTAX_IFP]) != NULL)
			if (sa->sa_family == AF_LINK) {
				sdl = (struct sockaddr_dl *)sa;
				if (sdl->sdl_nlen >= sizeof(kif->k.ifname))
					memcpy(kif->k.ifname, sdl->sdl_data,
					    sizeof(kif->k.ifname) - 1);
				else if (sdl->sdl_nlen > 0)
					memcpy(kif->k.ifname, sdl->sdl_data,
					    sdl->sdl_nlen);
				/* string already terminated via calloc() */
			}
		kif_insert(kif);
	}
	free(buf);
	return (0);
}

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
	struct if_msghdr	 ifm;
	struct iface *iface;

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
		
		switch (rtm->rtm_type) {
		case RTM_IFINFO:
			log_debug("RTM_IFINFO");
			kev_ifinfo(&ifm.ifm_data, iface);
			break;
		case RTM_IFANNOUNCE:
			log_debug("RTM_IFANNOUNCE");
/* 			if_announce(next); */
			break;
		case RTM_NEWADDR:
			/* TODO */
			log_debug("RTM_NEWADDR");
			break;
		case RTM_DELADDR:
			/* TODO */
			log_debug("RTM_DELADDR");
			break;
		default:
			/* ignore for now */
			break;
		}
	}
}

void
kev_ifinfo(struct if_data *ifd, struct iface *iface)
{
	if (LINK_STATE_IS_UP(ifd->ifi_link_state))
		if_fsm(iface, IF_EVT_UP);
	else
		if_fsm(iface, IF_EVT_DOWN);
}

void
kev_cleanup(void)
{
	/* TODO */
}


