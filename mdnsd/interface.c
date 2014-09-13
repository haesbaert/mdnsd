/*
 * Copyright (c) 2006 Michele Marchetto <mydecay@openbeer.it>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
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
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <event.h>

#include "mdnsd.h"
#include "log.h"

extern struct mdnsd_conf *conf;

int	 if_act_start(struct iface *);
int	 if_act_reset(struct iface *);

struct {
	int			state;
	enum iface_event	event;
	enum iface_action	action;
	int			new_state;
} iface_fsm[] = {
    /* current state	event that happened	action to take	resulting state */
    {IF_STA_DOWN,	IF_EVT_UP,		IF_ACT_STRT,	0},
    {IF_STA_ANY,	IF_EVT_DOWN,		IF_ACT_RST,	IF_STA_DOWN},
    {-1,		IF_EVT_NOTHING,		IF_ACT_NOTHING,	0},
};

const char * const if_action_names[] = {
	"NOTHING",
	"START",
	"RESET"
};

const char * const if_event_names[] = {
	"NOTHING",
	"UP",
	"DOWN",
};

int
if_fsm(struct iface *iface, enum iface_event event)
{
	int	 old_state;
	int	 new_state = 0;
	int	 i, ret = 0;

	old_state = iface->state;

	for (i = 0; iface_fsm[i].state != -1; i++)
		if ((iface_fsm[i].state & old_state) &&
		    (iface_fsm[i].event == event)) {
			new_state = iface_fsm[i].new_state;
			break;
		}

	if (iface_fsm[i].state == -1) {
		/* event outside of the defined fsm, ignore it. */
		log_debug("if_fsm: interface %s, "
		    "event '%s' not expected in state '%s'", iface->name,
		    if_event_name(event), if_state_name(old_state));
		return (0);
	}

	switch (iface_fsm[i].action) {
	case IF_ACT_STRT:
		ret = if_act_start(iface);
		break;
	case IF_ACT_RST:
		ret = if_act_reset(iface);
		break;
	case IF_ACT_NOTHING:
		/* do nothing */
		break;
	}

	if (ret) {
		log_debug("if_fsm: error changing state for interface %s, "
		    "event '%s', state '%s'", iface->name, if_event_name(event),
		    if_state_name(old_state));
		return (0);
	}

	if (new_state != 0)
		iface->state = new_state;

	log_debug("if_fsm: event '%s' resulted in action '%s' and changing "
	    "state for interface %s from '%s' to '%s'",
	    if_event_name(event), if_action_name(iface_fsm[i].action),
	    iface->name, if_state_name(old_state), if_state_name(iface->state));

	return (ret);
}

struct iface *
if_find_index(u_short ifindex)
{
	struct iface	 *iface;

	LIST_FOREACH(iface, &conf->iface_list, entry) {
		if (iface->ifindex == ifindex)
			return (iface);
	}

	return (NULL);
}

struct iface *
if_find_iface(unsigned int ifindex, struct in_addr src)
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

/* actions */
int
if_act_start(struct iface *iface)
{
	struct in_addr	 addr;
	struct timeval	 now;

	if (!((iface->flags & IFF_UP) &&
	    (LINK_STATE_IS_UP(iface->linkstate) ||
	    (iface->linkstate == LINK_STATE_UNKNOWN &&
	    iface->media_type != IFT_CARP)))) {
		log_debug("if_act_start: interface %s link down",
		    iface->name);
		return (0);
	}

	gettimeofday(&now, NULL);
	iface->uptime = now.tv_sec;

	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		inet_aton(ALL_MDNS_DEVICES, &addr);
		if (if_join_group(iface, &addr)) {
			log_warn("if_act_start: error joining group %s, "
			    "interface %s", inet_ntoa(addr), iface->name);
			return (-1);
		}

		iface->state = IF_STA_ACTIVE;
		break;
	default:
		fatalx("if_act_start: unknown interface type");
	}

	/* publish all groups on this interface */
	pg_publish_byiface(iface);

	return (0);
}

int
if_act_reset(struct iface *iface)
{
	struct in_addr		 addr;

	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		inet_aton(ALL_MDNS_DEVICES, &addr);
		if (if_leave_group(iface, &addr)) {
			log_warn("if_act_reset: error leaving group %s, "
			    "interface %s", inet_ntoa(addr), iface->name);
		}
		break;
	default:
		fatalx("if_act_reset: unknown interface type");
	}

	return (0);
}

const char *
if_event_name(int event)
{
	return (if_event_names[event]);
}

const char *
if_action_name(int action)
{
	return (if_action_names[action]);
}

/* misc */
int
if_set_mcast_ttl(int fd, u_int8_t ttl)
{
	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL,
	    (char *)&ttl, sizeof(ttl)) < 0) {
		log_warn("if_set_mcast_ttl: error setting "
		    "IP_MULTICAST_TTL to %d", ttl);
		return (-1);
	}

	return (0);
}

int
if_set_opt(int fd)
{
	int	 yes = 1;

	if (setsockopt(fd, IPPROTO_IP, IP_RECVIF, &yes,
	    sizeof(int)) < 0) {
		log_warn("if_set_opt: error setting IP_RECVIF");
		return (-1);
	}

	if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &yes,
	    sizeof(int)) < 0) {
		log_warn("if_set_opt: error setting IP_RECVDSTADDR");
		return (-1);
	}

	return (0);
}

int
if_set_tos(int fd, int tos)
{
	if (setsockopt(fd, IPPROTO_IP, IP_TOS,
	    (int *)&tos, sizeof(tos)) < 0) {
		log_warn("if_set_tos: error setting IP_TOS to 0x%x", tos);
		return (-1);
	}

	return (0);
}

int
if_set_mcast(struct iface *iface)
{
	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		if (setsockopt(iface->fd, IPPROTO_IP, IP_MULTICAST_IF,
		    &iface->addr.s_addr, sizeof(iface->addr.s_addr)) < 0) {
			log_debug("if_set_mcast: error setting "
				"IP_MULTICAST_IF, interface %s", iface->name);
			return (-1);
		}
		break;
	default:
		fatalx("if_set_mcast: unknown interface type");
	}

	return (0);
}

int
if_set_mcast_loop(int fd)
{
	u_int8_t	 loop = 0;

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP,
	    (char *)&loop, sizeof(loop)) < 0) {
		log_warn("if_set_mcast_loop: error setting IP_MULTICAST_LOOP");
		return (-1);
	}

	return (0);
}

void
if_set_recvbuf(int fd)
{
	int	 bsize;

	bsize = 65535;
	while (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bsize,
	    sizeof(bsize)) == -1)
		bsize /= 2;
}

int
if_join_group(struct iface *iface, struct in_addr *addr)
{
	struct ip_mreq	 mreq;

	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		mreq.imr_multiaddr.s_addr = addr->s_addr;
		mreq.imr_interface.s_addr = iface->addr.s_addr;

		if (setsockopt(iface->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		    (void *)&mreq, sizeof(mreq)) < 0)
			return (-1);
		break;
	default:
		fatalx("if_join_group: unknown interface type");
	}

	return (0);
}

int
if_leave_group(struct iface *iface, struct in_addr *addr)
{
	struct ip_mreq	 mreq;

	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		mreq.imr_multiaddr.s_addr = addr->s_addr;
		mreq.imr_interface.s_addr = iface->addr.s_addr;

		if (setsockopt(iface->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
		    (void *)&mreq, sizeof(mreq)) < 0)
			return (-1);
		break;
	default:
		fatalx("if_leave_group: unknown interface type");
	}

	return (0);
}

struct iface *
if_new(struct kif *kif)
{
	struct sockaddr_in	*sain;
	struct iface		*iface;
	struct ifreq		*ifr;
	int			s;
	int succeed = 0;

	if ((iface = calloc(1, sizeof(*iface))) == NULL)
		err(1, "if_new: calloc");

	iface->state = IF_STA_DOWN;

	strlcpy(iface->name, kif->ifname, sizeof(iface->name));

	if ((ifr = calloc(1, sizeof(*ifr))) == NULL)
		err(1, "if_new: calloc");

	/* set up ifreq */
	strlcpy(ifr->ifr_name, kif->ifname, sizeof(ifr->ifr_name));
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(1, "if_new: socket");

	/* get type */
	if (kif->flags & IFF_POINTOPOINT)
		iface->type = IF_TYPE_POINTOPOINT;
	if (kif->flags & IFF_BROADCAST &&
	    kif->flags & IFF_MULTICAST)
		iface->type = IF_TYPE_BROADCAST;
	if (kif->flags & IFF_LOOPBACK) {
		iface->type = IF_TYPE_POINTOPOINT;
		/* XXX protect loopback from sending packets over lo? */
	}

	/* get mtu, index and flags */
	iface->mtu = kif->mtu;
	iface->ifindex = kif->ifindex;
	iface->flags = kif->flags;
	iface->linkstate = kif->link_state;
	iface->media_type = kif->media_type;
	iface->baudrate = kif->baudrate;
	iface->ea = kif->ea;

	/* get address */
	if (ioctl(s, SIOCGIFADDR, ifr) < 0) {
		log_warn("if_new: cannot get address");
		goto end;
	}
	sain = (struct sockaddr_in *)&ifr->ifr_addr;
	iface->addr = sain->sin_addr;

	/* get mask */
	if (ioctl(s, SIOCGIFNETMASK, ifr) < 0) {
		log_warn("if_new: cannot get mask");
		goto end;
	}
	sain = (struct sockaddr_in *)&ifr->ifr_addr;
	iface->mask = sain->sin_addr;

	/* get p2p dst address */
	if (kif->flags & IFF_POINTOPOINT) {
		if (ioctl(s, SIOCGIFDSTADDR, ifr) < 0) {
			log_warn("if_new: cannot get dst addr");
			goto end;
		}
		sain = (struct sockaddr_in *)&ifr->ifr_addr;
		iface->dst = sain->sin_addr;
	}

	/* get the primary group for this interface */
	if (conf->no_workstation == 0)
		iface->pge_workstation = pge_new_workstation(iface);

	succeed = 1;

end:
	if (!succeed) {
		free(iface);
		iface = NULL;
	}

	free(ifr);
	close(s);

	return (iface);
}
