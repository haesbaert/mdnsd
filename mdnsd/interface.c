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
#include <net/if_dl.h>
#include <net/if_types.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <event.h>

#include <ifaddrs.h>

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

/* Return the first address matching the given af */
struct iface_addr *
if_get_addr(sa_family_t af, struct iface *iface)
{
	struct iface_addr *ifa;

	LIST_FOREACH(ifa, &iface->addr_list, entry) {
		if (ifa->addr.ss_family == af)
			return (ifa);
	}

	return (NULL);
}

/* Find the interface address that matches the given addr */
struct iface_addr *
if_find_addr(struct sockaddr *addr, struct iface *iface)
{
	struct iface_addr *ifa;
	struct sockaddr_in *sa4, *addr4;
	struct sockaddr_in6 *sa6, *addr6;

	LIST_FOREACH(ifa, &iface->addr_list, entry) {
		if (ifa->addr.ss_family != addr->sa_family)
			continue;

		switch (ifa->addr.ss_family) {
		case AF_INET:
			sa4 = (struct sockaddr_in *)&ifa->addr;
			addr4 = (struct sockaddr_in *)addr;
			if (sa4->sin_addr.s_addr == addr4->sin_addr.s_addr)
				return (ifa);
			break;
		case AF_INET6:
			sa6 = (struct sockaddr_in6 *)&ifa->addr;
			addr6 = (struct sockaddr_in6 *)addr;
			if (IN6_ARE_ADDR_EQUAL(&sa6->sin6_addr, &addr6->sin6_addr))
				return (ifa);
			break;
		default:
			log_warn("if_find_addr: AF not found");
		}
	}

	return (NULL);
}

/* Find the interface address that is in the same subnet as the given addr */
struct iface_addr *
if_contains_addr(struct sockaddr *addr, struct iface *iface)
{
	struct iface_addr *ifa;
	struct sockaddr_in *sa4, *snm4, *addr4;
	struct sockaddr_in6 *sa6, *snm6, *addr6;
	uint8_t *uaddr;
	int prefix;

	LIST_FOREACH(ifa, &iface->addr_list, entry) {
		if (ifa->addr.ss_family != addr->sa_family)
			continue;

		switch (ifa->addr.ss_family) {
		case AF_INET:
			sa4 = (struct sockaddr_in *)&ifa->addr;
			snm4 = (struct sockaddr_in *)&ifa->netmask;
			addr4 = (struct sockaddr_in *)addr;
			if ((sa4->sin_addr.s_addr & snm4->sin_addr.s_addr) == (addr4->sin_addr.s_addr & snm4->sin_addr.s_addr))
				return (ifa);
			break;
		case AF_INET6:
			sa6 = (struct sockaddr_in6 *)&ifa->addr;
			snm6 = (struct sockaddr_in6 *)&ifa->netmask;
			addr6 = (struct sockaddr_in6 *)addr;
			uaddr = (uint8_t *)&snm6->sin6_addr;
			for (prefix = 0; prefix < 16 && *uaddr == 0xff; prefix++, uaddr++);
			if (prefix != 0 && memcmp(&sa6->sin6_addr, &addr6->sin6_addr, prefix))
				return (ifa);
			break;
		default:
			log_warn("if_contains_addr: AF not found");
		}
	}

	return (NULL);
}

/* actions */
int
if_act_start(struct iface *iface)
{
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
		break;
	default:
		fatalx("if_act_start: unknown interface type");
	}

	if ((conf->udp4.fd != 0 && if_join_group(AF_INET, iface)) ||
	    (conf->udp6.fd != 0 && if_join_group(AF_INET6, iface))) {
		log_warn("if_act_start: error joining group %s, "
		    "interface %s", ALL_MDNS_DEVICES, iface->name);
		return (-1);
	}

	iface->state = IF_STA_ACTIVE;

	/* publish all groups on this interface */
	pg_publish_byiface(iface);

	return (0);
}

int
if_act_reset(struct iface *iface)
{
	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		break;
	default:
		fatalx("if_act_reset: unknown interface type");
	}

	if ((conf->udp4.fd != 0 && if_leave_group(AF_INET, iface)) ||
	    (conf->udp6.fd != 0 && if_leave_group(AF_INET6, iface))) {
		log_warn("if_act_reset: error leaving group %s, "
		    "interface %s", ALL_MDNS_DEVICES, iface->name);
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
if_set_mcast_ttl(sa_family_t af, int fd, u_int8_t ttl)
{
	int hops;

	switch (af) {
	case AF_INET:
		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL,
		    (char *)&ttl, sizeof(ttl)) < 0) {
			log_warn("if_set_mcast_ttl: error setting "
			    "IP_MULTICAST_TTL to %u", ttl);
			return (-1);
		}
		break;
	case AF_INET6:
		hops = MDNS_TTL;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
		   &hops, sizeof(hops)) < 0) {
			log_warn("if_set_mcast_ttl: error setting "
			    "IPV6_MULTICAST_HOPS to %u", ttl);
			return (-1);
		}
		break;
	default:
		log_warn("if_set_mcast_ttl: AF not found");
		return (-1);
	};

	return (0);
}

int
if_set_opt(sa_family_t af, int fd)
{
	int	 yes = 1;

	switch (af) {
	case AF_INET:
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
		break;
	case AF_INET6:
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes,
		    sizeof(int)) < 0) {
			log_warn("if_set_opt: error setting IPV6_RECVPKTINFO");
			return (-1);
		}
		break;
	default:
		log_warn("if_set_opt: AF not found");
		return (-1);
	};

	return (0);
}

int
if_set_mcast(sa_family_t af, struct iface *iface)
{
	struct iface_addr *ifa;

	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		break;
	default:
		fatalx("if_set_mcast: unknown interface type");
		return (-0);
	}

	switch (af) {
	case AF_INET:
		if ((ifa = if_get_addr(AF_INET, iface)) == NULL) {
			log_warn("if_set_mcast: No IP address found for iface");
		} else {
			if (setsockopt(conf->udp4.fd, IPPROTO_IP, IP_MULTICAST_IF,
			    &((struct sockaddr_in *)&ifa->addr)->sin_addr.s_addr, sizeof(in_addr_t)) < 0) {
				log_debug("if_set_mcast: error setting "
					"IP_MULTICAST_IF, interface %s", iface->name);
				return (-1);
			}
		}
		break;
	case AF_INET6:
		if (setsockopt(conf->udp6.fd, IPPROTO_IPV6, IPV6_MULTICAST_IF,
		    &iface->ifindex, sizeof(u_int)) < 0) {
			log_debug("if_set_mcast: error setting "
				"IPV6_MULTICAST_IF, interface %s", iface->name);
			return (-1);
		}
		break;
	default:
		log_warn("if_set_mcast: AF not found");
		return (-1);
	}

	return (0);
}

int
if_set_mcast_loop(sa_family_t af, int fd)
{
	u_int8_t	 loop = 0;
	uint loop6;

	switch (af) {
	case AF_INET:
		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP,
		    (char *)&loop, sizeof(loop)) < 0) {
			log_warn("if_set_mcast_loop: error setting IP_MULTICAST_LOOP");
			return (-1);
		}
		break;
	case AF_INET6:
		loop6 = loop;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
		    &loop6, sizeof(loop6)) < 0) {
			log_warn("if_set_mcast_loop: error setting IPV6_MULTICAST_LOOP");
			return (-1);
		}
		break;
	default:
		log_warn("if_set_mcast_loop: AF not found");
		return (-1);
	};

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
if_join_group(sa_family_t af, struct iface *iface)
{
	struct ip_mreq	 mreq;
	struct ipv6_mreq mreq6;
	struct iface_addr *ifa;

	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		break;
	default:
		fatalx("if_join_group: unknown interface type");
	}

	switch (af) {
	case AF_INET:
		if ((ifa = if_get_addr(AF_INET, iface)) == NULL) {
			log_warn("if_join_group: No IP address found for iface");
		} else {
			mreq.imr_multiaddr.s_addr = ntohl(MDNS_INADDR);
			mreq.imr_interface.s_addr = ((struct sockaddr_in *)&ifa->addr)->sin_addr.s_addr;

			if (setsockopt(conf->udp4.fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
			    (void *)&mreq, sizeof(mreq)) < 0) {
				log_warn("Error joining IPV4 group");
				return (-1);
			}
		}
		break;
	case AF_INET6:
		memcpy(&mreq6.ipv6mr_multiaddr, &mdns_in6addr, sizeof(struct in6_addr));
		mreq6.ipv6mr_interface = iface->ifindex;

		if (setsockopt(conf->udp6.fd, IPPROTO_IPV6, IPV6_JOIN_GROUP,
		    (void *)&mreq6, sizeof(mreq6)) < 0) {
			log_warn("Error joining IPV6 group");
			return (-1);
		}
		break;
	default:
		log_warn("if_join_group: AF not found");
		return (-1);
	}

	return (0);
}

int
if_leave_group(sa_family_t af, struct iface *iface)
{
	struct ip_mreq	 mreq;
	struct ipv6_mreq mreq6;
	struct iface_addr *ifa;

	switch (iface->type) {
	case IF_TYPE_POINTOPOINT:
	case IF_TYPE_BROADCAST:
		break;
	default:
		fatalx("if_leave_group: unknown interface type");
	}

	switch (af) {
	case AF_INET:
		if ((ifa = if_get_addr(AF_INET, iface)) == NULL) {
			log_warn("if_leave_group: No IP address found for iface");
		} else {
			mreq.imr_multiaddr.s_addr = ntohl(MDNS_INADDR);
			mreq.imr_interface.s_addr = ((struct sockaddr_in *)&ifa->addr)->sin_addr.s_addr;

			if (setsockopt(conf->udp4.fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,
			    (void *)&mreq, sizeof(mreq)) < 0)
				return (-1);
		}
		break;
	case AF_INET6:
		memcpy(&mreq6.ipv6mr_multiaddr, &mdns_in6addr, sizeof(struct in6_addr));
		mreq6.ipv6mr_interface = iface->ifindex;

		if (setsockopt(conf->udp6.fd, IPPROTO_IPV6, IPV6_LEAVE_GROUP,
		    (void *)&mreq6, sizeof(mreq6)) < 0)
			return (-1);
		break;
	default:
		log_warn("if_leave_group: AF not found");
		return (-1);
	}

	return (0);
}

struct iface *
if_new(const char *name)
{
	struct iface		*iface;
	struct iface_addr	*addr;
	struct sockaddr_dl	*sdl;
	struct if_data		*ifd;
	struct ifaddrs		*ifa, *ifalist;

	if (name == NULL)
		return (NULL);

	if ((iface = calloc(1, sizeof(*iface))) == NULL)
		err(1, "if_new: calloc");

	iface->state = IF_STA_DOWN;

	strlcpy(iface->name, name, sizeof(iface->name));

	if (getifaddrs(&ifalist) == -1)
		fatal("getifaddrs");

	for (ifa = ifalist; ifa != NULL; ifa = ifa->ifa_next) {
		if (strncmp(name, ifa->ifa_name, IF_NAMESIZE) != 0)
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_LINK:
			if ((ifa->ifa_flags & IFF_MULTICAST) == 0)
				warn("%s: Interface cannot recieve multicast", name);
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			ifd = (struct if_data *)ifa->ifa_data;
			iface->flags = ifa->ifa_flags;
			iface->ifindex = sdl->sdl_index;
			iface->type = sdl->sdl_type;
			iface->mtu = ifd->ifi_mtu;
			iface->linkstate = ifd->ifi_link_state;
			iface->media_type = sdl->sdl_type;
			iface->baudrate = ifd->ifi_baudrate;
			memcpy(&iface->ea, sdl->sdl_data + sdl->sdl_nlen, sdl->sdl_alen);
			break;
		case AF_INET:
		case AF_INET6:
			addr = calloc(1, sizeof(struct iface_addr));
			if (addr == NULL)
				fatal("calloc");

			memcpy(&addr->addr, ifa->ifa_addr, ifa->ifa_addr->sa_len);

			if (ifa->ifa_dstaddr != NULL)
				memcpy(&addr->dstaddr, ifa->ifa_dstaddr, ifa->ifa_dstaddr->sa_len);

			if (ifa->ifa_netmask != NULL)
				memcpy(&addr->netmask, ifa->ifa_netmask, ifa->ifa_netmask->sa_len);

			LIST_INSERT_HEAD(&iface->addr_list, addr, entry);
			break;
		default:
			warnx("if_add AF unsupported: %u", ifa->ifa_addr->sa_family);
		};
	}

	/* get type */
	if (iface->flags & IFF_POINTOPOINT)
		iface->type = IF_TYPE_POINTOPOINT;
	if (iface->flags & IFF_BROADCAST &&
	    iface->flags & IFF_MULTICAST)
		iface->type = IF_TYPE_BROADCAST;
	if (iface->flags & IFF_LOOPBACK) {
		iface->type = IF_TYPE_POINTOPOINT;
		/* XXX protect loopback from sending packets over lo? */
	}

	addr = if_get_addr(AF_INET, iface);

	/* get the primary group for this interface */
	if (conf->no_workstation == 0)
		iface->pge_workstation = pge_new_workstation(iface);

	freeifaddrs(ifalist);
	return (iface);
}

void
if_newaddr(struct sockaddr *addr, struct sockaddr *dstaddr, struct sockaddr *netmask, struct iface *iface)
{
	struct iface_addr *ifa;

	ifa = calloc(1, sizeof(struct iface_addr));
	if (ifa == NULL)
		fatal("calloc");

	memcpy(&ifa->addr, addr, addr->sa_len);

	if (dstaddr != NULL)
		memcpy(&ifa->dstaddr, dstaddr, dstaddr->sa_len);

	if (netmask != NULL)
		memcpy(&ifa->netmask, netmask, netmask->sa_len);

	/* XXX add address to the cache */
	/*
	rr = rr_set;
	if ((cn = cache_lookup_dname(rr->rrs.dname)) == NULL)
		return (cache_insert(rr));
	*/

	LIST_INSERT_HEAD(&iface->addr_list, ifa, entry);
	/* XXX If this is the first AF_INET address added after startup, then trigger if_group_join here */
	return;
}

void
if_deladdr(struct sockaddr *addr, struct iface *iface)
{
	struct iface_addr *ifa;

	ifa = if_find_addr(addr, iface);
	if (ifa == NULL) {
		log_warn("if_deladdr: Address not found");
		return;
	}

	LIST_REMOVE(ifa, entry);
	/* TODO purge address from cache */
	free(ifa);
}
