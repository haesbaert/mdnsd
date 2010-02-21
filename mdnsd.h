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

#ifndef _MDNSD_H_
#define	_MDNSD_H_

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <event.h>

#include "imsg.h"
#include "mdns.h"

#define	MDNSD_SOCKET	"/var/run/mdnsd.sock"
#define	MDNSD_USER	"_mdnsd"
#define RT_BUF_SIZE	16384
#define MAX_RTSOCK_BUF	128 * 1024

struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	void			*data;
	short			 events;
};

/* kiface.c */
struct kif {
	char		ifname[IF_NAMESIZE];
	u_int64_t	baudrate;
	int		flags;
	int		mtu;
	u_short		ifindex;
	u_int8_t	media_type;
	u_int8_t	link_state;
};

int		 kif_init(void);
void		 kif_cleanup(void);
struct kif	*kif_findname(char *);
void		 kev_init(void);
void		 kev_cleanup(void);

/* interface.c */
/* interface states */
#define IF_STA_DOWN		0x01
#define IF_STA_ACTIVE		(~IF_STA_DOWN)
#define IF_STA_ANY		0x7f

/* interface events */
enum iface_event {
	IF_EVT_NOTHING,
	IF_EVT_UP,
	IF_EVT_DOWN
};

/* interface actions */
enum iface_action {
	IF_ACT_NOTHING,
	IF_ACT_STRT,
	IF_ACT_RST
};

/* interface types */
enum iface_type {
	IF_TYPE_POINTOPOINT,
	IF_TYPE_BROADCAST,
	IF_TYPE_NBMA,
	IF_TYPE_POINTOMULTIPOINT
};

struct iface {
	LIST_ENTRY(iface)	 entry;

	char			 name[IF_NAMESIZE];
	struct in_addr		 addr;
	struct in_addr		 dst;
	struct in_addr		 mask;

	u_int64_t		 baudrate;
	time_t			 uptime;
	u_int			 mtu;
	int			 fd; /* XXX */
	int			 state;
	u_short			 ifindex;
	u_int16_t		 cost;
	u_int16_t		 flags;
	enum iface_type		 type;
	u_int8_t		 linktype;
	u_int8_t		 media_type;
	u_int8_t		 linkstate;
};

const char	*if_action_name(int);
const char	*if_event_name(int);
int		 if_act_reset(struct iface *);
int		 if_act_start(struct iface *);
int		 if_fsm(struct iface *, enum iface_event);
int		 if_join_group(struct iface *, struct in_addr *);
int		 if_leave_group(struct iface *, struct in_addr *);
int		 if_set_mcast(struct iface *);
int		 if_set_mcast_loop(int);
int		 if_set_mcast_ttl(int, u_int8_t);
int		 if_set_opt(int);
int		 if_set_tos(int, int);
struct iface *	 if_find_index(u_short);
struct iface *	 if_new(struct kif *);
void		 if_set_recvbuf(int);
void		 if_del(struct iface *);


/* mdnsd.c */
struct mdnsd_conf {
	LIST_HEAD(, iface)	iface_list;
	int 			mdns_sock;
	struct event	 	ev_mdns;
};

/* packet.c */
void	recv_packet(int, short, void *); /* these don't belong here */
int	send_packet(struct iface *, void *, size_t, struct sockaddr_in *);
	
/* cache.c */
void		 rrc_init(void);
int		 rrc_process(struct mdns_rr *);
void		 rrc_dump(void);
struct rr_head	*rrc_lookup_head(char [MAXHOSTNAMELEN], u_int16_t, u_int16_t);
struct mdns_rr	*rrc_lookup(char [MAXHOSTNAMELEN], u_int16_t, u_int16_t);

#endif /* _MDNSD_H_ */
