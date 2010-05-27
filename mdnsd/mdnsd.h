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

#include "mdns.h"
#include "imsg.h"
#include "control.h"

#define	MDNSD_USER		"_mdnsd"
#define RT_BUF_SIZE		16384
#define MAX_RTSOCK_BUF		128 * 1024
#define QUERY_TTL		1
#define RESPONSE_TTL		255
#define MDNS_PORT		5353
#define HDR_LEN			12	
#define MINQRY_LEN		6 /* 4 (qtype + qclass) +1 (null) + 1 (label len) */
#define HDR_QR_MASK		0x8000
#define MAX_PACKET		10000
#define MAX_LABELS		128
#define TTL_HNAME		120
#define CACHEFLUSH_MSK		0x8000
#define CLASS_MSK		~0x8000
#define UNIRESP_MSK		0x8000
#define NAMECOMP_MSK		0xc000
#define NAMEADDR_MSK		~0xc000
#define QR_MSK                 	0x8000
#define TC_MSK                 	0x200

struct rr {
	LIST_ENTRY(rr)		entry;
	char			dname[MAXHOSTNAMELEN];
	u_int16_t		type;
	int			cacheflush;	
	u_int16_t		class;
	u_int32_t		ttl;
	u_int16_t		rdlen;
	union {
		struct in_addr	A;
		char		CNAME[MAXHOSTNAMELEN];
		char		PTR[MAXHOSTNAMELEN];
		char		NS[MAXHOSTNAMELEN];
		char		TXT[MAX_CHARSTR];
		struct srv 	SRV;
		struct hinfo 	HINFO;

	} rdata;
	int		revision;	/* at 80% of ttl, then 90% and 95% */
	struct event 	rev_timer; 	/* cache revision timer */
	
};

struct question {
	LIST_ENTRY(question)	entry;
	char			dname[MAXHOSTNAMELEN];
	u_int16_t		qtype;
	u_int16_t		qclass;
	int			uniresp;
	int 			probe;
};

#define RR_UNIQ(rr) (rr->cacheflush)
#define QEQUIV(qa, qb)						\
	((qa->qtype  == qb->qtype)	&&			\
	    (qb->qclass == qb->qclass)	&&			\
	    (strcmp(qa->dname, qb->dname) == 0))
#define ANSWERS(q, rr)							\
	((((q)->qtype == T_ANY) || ((q)->qtype == (rr)->type))    &&	\
	    (q)->qclass == (rr)->class                            &&	\
	    strcmp((q)->dname, (rr)->dname) == 0)

/* mdnsd.c */
int	peersuser(int);
void	reversstr(char [MAXHOSTNAMELEN], struct in_addr *);
int	mdnsd_imsg_compose_ctl(struct ctl_conn *, u_int16_t, void *, u_int16_t);

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

/* this shouldn't be here */
struct rrt_node {
	RB_ENTRY(rrt_node)      entry;
	LIST_HEAD(rr_head, rr) hrr; /* head rr */
};

RB_HEAD(rrt_tree, rrt_node);
RB_PROTOTYPE(rrt_tree, rrt_node, entry, rrt_compare);

struct iface {
	LIST_ENTRY(iface)	 entry;
	struct rrt_tree		 rrt;
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

/* mdnsd.c */
struct mdnsd_conf {
	LIST_HEAD(, iface)	iface_list;
	int 			mdns_sock;
	struct event	 	ev_mdns;
	struct hinfo		hi;
	char 			myname[MAXHOSTNAMELEN];
};
void		 imsg_event_add(struct imsgev *);
int		 imsg_compose_event(struct imsgev *, u_int16_t, u_int32_t,
	pid_t, int, void *, u_int16_t);

/* packet.c */
struct pkt {
	/* mdns header */
	u_int8_t 	qr;
	u_int8_t	tc;
	
	u_int16_t	qdcount; /* question */
	u_int16_t	ancount; /* answer */
	u_int16_t	nscount; /* authority */
	u_int16_t	arcount; /* additional */
	
	LIST_HEAD(, question) qlist;
	LIST_HEAD(, rr)       anlist;
	LIST_HEAD(, rr)       nslist;
	LIST_HEAD(, rr)       arlist;
};

void	recv_packet(int, short, void *);	/* these don't belong here */
int	send_packet(struct iface *, void *, size_t, struct sockaddr_in *);
int	pkt_send_allif(struct pkt *);
void	pkt_init(struct pkt *);
int	pkt_add_question(struct pkt *, struct question *);
int 	pkt_add_anrr(struct pkt *, struct rr *);
int 	pkt_add_nsrr(struct pkt *, struct rr *);
int 	pkt_add_arrr(struct pkt *, struct rr *);
int 	question_set(struct question *, char [MAXHOSTNAMELEN], u_int16_t,
    u_int16_t, int, int);
int 	rr_set(struct rr *, char [MAXHOSTNAMELEN], u_int16_t, u_int16_t,
    u_int32_t, int, void *, size_t);

/* mdns.c */
enum publish_state {
	PUB_INITIAL,
    	PUB_PROBE,
    	PUB_ANNOUNCE,
	PUB_DONE
};

struct publish {
	LIST_ENTRY(publish)	entry;
	struct pkt	 	pkt;
	struct event	 	timer;	/* used in probe and announce */
	struct iface	       *iface;
	int		 	state;	/* enum publish state */
	int		 	sent;	/* how many packets we sent be it probe
					 * or announce */
	unsigned long	 	id;	/* unique id */
};

enum query_style {
	QUERY_SINGLE,
	QUERY_CONTINUOUS,
};

struct query {
	int		active;
	int		style;
	int		sleep;
	int		msgtype;
	struct question mq;
	struct event	timer;
};

void		 publish_init(void);
void		 publish_allrr(struct iface *);
int		 publish_insert(struct iface *, struct rr *);
int		 publish_delete(struct iface *, struct rr *);
struct rr *	 publish_lookupall(char [MAXHOSTNAMELEN], u_int16_t, u_int16_t);
void		 query_init(void);
struct query *	 query_place(int, char [MAXHOSTNAMELEN], u_int16_t, u_int16_t);
struct query *	 query_lookup(char [MAXHOSTNAMELEN], u_int16_t, u_int16_t);
int		 query_answerctl(struct ctl_conn *, struct rr *, int);
int		 query_notify(struct rr *, int);
void		 query_remove(struct query *);
void		 cache_init(void);
int		 cache_process(struct rr *);
struct rr	*cache_lookup(char [MAXHOSTNAMELEN], u_int16_t, u_int16_t);

LIST_HEAD(, publish)		probing_list;

/* control.c */
int   		 control_hasq(struct ctl_conn *, struct query *);
TAILQ_HEAD(ctl_conns, ctl_conn) ctl_conns;

#endif /* _MDNSD_H_ */
