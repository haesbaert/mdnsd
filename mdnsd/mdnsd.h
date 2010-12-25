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
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>

#include <event.h>
#include <imsg.h>

#include "mdns.h"
#include "control.h"

#define MDNSD_USER		"_mdnsd"
#define ALL_MDNS_DEVICES	"224.0.0.251"
#define MDNS_ADDRT		0xFB0000E0 /* the in_addr for 224.0.0.251 */
#define MDNS_TTL		255
#define MDNS_PORT		5353
#define TTL_A			120
#define TTL_AAAA		120
#define TTL_HNAME		120
#define TTL_SRV			(75 * 60)
#define TTL_TXT			(75 * 60)
#define TTL_PTR			(75 * 60)
#define MDNS_QUERY		0
#define MDNS_RESPONSE		1
#define INTERVAL_PROBETIME	250000
#define RANDOM_PROBETIME	arc4random_uniform(250000)
#define FIRST_QUERYTIME		(arc4random_uniform(120000) + 20000)
#define MAXQUERYTIME		(60 * 60) /* one hour */

#define ANSWERS(q, rr)							\
	((((q)->rrs.type == T_ANY) || ((q)->rrs.type == (rr)->rrs.type)) && \
	    (q)->rrs.class == (rr)->rrs.class                            && \
	    (strcmp((q)->rrs.dname, (rr)->rrs.dname)) == 0)

#define RR_UNIQ(rr) (rr->cacheflush)

struct rrset {
	LIST_ENTRY(rrset) entry;
	char            dname[MAXHOSTNAMELEN];
	u_int16_t       type;
	u_int16_t       class;
};

struct rrt_node {
	RB_ENTRY(rrt_node)      entry;
	struct rrset		rrs;
	LIST_HEAD(, rr) 	hrr;	/* head rr */
};
RB_HEAD(rrt_tree, rrt_node);
RB_PROTOTYPE(rrt_tree, rrt_node, entry, rrt_cmp);

struct hinfo {
	char    cpu[MAXCHARSTR];
	char    os[MAXCHARSTR];
};

struct srv {
	u_int16_t       priority;
	u_int16_t       weight;
	u_int16_t       port;
	char            target[MAXHOSTNAMELEN];
};

struct rr {
	LIST_ENTRY(rr)		centry;	/* cache entry */
	LIST_ENTRY(rr)		pentry;	/* packet entry */
	LIST_ENTRY(rr)		gentry;	/* group entry */
	struct rrset 		rrs;
	int			cacheflush;
	u_int32_t		ttl;
	union {
		struct in_addr	A;
		char		CNAME[MAXHOSTNAMELEN];
		char		PTR[MAXHOSTNAMELEN];
		char		NS[MAXHOSTNAMELEN];
		char		TXT[MAXCHARSTR];
		struct srv	SRV;
		struct hinfo	HINFO;

	} rdata;
	int		revision;	/* at 80% of ttl, then 90% and 95% */
	struct event	rev_timer;	/* cache revision timer */
	struct timespec	age;
};

struct pkt {
	TAILQ_ENTRY(pkt)	entry;
	HEADER			h;
	LIST_HEAD(, question) 	qlist;	/* Question section */
	LIST_HEAD(, rr)       	anlist;	/* Answer section */
	LIST_HEAD(, rr)       	nslist;	/* Authority section */
	LIST_HEAD(, rr)       	arlist;	/* Additional section */
	struct sockaddr_in	ipsrc;
	struct event		timer;
	struct iface 	       *iface; /* The received interface */
};

struct question {
	LIST_ENTRY(question)	entry;
	RB_ENTRY(question)	qst_entry;
	struct rrset 		rrs;			
	struct in_addr		src; /* If unicast response, src != 0 */
	int			active;
	u_int			sent;
	struct timespec		lastsent;
	struct timespec		sched;
};

enum query_style {
	QUERY_LOOKUP,
	QUERY_BROWSE,
	QUERY_RESOLVE,
};

struct query {
	LIST_ENTRY(query)	 entry;
	LIST_HEAD(, rrset)	 rrslist;
	struct ctl_conn		*ctl;
	enum query_style	 style;
	struct event		 timer;
	u_int			 count;
	struct rrset		*ms_srv; /* The SRV in QUERY_RESOLVE */
	struct rrset		*br_ptr;
};

/* Publish Group */
struct pg {
	TAILQ_ENTRY(pg) 	entry;
	LIST_HEAD(, pge) 	pge_list;
	struct ctl_conn 	*c;
	char 			name[MAXHOSTNAMELEN];
	u_int 			flags;
#define PG_FLAG_INTERNAL 0x01
#define PG_FLAG_COMMITED 0x02
};

/* Publish Group Entry types */
enum pge_type {
	PGE_TYPE_CUSTOM,
	PGE_TYPE_SERVICE,
	PGE_TYPE_ADDRESS
};

enum pge_if_state {
	PGE_IF_STA_UNPUBLISHED,
	PGE_IF_STA_PROBING,
	PGE_IF_STA_ANNOUNCING,
	PGE_IF_STA_PUBLISHED,
};

/* Publish Group Entry */
struct pge {
	TAILQ_ENTRY(pge) 	entry;	  	/* pge_queue link */
	LIST_ENTRY(pge)		pge_entry; 	/* Group link */
	LIST_HEAD(, pge_if)	pge_if_list;	/* FSM list, one per iface */
	struct pg 	       *pg;		/* Parent Publish Group */
	enum pge_type 	 	pge_type;	/* Type of this entry */
	u_int 		 	pge_flags;	
#define PGE_FLAG_INC_A 0x01	/* Include primary A record */
};
	
/* Publish Group Entry per iface state */
struct pge_if {
	LIST_ENTRY(pge_if)	 entry;	    	/* pge_if_list link */
	LIST_HEAD(, rr)		 rr_list;	/* Proposed records */
	struct question 	*pqst;		/* Probing Question, may be NULL */
	struct pge		*pge; 		/* Pointer to parent */
	struct iface		*iface;		/* Iface to be published */
	struct event		 if_timer;	/* FSM timer */
	enum pge_if_state	 if_state;	/* FSM state */
	u_int			 if_sent;	/* How many sent packets */
	
};

/* Publish Group Queue, should hold all publishing groups */
TAILQ_HEAD(, pg)  pg_queue;
/* Publish Group Entry Queue, should hold all publishing group entries */
TAILQ_HEAD(, pge) pge_queue;

struct kif {
	char		ifname[IF_NAMESIZE];
	u_int64_t	baudrate;
	int		flags;
	int		mtu;
	u_short		ifindex;
	u_int8_t	media_type;
	u_int8_t	link_state;
};

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
	LIST_HEAD(, rr)	       	 auth_rr_list;
	struct pg		*pg_primary;
/* 	struct rrt_tree		 rrt; */
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

/* interface.c */
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
struct iface	*if_find_index(u_short);
struct iface	*if_find_iface(unsigned int, struct in_addr);
struct iface	*if_new(struct kif *);
void		 if_set_recvbuf(int);

struct mdnsd_conf {
	LIST_HEAD(, iface)	iface_list;
	int			mdns_sock;
	struct event		ev_mdns;
	struct hinfo		hi;
	char			myname[MAXHOSTNAMELEN];
};

/* kiface.c */
int		 kif_init(void);
void		 kif_cleanup(void);
struct kif	*kif_findname(char *);
void		 kev_init(void);
void		 kev_cleanup(void);

/* mdnsd.c */
int	peersuser(int);
void	reversstr(char [MAXHOSTNAMELEN], struct in_addr *);
int	mdnsd_imsg_compose_ctl(struct ctl_conn *, u_int16_t, void *, u_int16_t);
void	imsg_event_add(struct imsgev *);
int	imsg_compose_event(struct imsgev *, u_int16_t, u_int32_t, pid_t,
    int, void *, u_int16_t);

/* packet.c */
void	  packet_init(void);
void	  recv_packet(int, short, void *);   
int	  send_packet(struct iface *, void *, size_t, struct sockaddr_in *);
void	  pkt_process(int, short, void *);
int	  pkt_send_if(struct pkt *, struct iface *);
int	  pkt_send_allif(struct pkt *);
void	  pkt_init(struct pkt *);
void	  pkt_cleanup(struct pkt *);
void	  pkt_add_question(struct pkt *, struct question *);
void	  pkt_add_anrr(struct pkt *, struct rr *);
void	  pkt_add_nsrr(struct pkt *, struct rr *);
void	  pkt_add_arrr(struct pkt *, struct rr *);
int	  rr_rdata_cmp(struct rr *, struct rr *);
u_int32_t rr_ttl_left(struct rr *);
void	pktcomp_reset(int, u_int8_t *, u_int16_t);
int	rr_set(struct rr *, char [MAXHOSTNAMELEN], u_int16_t, u_int16_t,
    u_int32_t, int, void *, size_t);

/* mdns.c */
void		 publish_init(void);
void		 publish_allrr(struct iface *);
int		 publish_insert(struct iface *, struct rr *);
int		 publish_delete(struct iface *, struct rr *);
struct rr	*publish_lookupall(struct rrset *);
void		 publish_fsm(int, short, void *_pub);
void		 query_init(void);
void		 query_fsm(int, short, void *);
struct query	*query_lookup(struct rrset *);
void		 query_remove(struct query *);
void		 query_remove(struct query *);
struct question	*question_add(struct rrset *);
void		 question_remove(struct rrset *);
void		 cache_init(void);
int		 cache_process(struct rr *);
struct rr	*cache_lookup(struct rrset *);
int		 rrset_cmp(struct rrset *, struct rrset *);
int		 rr_notify_in(struct rr *);
int		 rr_notify_out(struct rr *);
struct rr	*rr_dup(struct rr *);
struct question *question_dup(struct question *);
void		 pg_init(void);
void		 pg_publish_byiface(struct iface *);
struct pg *	 pg_new_primary(struct iface *);
struct pg	*pg_get(int, char [MAXHOSTNAMELEN], struct ctl_conn *);
void		 pg_kill(struct pg *);
int		 pg_rr_in_conflict(struct rr *);
struct pge	*pge_from_ms(struct pg *, struct mdns_service *, struct iface *);
void		 pge_kill(struct pge *);
void		 pge_if_fsm(int, short, void *);
void		 pge_if_fsm_restart(struct pge_if *, struct timeval *);
struct rr *	 auth_lookup_rr(struct iface *, struct question *);

/* control.c */
TAILQ_HEAD(ctl_conns, ctl_conn) ctl_conns;
int     control_send_rr(struct ctl_conn *, struct rr *, int);
int	control_send_ms(struct ctl_conn *, struct mdns_service *, int);
int     control_try_answer_ms(struct ctl_conn *, char[MAXHOSTNAMELEN]);
				    

#endif /* _MDNSD_H_ */
