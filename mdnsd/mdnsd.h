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
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <event.h>
#include <imsg.h>

#include "mdns.h"
#include "control.h"

#define MDNSD_USER		"_mdnsd"
#define ALL_MDNS_DEVICES	"224.0.0.251"
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
#define ALL_IFACE 		(NULL)

#define ANSWERS(qrrs, rrs)						\
	((((qrrs)->type == T_ANY) || ((qrrs)->type == (rrs)->type))  && \
	    (qrrs)->class == (rrs)->class                            &&	\
	    (strcmp((qrrs)->dname, (rrs)->dname)) == 0)

#define RR_UNIQ(rr) (rr->flags & RR_FLAG_CACHEFLUSH)
#define RR_AUTH(rr) (rr->auth_refcount > 0)

#define CACHE_FOREACH_RRS(var, rrs)		\
	/* struct rr *var */			\
	/* struct rrs *rrs */			\
	for ((var) = cache_lookup(rrs);		\
	     (var) != NULL;			\
	     (var) = cache_next_by_rrs(var))

#define CACHE_FOREACH_DNAME(var, var2, dname)				\
	/* struct rr *var */						\
	/* struct cache_node *var2 */					\
	/* char dname[MAXHOSTNAMELEN] */				\
	for (((var2) = cache_lookup_dname(dname)),			\
		 (var2) ?						\
		 ((var) = LIST_FIRST(&(var2)->rr_list)) : NULL ;	\
	     (var2) != NULL && (var) != NULL;				\
	     (var) = LIST_NEXT(var, centry))				\

struct rrset {
	LIST_ENTRY(rrset) entry;	       /* List link */
	char            dname[MAXHOSTNAMELEN]; /* Domain Name */
	u_int16_t       type;		       /* RR type: T_A, T_PTR... */
	u_int16_t       class;		       /* C_IN */
};

struct cache_node {
	RB_ENTRY(cache_node) entry; 	/* Cache RBTREE link */
	LIST_HEAD(, rr)	     rr_list;	/* List of RR under dname */
	char 		     dname[MAXHOSTNAMELEN]; /* domain name */
};

struct hinfo {
	char    cpu[MAXCHARSTR]; /* Cpu name */
	char    os[MAXCHARSTR];	 /* Operating System name */
};

struct srv {
	u_int16_t       priority; /* Used only by application */
	u_int16_t       weight;	  /* Used only by application */
	u_int16_t       port;	  /* Service port, tcp or udp */
	char            target[MAXHOSTNAMELEN]; /* Service host */
};

struct rr {
	LIST_ENTRY(rr)		centry;	/* Cache entry */
	LIST_ENTRY(rr)		pentry;	/* Packet entry */
	struct rrset 		rrs;	/* RR tripple */
	u_int32_t		ttl;	/* DNS Time to live */
	union {
		struct in_addr	A; 	/* IPv4 Address */
		char		CNAME[MAXHOSTNAMELEN]; /* CNAME */
		char		PTR[MAXHOSTNAMELEN];   /* PTR */
		char		NS[MAXHOSTNAMELEN];    /* Name server */
		char		TXT[MAXCHARSTR];       /* Text */
		struct srv	SRV;		       /* Service */
		struct hinfo	HINFO;		       /* Host Info */

	} rdata;
	struct iface		*iface;	/* Published/Received interface */
	struct cache_node	*cn;	/* Cache parent node */
	int			 auth_refcount; /* Number of pges holding us */
	int			 revision; /* at 80% of ttl, then 90% and 95% */
	struct event		 timer; /* revision timer */
	struct timespec		 age;	/* XXX cant remember */
	u_int			 flags;	/* RR Flags */
#define RR_FLAG_CACHEFLUSH	0x01	/* Unique record */
#define RR_FLAG_PUBLISHED	0x02	/* Published record */
};

struct pkt {
	TAILQ_ENTRY(pkt)	entry;	/* Deferred pkt queue */
	u_int			flags;	/* Packet flags */
#define PKT_FLAG_LEGACY 0x1		/* Legacy unicast packet */
	HEADER			h;	/* Packet header */
	LIST_HEAD(, question) 	qlist;	/* Question section */
	LIST_HEAD(, rr)	      	anlist;	/* Answer section */
	LIST_HEAD(, rr)	      	nslist;	/* Authority section */
	LIST_HEAD(, rr)	      	arlist;	/* Additional section */
	struct sockaddr_in	ipsrc;	/* Received ipsource */
	struct event		timer;	/* Timer for truncated pkts */
	struct iface 	       *iface;  /* Received interface */
};

struct question {
	LIST_ENTRY(question)	entry; 	   /* Packet link */
	RB_ENTRY(question)	qst_entry; /* Question Tree link */
	struct rrset 		rrs;	   /* RR tripple */
	u_int			flags;	   /* Question flags */
#define QST_FLAG_UNIRESP 0x1		   /* Accepts unicast response */
	int			active;	   /* Active controllers */
	u_int			sent;	   /* Used in question_fsm */
	struct timespec		lastsent;  /* Last time we sent this question */
	struct timespec		sched;	   /* Next scheduled time to send */
};

enum query_style {
	QUERY_LOOKUP,		/* A simple single-shot query */
	QUERY_BROWSE,		/* A Continuous Querying query */
	QUERY_RESOLVE,		/* A service resolve query */
};

struct query {
	LIST_ENTRY(query)	 entry;	 /* Query link */
	LIST_HEAD(, rrset)	 rrslist;/* List of question tree keys */
	struct ctl_conn		*ctl;	 /* Owner */
	enum query_style	 style;	 /* Style */
	struct event		 timer;	 /* query_fsm() timer */
	u_int			 count;	 /* Used in query_fsm() */
	struct rrset		*ms_srv; /* The SRV in QUERY_RESOLVE */
	struct rrset		*ms_a;   /* The A in QUERY_RESOLVE */
	struct rrset		*br_ptr; /* The PTR in QUERY_BROWSE */
};

enum pg_state {
	PG_STA_NEW,
	PG_STA_COMMITED,
	PG_STA_COLLISION
};
/* Publish Group */
struct pg {
	TAILQ_ENTRY(pg) 	entry; 		/* pg_queue link */
	LIST_HEAD(, pge) 	pge_list;	/* List of pge */
	struct ctl_conn 	*c;		/* Owner */
	char 			name[MAXHOSTNAMELEN]; /* Name id */
	u_int 			flags;		/* Misc flags */
	enum pg_state		state;		/* enum pg_state */
};

/* Publish Group Entry types */
enum pge_type {
	PGE_TYPE_CUSTOM,	/* Unused */
	PGE_TYPE_SERVICE,	/* A DNS-SD Service */
	PGE_TYPE_ADDRESS	/* A Primary Address */
};

enum pge_state {
	PGE_STA_UNPUBLISHED,		/* Initial state */
	PGE_STA_PROBING,		/* Probing state */
	PGE_STA_ANNOUNCING,		/* Considered announced */
	PGE_STA_PUBLISHED,		/* Finished announcing */
};

#define PGE_RR_MAX 8
struct pge {
	TAILQ_ENTRY(pge) entry;	  	/* pge_queue link */
	LIST_ENTRY(pge)	 pge_entry; 	/* Group link */
	struct pg 	 *pg;		/* Parent Publish Group */
	enum pge_type 	  pge_type;	/* Type of this entry */
	u_int 		  pge_flags;	/* Misc flags */
#define PGE_FLAG_INC_A	  0x01		/* Include primary T_A record */
#define PGE_FLAG_INTERNAL 0x02		/* TODO: kill and test for pg */
	struct question  *pqst;		/* Probing Question, may be NULL */
	struct rr 	 *rr[PGE_RR_MAX]; /* Array of to publish rr */
	int 		  nrr;		/* Members in rr array */
	struct iface	 *iface;	/* Iface to be published */
	struct event	  timer;	/* FSM timer */
	enum pge_state	  state;	/* FSM state */
	u_int		  sent;		/* How many sent packets */
};

/* Publish Group Queue, should hold all publishing groups */
TAILQ_HEAD(, pg)  pg_queue;
/* Publish Group Entry Queue, should hold all publishing group entries */
TAILQ_HEAD(, pge) pge_queue;

struct kif {
	char			ifname[IF_NAMESIZE];
	u_int64_t		baudrate;
	int			flags;
	int			mtu;
	u_short			ifindex;
	u_int8_t		media_type;
	u_int8_t		link_state;
	struct ether_addr	ea;
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
	struct pge		*pge_primary;
	struct pge		*pge_workstation;
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
	struct ether_addr	 ea;
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
	int 			no_workstation;
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
int	  pkt_send_if(struct pkt *, struct iface *, struct sockaddr_in *);
int	  pkt_send_allif_do(struct pkt *, int);
#define   pkt_send_allif(pkt) pkt_send_allif_do(pkt, 0)
#define   pkt_send_allif_inc_prim(pkt) pkt_send_allif_do(pkt, 1)
void	  pkt_init(struct pkt *);
void	  pkt_cleanup(struct pkt *);
void	  pkt_add_question(struct pkt *, struct question *);
void	  pkt_add_anrr(struct pkt *, struct rr *);
void	  pkt_add_nsrr(struct pkt *, struct rr *);
void	  pkt_add_arrr(struct pkt *, struct rr *);
int	  rr_rdata_cmp(struct rr *, struct rr *);
u_int32_t rr_ttl_left(struct rr *);
void	  pktcomp_reset(int, u_int8_t *, u_int16_t);
int	  rr_set(struct rr *, char [MAXHOSTNAMELEN], u_int16_t, u_int16_t,
    u_int32_t, u_int, void *, size_t);

/* mdns.c */
void		 publish_init(void);
void		 publish_allrr(struct iface *);
int		 publish_insert(struct iface *, struct rr *);
int		 publish_delete(struct iface *, struct rr *);
struct rr	*publish_lookupall(struct rrset *);
void		 publish_fsm(int, short, void *);
void		 query_init(void);
void		 query_fsm(int, short, void *);
struct query	*query_lookup(struct rrset *);
void		 query_remove(struct query *);
struct question	*question_add(struct rrset *);
void		 question_remove(struct rrset *);
void		 cache_init(void);
int		 cache_insert(struct rr *);
int		 cache_delete(struct rr *);
void		 cache_schedrev(struct rr *);
void		 cache_rev(int, short, void *);
int		 cache_node_cmp(struct cache_node *, struct cache_node *);
int		 cache_process(struct rr *);
struct rr	*cache_lookup(struct rrset *);
struct cache_node *cache_lookup_dname(const char *);
struct rr 	*cache_next_by_rrs(struct rr *);
int		 rrset_cmp(struct rrset *, struct rrset *);
int		 rr_notify_in(struct rr *);
int		 rr_notify_out(struct rr *);
struct rr	*rr_dup(struct rr *);
struct question *question_dup(struct question *);
void		 pg_init(void);
void		 pg_publish_byiface(struct iface *);
struct pg	*pg_get(int, char [MAXHOSTNAMELEN], struct ctl_conn *);
void		 pg_kill(struct pg *);
int		 pg_published(struct pg *);
struct pge	*pge_from_ms(struct pg *, struct mdns_service *, struct iface *);
void		 pge_kill(struct pge *);
void		 pge_fsm(int, short, void *);
void		 pge_fsm_restart(struct pge *, struct timeval *);
struct pge 	*pge_new_primary(struct iface *);
struct pge 	*pge_new_workstation(struct iface *);
void		 pge_conflict_revert_probe(struct pge *);
void		 pge_conflict_drop(struct pge *);
struct rr *	 get_prim_a(struct iface *);
struct rr *	 auth_get(struct rr *);
void		 auth_release(struct rr *);
int		 rr_send_goodbye(struct rr *);
int		 rr_send_an(struct rr *);
void		 conflict_resolve_by_rr(struct rr *);

/* control.c */
TAILQ_HEAD(ctl_conns, ctl_conn) ctl_conns;
int     control_send_rr(struct ctl_conn *, struct rr *, int);
int	control_send_ms(struct ctl_conn *, struct mdns_service *, int);
int     control_try_answer_ms(struct ctl_conn *, char[MAXHOSTNAMELEN]);
int    	control_notify_pg(struct ctl_conn *, struct pg *, int);


#endif /* _MDNSD_H_ */
