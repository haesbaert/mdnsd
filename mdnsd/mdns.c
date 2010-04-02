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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "mdnsd.h"
#include "log.h"

#define RANDOM_PROBETIME arc4random_uniform((u_int32_t) 250000)

static void		 publish_fsm(int, short, void *_pub);
static int		 cache_insert(struct rr *);
static int		 cache_delete(struct rr *);
static void		 cache_schedrev(struct rr *);
static void		 cache_rev(int, short, void *);
static int		 rrt_compare(struct rrt_node *, struct rrt_node *);
void			 rrt_dump(struct rrt_tree *);
static struct rr	*rrt_lookup(struct rrt_tree *, char [MAXHOSTNAMELEN],
    u_int16_t, u_int16_t);
static struct rr_head	*rrt_lookup_head(struct rrt_tree *,
    char [MAXHOSTNAMELEN],  u_int16_t, u_int16_t);
static struct rrt_node	*rrt_lookup_node(struct rrt_tree *, char [],
    u_int16_t, u_int16_t);

RB_GENERATE(rrt_tree,  rrt_node, entry, rrt_compare);
extern struct mdnsd_conf	*conf;
static struct rrt_tree		 rrt_cache;

/* TODO: Turn all the publishing types into functions */
/* Publishing */
void
publish_init(void)
{
	struct iface	*iface;
	struct rr	*rr;
	char		 revaddr[MAXHOSTNAMELEN];
	
	/* init publishing list used in name conflicts */
	LIST_INIT(&publishing_list);
	
	/* insert default records in all our interfaces */
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		/* myname */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		rr_set(rr, conf->myname, T_A, C_IN, TTL_HNAME, 1,
		    &iface->addr, sizeof(iface->addr));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");

		/* publish reverse address */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		reversstr(revaddr, &iface->addr);
		rr_set(rr, revaddr, T_PTR, C_IN, TTL_HNAME, 1,
		    conf->myname, sizeof(conf->myname));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");
		
		/* publish hinfo */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		rr_set(rr, conf->myname, T_HINFO, C_IN, TTL_HNAME, 1,
		    &conf->hi, sizeof(conf->hi));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");
 	}
}

void
publish_allrr(struct iface *iface)
{
	struct question	*mq;
	struct rr		*rr, *rrcopy;
	struct publish		*pub;
	struct rrt_node		*n;
	struct timeval		 tv;
	
	/* start a publish thingy */
	if ((pub = calloc(1, sizeof(*pub))) == NULL)
		fatal("calloc");
	pub->state = PUB_INITIAL;
	pkt_init(&pub->pkt);
	if ((mq = calloc(1, sizeof(*mq))) == NULL)
		fatal("calloc");
	question_set(mq, conf->myname, T_ANY, C_IN, 1, 1);
	pkt_add_question(&pub->pkt, mq);
	
	RB_FOREACH(n, rrt_tree, &iface->rrt) {
		/* now go through all our rr and add to the same packet */
		LIST_FOREACH(rr, &n->hrr, entry) {
			if ((rrcopy = calloc(1, sizeof(struct rr))) == NULL)
				fatal("calloc");
			memcpy(rrcopy, rr, sizeof(struct rr));
			pkt_add_nsrr(&pub->pkt, rrcopy);
		}
	}
	
	timerclear(&tv);
	tv.tv_usec = RANDOM_PROBETIME;
	evtimer_set(&pub->timer, publish_fsm, pub);
	evtimer_add(&pub->timer, &tv);
}

int
publish_delete(struct iface *iface, struct rr *rr)
{
	struct rr	*rraux, *next;
	struct rrt_node	*s;
	int		 n = 0;
	
	log_debug("publish_delete: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	s = rrt_lookup_node(&iface->rrt, rr->dname, rr->type, rr->class);
	if (s == NULL)
		return 0;
	
	for (rraux = LIST_FIRST(&s->hrr); rraux != NULL; rraux = next) {
		next = LIST_NEXT(rraux, entry);
		if (RR_UNIQ(rr) ||
		    (memcmp(&rr->rdata, &rraux->rdata,
		    rraux->rdlen) == 0)) {
			LIST_REMOVE(rraux, entry);
			free(rraux);
			n++;
		}
	}	
	
	if (LIST_EMPTY(&s->hrr)) {
		RB_REMOVE(rrt_tree, &iface->rrt, s);
		free(s);
	}
	
	return n;
}

int
publish_insert(struct iface *iface, struct rr *rr)
{
	struct rr_head	*hrr;
	struct rrt_node *n;
	struct rr	*rraux;
	
	log_debug("publish_insert: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	
	hrr = rrt_lookup_head(&iface->rrt, rr->dname, rr->type, rr->class);
	if (hrr == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		
		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, entry);
		if (RB_INSERT(rrt_tree, &iface->rrt, n) != NULL)
			fatal("rrt_insert: RB_INSERT");
		
		return 0;
	}
		
	/* if an unique record, clean all previous and substitute */
	if (RR_UNIQ(rr)) {
		while ((rraux = LIST_FIRST(hrr)) != NULL) {
			LIST_REMOVE(rraux, entry);
			free(rraux);
		}
		LIST_INSERT_HEAD(hrr, rr, entry);
		
		return 0;
	}
	
	/* not unique, just add */
	LIST_INSERT_HEAD(hrr, rr, entry);
	
	return 0;
}

struct rr *
publish_lookupall(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct iface	*iface;
	struct rr	*rr;
	
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		rr = rrt_lookup(&iface->rrt, dname, type, class);
		if (rr != NULL)
			return rr;
	}
	
	return NULL;
}

static void
publish_fsm(int unused, short event, void *v_pub)
{
	struct publish		*pub = v_pub;
	struct timeval		 tv;
	struct rr		*rr;
	struct question		*mq;
	static unsigned long	pubid;

	switch (pub->state) {
	case PUB_INITIAL:	
		pub->state = PUB_PROBE;
		pub->id = ++pubid;
		/* Register probing in our probing lists so we can deal with
		 * name conflicts */
		LIST_INSERT_HEAD(&publishing_list, pub, entry);
		/* FALLTHROUGH */
	case PUB_PROBE:
		pub->pkt.qr = 0;
		if (pkt_send_allif(&pub->pkt) == -1)
			log_debug("can't send packet to all interfaces");
		pub->sent++;
		if (pub->sent == 3) { /* enough probing, start announcing */
			/* cool, so now that we're done, remove it from
			 * publishing lists, now the record is ours. */
			LIST_REMOVE(pub, entry);
			pub->state  = PUB_ANNOUNCE;
			pub->sent   = 0;
			pub->pkt.qr = 1;
			/* remove questions */
			while ((mq = (LIST_FIRST(&pub->pkt.qlist))) != NULL) {
				LIST_REMOVE(mq, entry);
				pub->pkt.qdcount--;
				free(mq);
			}
			/* move all ns records to answer records */
			while ((rr = (LIST_FIRST(&pub->pkt.nslist))) != NULL) {
				LIST_REMOVE(rr, entry);
				pub->pkt.nscount--;
				if (pkt_add_anrr(&pub->pkt, rr) == -1)
					log_debug("publish_fsm: "
					    "pkt_add_anrr failed");
			}
			publish_fsm(unused, event, pub);
			return;
		}
		tv.tv_usec = RANDOM_PROBETIME;
		evtimer_add(&pub->timer, &tv);
		break;
	case PUB_ANNOUNCE:
		if (pkt_send_allif(&pub->pkt) == -1)
			log_debug("can't send packet to all interfaces");
		pub->sent++;
		if (pub->sent < 3) {
			timerclear(&tv);
			tv.tv_sec = pub->sent; /* increse delay linearly */
			evtimer_add(&pub->timer, &tv);
			return;
		}
		
		/* sent announcement three times, finish */
		pub->state = PUB_DONE;
		publish_fsm(unused, event, pub);
		break;
	case PUB_DONE:
		while ((rr = LIST_FIRST(&pub->pkt.anlist)) != NULL) {
			LIST_REMOVE(rr, entry);
			pub->pkt.ancount--;
			free(rr);
		}
		while ((rr = LIST_FIRST(&pub->pkt.nslist)) != NULL) {
			LIST_REMOVE(rr, entry);
			pub->pkt.nscount--;
			free(rr);
		}
		while ((rr = LIST_FIRST(&pub->pkt.arlist)) != NULL) {
			LIST_REMOVE(rr, entry);
			pub->pkt.arcount--;
			free(rr);
		}
		while ((mq = LIST_FIRST(&pub->pkt.qlist)) != NULL) {
			LIST_REMOVE(mq, entry);
			pub->pkt.qdcount--;
			free(mq);
		}
		free(pub);
		break;
	default:
		fatalx("Unknown publish state, report this");
		break;
	}
}

/* Querier */
void
query_init(void)
{
	LIST_INIT(&query_list);
}

struct query *
query_place(int type, struct question *mq, struct ctl_conn *c)
{
	struct query	*q;

	/* avoid having two equivalent questions */
	LIST_FOREACH(q, &query_list, entry)
	    if (QEQUIV(mq, q->mq)) {
		    LIST_INSERT_HEAD(&q->ctl_list, c, qentry);
		    return q;
	    }
	
	if ((q = calloc(1, sizeof(*q))) == NULL)
		fatal("calloc");
	
	LIST_INIT(&q->ctl_list);
	LIST_INSERT_HEAD(&q->ctl_list, c, qentry);
	q->type = type;
	q->mq	= mq;
	LIST_INSERT_HEAD(&query_list, q, entry);
	
	return q;
}

/* notify about this new rr to all interested peers */
int
query_notifyin(struct rr *rr)
{
	struct query	*q;
	struct ctl_conn *c;
	int		 match	   = 0;
	LIST_FOREACH(q, &query_list, entry) {
		if (!ANSWERS(q->mq, rr))
			continue;
		match++;
		switch (q->type) {
		case QUERY_LOOKUP:
			LIST_FOREACH(c, &q->ctl_list, qentry)
			    mdnsd_imsg_compose_ctl(c, IMSG_CTL_LOOKUP,
				&rr->rdata.A, sizeof(rr->rdata.A));
			break;
		case QUERY_LOOKUP_ADDR:
			LIST_FOREACH(c, &q->ctl_list, qentry)
			    mdnsd_imsg_compose_ctl(c, IMSG_CTL_LOOKUP_ADDR,
				&rr->rdata.PTR, sizeof(rr->rdata.PTR));
			break;
		case QUERY_LOOKUP_HINFO:
			LIST_FOREACH(c, &q->ctl_list, qentry)
			    mdnsd_imsg_compose_ctl(c, IMSG_CTL_LOOKUP_HINFO,
				&rr->rdata.HINFO, sizeof(rr->rdata.HINFO));
			break;
		case QUERY_BROWSING:
			rr->active = 1;
			/* TODO: fill me with love */
			break;
		default:
			log_warnx("Unknown query type, report this bug");
			break;
		}
	}
	
	return match;
}

int
query_notifyout(struct rr *rr)
{
	struct query	*q;
	int		 match = 0;
	
	LIST_FOREACH(q, &query_list, entry) {
		if (!ANSWERS(q->mq, rr))
			continue;
		match++;
		rr->active = 0;
		switch (q->type) {
		case QUERY_LOOKUP:
			/* nothing */
			break;
		case QUERY_LOOKUP_ADDR:
			/* nothing */
			break;
		case QUERY_BROWSING:
			/* TODO: fill me with love */
			break;
		default:
			log_warnx("Unknown query type, report this bug");
			break;
		}
	}
	
	return match;
}

void
query_cleanbyconn(struct ctl_conn *c)
{
	/* take ourselves out from the query */
	if (c->q == NULL)
		return;
	
	LIST_REMOVE(c, qentry);
	
	if (LIST_EMPTY(&c->q->ctl_list)) {
		LIST_REMOVE(c->q, entry);
		free(c->q->mq);
		free(c->q);
	}
}

/* RR cache */
void
cache_init(void)
{
	RB_INIT(&rrt_cache);
}

int
cache_process(struct rr *rr)
{

	evtimer_set(&rr->rev_timer, cache_rev, rr);
	if (rr->ttl == 0)
		return cache_delete(rr);
	if (cache_insert(rr) == -1)
		return -1;
	
	return 0;
}
	
struct rr *
cache_lookup(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	return rrt_lookup(&rrt_cache, dname, type, class);
}

static int
cache_insert(struct rr *rr)
{
	struct rr_head	*hrr;
	struct rrt_node *n;
	struct rr	*rraux;
	
	log_debug("cache_insert: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	
	hrr = rrt_lookup_head(&rrt_cache, rr->dname, rr->type, rr->class);
	if (hrr == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		
		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, entry);
		if (RB_INSERT(rrt_tree, &rrt_cache, n) != NULL)
			fatal("rrt_insert: RB_INSERT");
		cache_schedrev(rr);
		query_notifyin(rr);
		
		return 0;
	}
		
	/* if an unique record, clean all previous and substitute */
	if (RR_UNIQ(rr)) {
		while ((rraux = LIST_FIRST(hrr)) != NULL) {
			LIST_REMOVE(rraux, entry);
			if (evtimer_pending(&rraux->rev_timer, NULL))
				evtimer_del(&rraux->rev_timer);
			free(rraux);
		}
		LIST_INSERT_HEAD(hrr, rr, entry);
		cache_schedrev(rr);
		query_notifyin(rr);
		
		return 0;
	}
	
	/* rr is not unique, see if this is a cache refresh */
	LIST_FOREACH(rraux, hrr, entry) {
		if (memcmp(&rr->rdata, &rraux->rdata, rraux->rdlen) == 0) {
			rraux->ttl = rr->ttl;
			rraux->revision = 0;
			cache_schedrev(rraux);
			free(rr);
			
			return 0;
		}
	}
	
	/* not a refresh, so add */
	LIST_INSERT_HEAD(hrr, rr, entry);
	query_notifyin(rr);
	
	return 0;
}

static int
cache_delete(struct rr *rr)
{
	struct rr	*rraux, *next;
	struct rrt_node	*s;
	int		 n = 0;
	
	log_debug("cache_delete: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	s = rrt_lookup_node(&rrt_cache, rr->dname, rr->type, rr->class);
	if (s == NULL)
		return 0;
	
	for (rraux = LIST_FIRST(&s->hrr); rraux != NULL; rraux = next) {
		next = LIST_NEXT(rraux, entry);
		if (RR_UNIQ(rr) ||
		    (memcmp(&rr->rdata, &rraux->rdata,
		    rraux->rdlen) == 0)) {
			LIST_REMOVE(rraux, entry);
			if (evtimer_pending(&rraux->rev_timer, NULL))
				evtimer_del(&rraux->rev_timer);
			free(rraux);
			n++;
		}
	}

	if (LIST_EMPTY(&s->hrr)) {
		RB_REMOVE(rrt_tree, &rrt_cache, s);
		free(s);
	}
	
	return n;
}

static void
cache_schedrev(struct rr *rr)
{
	struct timeval tv;
	
	timerclear(&tv);
	
	switch (rr->revision) {
	case 0: 		
		tv.tv_sec = rr->ttl * 0.8;
		break;
	case 1:
		tv.tv_sec = rr->ttl - (rr->ttl * 0.9);
		break;
	case 2:
		tv.tv_sec = rr->ttl - (rr->ttl * 0.95);
		break;
	case 3:			/* expired, delete from cache in 1 sec */
		tv.tv_sec = 1;
		break;
	}
	
	log_debug("cache_schedrev: schedule rr type: %s, name: %s (%d)",
	    rr_type_name(rr->type), rr->dname, tv.tv_sec);

	rr->revision++;
	
	if (evtimer_add(&rr->rev_timer, &tv) == -1)
		fatal("rrt_sched_rev");
}

static void
cache_rev(int unused, short event, void *v_rr)
{
	struct rr *rr = v_rr;
	
	log_debug("cache_rev: timeout rr type: %s, name: %s (%u)",
	    rr_type_name(rr->type), rr->dname, rr->ttl);
	
/* 	if (rr->active && rr->revision <= 3) */
	if (rr->revision <= 3)
		cache_schedrev(rr);
	else
		cache_delete(rr);
/* 	rrt_dump(); */
}

/* RR tree */
void
rrt_dump(struct rrt_tree *rrt)
{
	struct rr	*rr;
	struct rrt_node *n;

	log_debug("rrt_dump");
	RB_FOREACH(n, rrt_tree, rrt) {
		rr = LIST_FIRST(&n->hrr);
		LIST_FOREACH(rr, &n->hrr, entry)
		    log_debug_rrdata(rr);
	}
}

static struct rr_head *
rrt_lookup_head(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN],
    u_int16_t type, u_int16_t class)
{
	struct rrt_node	*tmp;
	
	tmp = rrt_lookup_node(rrt, dname, type, class);
	if (tmp == NULL)
		return NULL;
	
	return &tmp->hrr;
}

static struct rr *
rrt_lookup(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rr_head	*hrr;
	
	hrr = rrt_lookup_head(rrt, dname, type, class);
	if (hrr)
		return LIST_FIRST(hrr);
	return NULL;
}

static struct rrt_node *
rrt_lookup_node(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rrt_node	s, *tmp;
	struct rr	rr;
	
	bzero(&s, sizeof(s));
	bzero(&rr, sizeof(rr));
	rr.type	 = type;
	rr.class = class;
	strlcpy(rr.dname, (const char *)dname, MAXHOSTNAMELEN);

	LIST_INIT(&s.hrr);
	LIST_INSERT_HEAD(&s.hrr, &rr, entry);
	
	tmp = RB_FIND(rrt_tree, rrt, &s);
	if (tmp == NULL)
		return NULL;
	
	return tmp;
}

static int
rrt_compare(struct rrt_node *a, struct rrt_node *b)
{
	struct rr *rra, *rrb;
	
	rra = LIST_FIRST(&a->hrr);
	rrb = LIST_FIRST(&b->hrr);
	
	if (rra->class < rrb->class)
		return -1;
	if (rra->class > rrb->class)
		return 1;
	if (rra->type < rrb->type)
		return -1;
	if (rra->type > rrb->type)
		return 1;
	
	return strcmp(rra->dname, rrb->dname);
}

