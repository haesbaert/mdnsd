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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "mdnsd.h"
#include "log.h"

#define INTERVAL_PROBETIME	250000
#define RANDOM_PROBETIME	arc4random_uniform(250000)
#define FIRST_QUERYTIME		(arc4random_uniform(120000) + 20000)
#define MAX_QUERYTIME		(60 * 60) /* one hour */

struct query_node {
	RB_ENTRY(query_node)	entry;
	struct query		q;
};

int		 cache_insert(struct rr *);
int		 cache_delete(struct rr *);
void		 cache_schedrev(struct rr *);
void		 cache_rev(int, short, void *);
struct rrt_node *cache_lookup_node(struct rrset *);

void   		   query_fsm(int, short, void *);
int 		   query_node_cmp(struct query_node *, struct query_node *);
struct query_node *query_lookup_node(struct rrset *);

void		 rrt_dump(struct rrt_tree *);
int		 rrt_cmp(struct rrt_node *, struct rrt_node *);
struct rr	*rrt_lookup(struct rrt_tree *, struct rrset *);
struct rrt_node	*rrt_lookup_node(struct rrt_tree *, struct rrset *);

RB_GENERATE(rrt_tree,  rrt_node, entry, rrt_cmp);
RB_HEAD(query_tree, query_node);
RB_PROTOTYPE(query_tree, query_node, entry, query_node_cmp)
RB_GENERATE(query_tree, query_node, entry, query_node_cmp)

extern struct mdnsd_conf	*conf;
struct query_tree		 query_tree;
struct rrt_tree			 cache_tree;

/*
 * Publishing
 */

void
publish_init(void)
{
	struct iface	*iface;
	struct rr	*rr;
	char		 revaddr[MAXHOSTNAMELEN];

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
	struct question		*mq;
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
	strlcpy(mq->rrs.dname, conf->myname, sizeof(mq->rrs.dname));
	mq->rrs.type  = T_ANY;
	mq->rrs.class = C_IN;
	pub->pkt.h.qr = MDNS_QUERY;
	pkt_add_question(&pub->pkt, mq);

	RB_FOREACH(n, rrt_tree, &iface->rrt) {
		/* now go through all our rr and add to the same packet */
		LIST_FOREACH(rr, &n->hrr, centry) {
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

	log_debug("publish_delete: type: %s name: %s",
	    rr_type_name(rr->rrs.type), rr->rrs.dname);
	s = rrt_lookup_node(&iface->rrt, &rr->rrs);
	if (s == NULL)
		return (0);

	for (rraux = LIST_FIRST(&s->hrr); rraux != NULL; rraux = next) {
		next = LIST_NEXT(rraux, centry);
		if (RR_UNIQ(rr) || /* XXX: Revise this */
		    (rr_rdata_cmp(rr, rraux) == 0)) {
			LIST_REMOVE(rraux, centry);
			free(rraux);
			n++;
		}
	}

	if (LIST_EMPTY(&s->hrr)) {
		RB_REMOVE(rrt_tree, &iface->rrt, s);
		free(s);
	}

	return (n);
}

int
publish_insert(struct iface *iface, struct rr *rr)
{
	struct rrt_node *n;
	struct rr	*rraux;

	log_debug("publish_insert: type: %s name: %s",
	    rr_type_name(rr->rrs.type), rr->rrs.dname);

	n = rrt_lookup_node(&iface->rrt, &rr->rrs);
	if (n == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		n->rrs = rr->rrs;
		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, centry);
		if (RB_INSERT(rrt_tree, &iface->rrt, n) != NULL)
			fatal("rrt_insert: RB_INSERT");

		return (0);
	}

	/* if an unique record, clean all previous and substitute */
	if (RR_UNIQ(rr)) {
		while ((rraux = LIST_FIRST(&n->hrr)) != NULL) {
			LIST_REMOVE(rraux, centry);
			free(rraux);
		}
		LIST_INSERT_HEAD(&n->hrr, rr, centry);

		return (0);
	}

	/* not unique, just add */
	LIST_INSERT_HEAD(&n->hrr, rr, centry);

	return (0);
}

/* XXX: if query type is ANY, won't match. */
struct rr *
publish_lookupall(struct rrset *rrs)
{
	struct iface	*iface;
	struct rr	*rr;

	LIST_FOREACH(iface, &conf->iface_list, entry) {
		rr = rrt_lookup(&iface->rrt, rrs);
		if (rr != NULL)
			return (rr);
	}

	return (NULL);
}

void
publish_fsm(int unused, short event, void *v_pub)
{
	struct publish	*pub = v_pub;
	struct timeval	 tv;
	struct rr	*rr;
	struct question	*mq;
	static u_long	 pubid;
	
	timerclear(&tv);
	switch (pub->state) {
	case PUB_INITIAL:
		pub->state = PUB_PROBE;
		pub->id = ++pubid;
		/* FALLTHROUGH */
	case PUB_PROBE:
		pub->pkt.h.qr = MDNS_QUERY;
		if (pkt_send_allif(&pub->pkt) == -1)
			log_debug("can't send packet to all interfaces");
		pub->sent++;
		/* Send only the first 2 question as QU */
		if (pub->sent == 2)
			LIST_FOREACH(mq, &pub->pkt.qlist, entry)
				mq->src.s_addr = 0;
		/* enough probing, start announcing */
		else if (pub->sent == 3) { 
			/* cool, so now that we're done, remove it from
			 * probing list, now the record is ours. */
			pub->state    = PUB_ANNOUNCE;
			pub->sent     = 0;
			pub->pkt.h.qr = MDNS_RESPONSE;
			/* remove questions */
			while ((mq = (LIST_FIRST(&pub->pkt.qlist))) != NULL) {
				LIST_REMOVE(mq, entry);
				pub->pkt.h.qdcount--;
				free(mq);
			}
			/* move all ns records to answer records */
			while ((rr = (LIST_FIRST(&pub->pkt.nslist))) != NULL) {
				LIST_REMOVE(rr, pentry);
				pub->pkt.h.nscount--;
				if (pkt_add_anrr(&pub->pkt, rr) == -1)
					log_debug("publish_fsm: "
					    "pkt_add_anrr failed");
			}
			publish_fsm(unused, event, pub);
			return;
		}
		tv.tv_usec = INTERVAL_PROBETIME;
		evtimer_add(&pub->timer, &tv);
		break;
	case PUB_ANNOUNCE:
		if (pkt_send_allif(&pub->pkt) == -1)
			log_debug("can't send packet to all interfaces");
		pub->sent++;
		if (pub->sent < 3) {
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
			LIST_REMOVE(rr, pentry);
			pub->pkt.h.ancount--;
			free(rr);
		}
		while ((rr = LIST_FIRST(&pub->pkt.nslist)) != NULL) {
			LIST_REMOVE(rr, pentry);
			pub->pkt.h.nscount--;
			free(rr);
		}
		while ((rr = LIST_FIRST(&pub->pkt.arlist)) != NULL) {
			LIST_REMOVE(rr, pentry);
			pub->pkt.h.arcount--;
			free(rr);
		}
		while ((mq = LIST_FIRST(&pub->pkt.qlist)) != NULL) {
			LIST_REMOVE(mq, entry);
			pub->pkt.h.qdcount--;
			free(mq);
		}
		free(pub);
		break;
	default:
		fatalx("Unknown publish state, report this");
		break;
	}
}

/*
 * RR cache
 */

void
cache_init(void)
{
#ifdef DUMMY_ENTRIES
	char **nptr;
	struct rr *rr;
	char *tnames[] = {
		"teste1.local",
		"teste2.local",
		"teste3.local",
		"teste4.local",
		"teste5.local",
		"teste6.local",
		"teste7.local",
		"teste8.local",
		"teste9.local",
		"teste10.local",
		"teste11.local",
		"teste12.local",
		"teste13.local",
		"teste14.local",
		"teste15.local",
		"teste16.local",
		"teste17.local",
		"teste18.local",
		"teste19.local",
		"teste20.local",
		"teste21.local",
		"teste22.local",
		"teste23.local",
		"teste24.local",
		"teste25.local",
		"teste26.local",
		"teste27.local",
		"teste28.local",
		"teste29.local",
		"teste30.local",
		"teste31.local",
		"teste32.local",
		"teste33.local",
		"teste34.local",
		"teste35.local",
		"teste36.local",
		"teste37.local",
		"teste38.local",
		"teste39.local",
		"teste40.local",
		"teste41.local",
		"teste42.local",
		"teste43.local",
		"teste44.local",
		"teste45.local",
		"teste46.local",
		"teste47.local",
		"teste48.local",
		"teste49.local",
		"teste50.local",
		0
	};
#endif
	RB_INIT(&cache_tree);
#ifdef DUMMY_ENTRIES
	for (nptr = tnames; *nptr != NULL; nptr++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			err(1, "calloc");
		strlcpy(rr->dname, "_http._tcp.local", sizeof(rr->dname));
		rr->type = T_PTR;
		rr->class = C_IN;
		rr->ttl = 60;
		strlcpy(rr->rdata.PTR, *nptr, sizeof(rr->rdata.PTR));
		rr->rdlen = strlen(*nptr);
		evtimer_set(&rr->rev_timer, cache_rev, rr);
		cache_insert(rr);

	}

#endif

}

int
cache_process(struct rr *rr)
{
	evtimer_set(&rr->rev_timer, cache_rev, rr);
	if (clock_gettime(CLOCK_MONOTONIC, &rr->age) == -1)
		fatal("clock_gettime");
	/*
	 * If ttl is 0 this is a Goodbye RR. cache_delete() will look for all
	 * corresponding RR in our cache and remove/free them. This rr isn't in
	 * cache, therefore cache_delete() won't free it, this is the only
	 * special case when we call cache_delete() on a rr that isn't in *
	 * cache.
	 */
	
	/* TODO: schedule it for 1 second */
	if (rr->ttl == 0) {
		cache_delete(rr);
		free(rr);
		
		return (0);
	}
	
	if (cache_insert(rr) == -1)
		return (-1);

	return (0);
}

struct rr *
cache_lookup(struct rrset *rrs)
{
	return (rrt_lookup(&cache_tree, rrs));
}

struct rrt_node *
cache_lookup_node(struct rrset *rrs)
{
	return (rrt_lookup_node(&cache_tree, rrs));
}

int
cache_insert(struct rr *rr)
{
	struct rrt_node *n;
	struct rr	*rraux;

/* 	log_debug("cache_insert: type: %s name: %s", rr_type_name(rr->type), */
/* 	    rr->dname); */

	n = cache_lookup_node(&rr->rrs);
	if (n == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		
		n->rrs = rr->rrs;
		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, centry);
		if (RB_INSERT(rrt_tree, &cache_tree, n) != NULL)
			fatal("rrt_insert: RB_INSERT");
		cache_schedrev(rr);
		query_notify(rr, 1);

		return (0);
	}

	/* if an unique record, clean all previous and substitute */
	if (RR_UNIQ(rr)) {
		while ((rraux = LIST_FIRST(&n->hrr)) != NULL) {
			LIST_REMOVE(rraux, centry);
			if (evtimer_pending(&rraux->rev_timer, NULL))
				evtimer_del(&rraux->rev_timer);
			free(rraux);
		}
		LIST_INSERT_HEAD(&n->hrr, rr, centry);
		cache_schedrev(rr);
		query_notify(rr, 1);

		return (0);
	}

	/* rr is not unique, see if this is a cache refresh */
	LIST_FOREACH(rraux, &n->hrr, centry) {
		if (rr_rdata_cmp(rr, rraux) == 0) {
			rraux->ttl = rr->ttl;
			rraux->revision = 0;
			cache_schedrev(rraux);
			free(rr);

			return (0);
		}
	}

	/* not a refresh, so add */
	LIST_INSERT_HEAD(&n->hrr, rr, centry);
	query_notify(rr, 1);
	cache_schedrev(rr);
	/* XXX: should we cache_schedrev ? */

	return (0);
}

int
cache_delete(struct rr *rr)
{
	struct rr	*rraux, *next;
	struct rrt_node	*s;
	int		 n = 0;

	log_debug("cache_delete: type: %s name: %s", rr_type_name(rr->rrs.type),
	    rr->rrs.dname);
	query_notify(rr, 0);
	s = cache_lookup_node(&rr->rrs);
	if (s == NULL)
		return (0);

	for (rraux = LIST_FIRST(&s->hrr); rraux != NULL; rraux = next) {
		next = LIST_NEXT(rraux, centry);
		if (RR_UNIQ(rr) ||
		    (rr_rdata_cmp(rr, rraux) == 0)) {
			LIST_REMOVE(rraux, centry);
			if (evtimer_pending(&rraux->rev_timer, NULL))
				evtimer_del(&rraux->rev_timer);
			free(rraux);
			n++;
		}
	}

	if (LIST_EMPTY(&s->hrr)) {
		RB_REMOVE(rrt_tree, &cache_tree, s);
		free(s);
	}

	return (n);
}

void
cache_schedrev(struct rr *rr)
{
	struct timeval tv;
	u_int32_t var;

	timerclear(&tv);

	switch (rr->revision) {
	case 0:
		/* Expire at 80%-82% of ttl */
		var = 80 + arc4random_uniform(3);
		tv.tv_sec = ((10 * rr->ttl) * var) / 1000;
		break;
	case 1:
		/* Expire at 90%-92% of ttl */
		var = 90 + arc4random_uniform(3);
		tv.tv_sec  = ((10 * rr->ttl) * var) / 1000;
		tv.tv_sec -= ((10 * rr->ttl) * 80)  / 1000;
		break;
	case 2:
		/* Expire at 95%-97% of ttl */
		var = 95 + arc4random_uniform(3);
		tv.tv_sec  = ((10 * rr->ttl) * var) / 1000;
		tv.tv_sec -= ((10 * rr->ttl) * 90)  / 1000;
		break;
	case 3:	/* expired, delete from cache in 1 sec */
		tv.tv_sec = 1;
		break;
	}
/* 	log_debug("cache_schedrev: schedule rr type: %s, name: %s (%d)", */
/* 	    rr_type_name(rr->type), rr->dname, tv.tv_sec); */

	rr->revision++;

	if (evtimer_pending(&rr->rev_timer, NULL))
		evtimer_del(&rr->rev_timer);
	if (evtimer_add(&rr->rev_timer, &tv) == -1)
		fatal("rrt_sched_rev");
}

void
cache_rev(int unused, short event, void *v_rr)
{
	struct rr	*rr = v_rr;
	struct query	*q;
	struct pkt	 pkt;

/* 	log_debug("cache_rev: timeout rr type: %s, name: %s (%u)", */
/* 	    rr_type_name(rr->type), rr->dname, rr->ttl); */

	/* If we have an active query, try to renew the answer */
	if ((q = query_lookup(&rr->rrs)) != NULL) {
		pkt_init(&pkt);
		pkt.h.qr = MDNS_QUERY;
		pkt_add_question(&pkt, &q->mq);
		if (pkt_send_allif(&pkt) == -1)
			log_warnx("can't send packet to all interfaces");
	}

	if (rr->revision <= 3)
		cache_schedrev(rr);
	else
		cache_delete(rr);
}

/*
 * RR tree
 */

void
rrt_dump(struct rrt_tree *rrt)
{
	struct rr	*rr;
	struct rrt_node *n;

	log_debug("rrt_dump");
	RB_FOREACH(n, rrt_tree, rrt) {
		rr = LIST_FIRST(&n->hrr);
		LIST_FOREACH(rr, &n->hrr, centry)
		    log_debug_rr(rr);
	}
}

struct rr *
rrt_lookup(struct rrt_tree *rrt, struct rrset *rrs)
{
	struct rrt_node *tmp;
	
	tmp = rrt_lookup_node(rrt, rrs);
	if (tmp != NULL)
		return (LIST_FIRST(&tmp->hrr));
	
	return (NULL);
}

struct rrt_node *
rrt_lookup_node(struct rrt_tree *rrt, struct rrset *rrs)
{
	struct rrt_node s;
	
	bzero(&s, sizeof(s));
	s.rrs = *rrs;

	return (RB_FIND(rrt_tree, rrt, &s));
}

int
rrt_cmp(struct rrt_node *a, struct rrt_node *b)
{
	return (rrset_cmp(&a->rrs, &b->rrs));
}

int
rrset_cmp(struct rrset *a, struct rrset *b)
{
	if (a->class < b->class)
		return (-1);
	if (a->class > b->class)
		return (1);
	if (a->type < b->type)
		return (-1);
	if (a->type > b->type)
		return (1);

	return (strcmp(a->dname, b->dname));
}

/*
 * Querier
 */

void
query_init(void)
{
	RB_INIT(&query_tree);
}

struct query_node *
query_lookup_node(struct rrset *rrs)
{
	struct query_node qn;

	bzero(&qn, sizeof(qn));
	qn.q.mq.rrs = *rrs;
	return (RB_FIND(query_tree, &query_tree, &qn));
}

struct query *
query_lookup(struct rrset *rrs)
{
	struct query_node *qn;

	qn = query_lookup_node(rrs);
	if (qn != NULL)
		return (&qn->q);
	return (NULL);
}

struct query *
query_place(enum query_style s, struct rrset *rrs)
{
	struct query		*q;
	struct query_node	*qn;
	struct timeval		 tv;

	q = query_lookup(rrs);
	/* existing query, increase active */
	if (q != NULL) {
		if (s != q->style) {
			log_warnx("trying to change a query style");
			return (NULL);
		}
		q->active++;
		log_debug("existing query active = %d", q->active);
		return (q);
	}
	/* no query, make a new one */
	log_debug("making new query");
	if ((qn = calloc(1, sizeof(*qn))) == NULL)
		fatal("calloc");
	q = &qn->q;
	q->mq.rrs = *rrs;
	q->style = s;
	q->active++;
	if (RB_INSERT(query_tree, &query_tree, qn) != NULL)
		fatal("query_place: RB_INSERT");
	/* start the sending machine */
	timerclear(&tv);
	tv.tv_usec = FIRST_QUERYTIME;
	evtimer_set(&q->timer, query_fsm, q);
	evtimer_add(&q->timer, &tv);
	return (q);
}

void
query_remove(struct query *qrem)
{
	struct query *qfound;
	struct query_node *qn;

	qn = query_lookup_node(&qrem->mq.rrs);
	if (qn == NULL)
		return;
	qfound = &qn->q;
	if (--qfound->active == 0) {
		RB_REMOVE(query_tree, &query_tree, qn);
		if (evtimer_pending(&qn->q.timer, NULL))
			evtimer_del(&qn->q.timer);
		free(qn);
	}
}

/* RR in/out, 1 = in, 0 = out */
int
query_notify(struct rr *rr, int in)
{
	struct ctl_conn *c;
	struct query	*q;
	int		 tosee;
	int		 msgtype;

	q = query_lookup(&rr->rrs);
	if (q == NULL)
		return (0);
	/* try to answer the controllers */
	tosee = q->active;
	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (!tosee)
			break;
		if (!control_hasq(c, q))
			continue;
		/* sanity check */
		if (!ANSWERS(&q->mq, rr)) {
			log_warnx("Bogus pointer, report me");
			return (0);
		}
		/* notify controller */
		switch (q->style) {
		case QUERY_LKUP:
			msgtype = IMSG_CTL_LOOKUP;
			break;
		case QUERY_BROWSE:
			msgtype = in ? IMSG_CTL_BROWSE_ADD
			    : IMSG_CTL_BROWSE_DEL;
			break;
		default:
			log_warnx("Unknown query style");
			return (-1);
		}
		if (query_answerctl(c, rr, msgtype) == -1)
			log_warnx("Query_answerctl error");
	}

	/* number of notified controllers */
	return (q->active - tosee);
}

int
query_answerctl(struct ctl_conn *c, struct rr *rr, int msgtype)
{
	log_debug("query_answerctl (%s) %s", rr_type_name(rr->rrs.type),
	    rr->rrs.dname);
	switch (rr->rrs.type) {
	case T_A:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.A, sizeof(rr->rdata.A));
		break;
	case T_PTR:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.PTR, sizeof(rr->rdata.PTR));
		break;
	case T_HINFO:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.HINFO, sizeof(rr->rdata.HINFO));
		break;
	case T_SRV:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.SRV, sizeof(rr->rdata.SRV));
		break;
	case T_TXT:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.TXT, sizeof(rr->rdata.TXT));
		break;
	default:
		log_warnx("Unknown question type, report this");
		return (-1);
		break;		/* NOTREACHED */
	}

	return (0);
}

void
query_fsm(int unused, short event, void *v_query)
{
	struct pkt	 pkt;
	struct timeval	 tv;
	struct query	*q;
	struct rr	*rr;
	long		 tosleep;

	q = v_query;
	pkt_init(&pkt);
	pkt.h.qr = MDNS_QUERY;
	pkt_add_question(&pkt, &q->mq);

	if (q->style == QUERY_BROWSE) {
		/* This will send at seconds 0, 1, 2, 4, 8, 16... */
		if (q->sent == 0)
			tosleep = 1;
		else
			tosleep = (1 << (q->sent + 1)) - (1 << (q->sent));
		
		if (tosleep > MAX_QUERYTIME)
			tosleep = MAX_QUERYTIME;
		timerclear(&tv);
		tv.tv_sec = tosleep;
		evtimer_add(&q->timer, &tv);

		/* Known Answer Supression */
		for (rr = cache_lookup(&q->mq.rrs); rr != NULL;
		     rr = LIST_NEXT(rr, centry)) {
			/* Don't include packet if it's too old */
			if (rr_ttl_left(rr) < rr->ttl / 2)
				continue;
			if (pkt_add_anrr(&pkt, rr) == -1)
				log_warnx("KNA error pkt_add_anrr: %s",
				    rr->rrs.dname);
		}
	}

	if (pkt_send_allif(&pkt) == -1)
		log_warnx("can't send packet to all interfaces");
	q->sent++;
}

int
query_node_cmp(struct query_node *a, struct query_node *b)
{
	return (rrset_cmp(&a->q.mq.rrs, &b->q.mq.rrs));
}

