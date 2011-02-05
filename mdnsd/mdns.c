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

int		 cache_insert(struct rr *);
int		 cache_delete(struct rr *);
void		 cache_schedrev(struct rr *);
void		 cache_rev(int, short, void *);
struct rrt_node *cache_lookup_node(struct rrset *);

int 		 question_cmp(struct question *, struct question *);
struct question *question_lookup(struct rrset *);

void		 rrt_dump(struct rrt_tree *);
int		 rrt_cmp(struct rrt_node *, struct rrt_node *);
struct rr	*rrt_lookup(struct rrt_tree *, struct rrset *);
struct rrt_node	*rrt_lookup_node(struct rrt_tree *, struct rrset *);

RB_GENERATE(rrt_tree,  rrt_node, entry, rrt_cmp);
RB_HEAD(question_tree, question);
RB_PROTOTYPE(question_tree, question, qst_entry, question_cmp);
RB_GENERATE(question_tree, question, qst_entry, question_cmp);

extern struct mdnsd_conf	*conf;
struct question_tree		 question_tree;
struct rrt_tree			 cache_tree;

/*
 * RR cache
 */

void
cache_init(void)
{
	RB_INIT(&cache_tree);
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
	log_debug("cache_lookup %s", rrs_str(rrs));
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

	n = cache_lookup_node(&rr->rrs);
	/* New entry */
	if (n == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		
		n->rrs = rr->rrs;
		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, centry);
		if (RB_INSERT(rrt_tree, &cache_tree, n) != NULL)
			fatal("rrt_insert: RB_INSERT");
		cache_schedrev(rr);
		rr_notify_in(rr);

		log_debug("cache_insert: (new) type: %s name: %s",
		    rr_type_name(rr->rrs.type), rr->rrs.dname);
	
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
		rr_notify_in(rr);

		log_debug("cache_insert: (not new, unique) type: %s name: %s",
		    rr_type_name(rr->rrs.type), rr->rrs.dname);
		
		return (0);
	}

	/* rr is not unique, see if this is a cache refresh */
	LIST_FOREACH(rraux, &n->hrr, centry) {
		if (rr_rdata_cmp(rr, rraux) == 0) {
			rraux->ttl = rr->ttl;
			rraux->revision = 0;
			cache_schedrev(rraux);
			free(rr);
			log_debug("cache_insert: (cache refresh) "
			    "type: %s name: %s",
			    rr_type_name(rr->rrs.type), rr->rrs.dname);
			return (0);
		}
	}

	/* not a refresh, so add */
	LIST_INSERT_HEAD(&n->hrr, rr, centry);
	rr_notify_in(rr);
	/* XXX: should we cache_schedrev ? */
	cache_schedrev(rr);
	log_debug("cache_insert: (shared) type: %s name: %s",
	    rr_type_name(rr->rrs.type), rr->rrs.dname);


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
	rr_notify_out(rr);
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
	struct question	*qst;
	struct pkt	 pkt;

/* 	log_debug("cache_rev: timeout rr type: %s, name: %s (%u)", */
/* 	    rr_type_name(rr->type), rr->dname, rr->ttl); */

	/* If we have an active question, try to renew the answer */
	if ((qst = question_lookup(&rr->rrs)) != NULL) {
		pkt_init(&pkt);
		pkt.h.qr = MDNS_QUERY;
		pkt_add_question(&pkt, qst);
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
	RB_INIT(&question_tree);
}

struct question *
question_lookup(struct rrset *rrs)
{
	struct question qst;
	
	bzero(&qst, sizeof(qst));
	qst.rrs = *rrs;
	
	return (RB_FIND(question_tree, &question_tree, &qst));
}

struct question *
question_add(struct rrset *rrs)
{
	struct question *qst;

	qst = question_lookup(rrs);
	if (qst != NULL) {
		qst->active++;
		log_debug("existing question for %s (%s) active = %d",
		    rrs->dname, rr_type_name(rrs->type), qst->active);
		return (qst);
	}
	if ((qst = calloc(1, sizeof(*qst))) == NULL)
		fatal("calloc");
	qst->active++;
	qst->rrs = *rrs;
	if (RB_INSERT(question_tree, &question_tree, qst) != NULL)
		fatal("question_add: RB_INSERT");
	
	return (qst);
}

void
question_remove(struct rrset *rrs)
{
	struct question *qst;

	qst = question_lookup(rrs);
	if (qst == NULL) {
		log_warnx("trying to remove non existant question");
		return;
	}
	if (--qst->active == 0) {
		RB_REMOVE(question_tree, &question_tree, qst);
		free(qst);
	}
}

void
query_remove(struct query *q)
{
	struct rrset *rrs;
	
	LIST_REMOVE(q, entry);
	while ((rrs = LIST_FIRST(&q->rrslist)) != NULL) {
		question_remove(rrs);
		LIST_REMOVE(rrs, entry);
		log_debug("question_remove %s", rrs_str(rrs));
		free(rrs);
	}
	if (evtimer_pending(&q->timer, NULL))
		evtimer_del(&q->timer);
	free(q);
}

void
query_fsm(int unused, short event, void *v_query)
{
	struct pkt		 pkt;
	struct mdns_service	 nullms;
	struct query		*q;
	struct question		*qst;
	struct rr		*rraux, nullrr;
	struct rrset		*rrs;
	struct timespec		 tnow;
	struct timeval		 tv;
	time_t			 tosleep;

	q = v_query;
	pkt_init(&pkt);
	pkt.h.qr = MDNS_QUERY;
	
	/* This will send at seconds 0, 1, 2, 4, 8, 16... */
	tosleep = (2 << q->count) - (1 << q->count);
	if (tosleep > MAXQUERYTIME)
		tosleep = MAXQUERYTIME;
	timerclear(&tv);
	tv.tv_sec = tosleep;

	if (clock_gettime(CLOCK_MONOTONIC, &tnow) == -1)
		fatal("clock_gettime");
	
	log_debug("query_fsm");
	
	/*
	 * If we're in our third call and we're still alive,
	 * consider a failure.
	 */
	if (q->style == QUERY_LOOKUP && q->count == 2) {
		rrs = LIST_FIRST(&q->rrslist);
		bzero(&nullrr, sizeof(nullrr));
		nullrr.rrs = *rrs;
		control_send_rr(q->ctl, &nullrr, IMSG_CTL_LOOKUP_FAILURE);
		query_remove(q);
		return;
	}
	
	if (q->style == QUERY_RESOLVE && q->count == 3) {
		log_debug("query_resolve failed");
		bzero(&nullms, sizeof(nullms));
		strlcpy(nullms.name, q->ms_srv->dname, sizeof(nullms.name));
		control_send_ms(q->ctl, &nullms, IMSG_CTL_RESOLVE_FAILURE);
		query_remove(q);
		return;
	}

	LIST_FOREACH(rrs, &q->rrslist, entry) {
		if (q->style == QUERY_RESOLVE && cache_lookup(rrs)) {
			log_debug("question for %s supressed, have answer",
			    rrs_str(rrs));
			continue;
		}
		if ((qst = question_lookup(rrs)) == NULL) {
			log_warnx("Can't find question in query_fsm for %s",
			    rrs_str(rrs));
			/* XXX: we leak memory */
			return;
		}
		
		/* Can't send question before schedule */
		if (timespeccmp(&tnow, &qst->sched, <)) {
			log_debug("question for %s before schedule",
			    rrs_str(rrs));
			continue;
		}
		
		pkt_add_question(&pkt, qst);
		qst->sent++;
		qst->lastsent = tnow;
		qst->sched = tnow;
		qst->sched.tv_sec += tosleep;
		if (q->style == QUERY_BROWSE) {
			/* Known Answer Supression */
			for (rraux = cache_lookup(rrs);
			     rraux != NULL;
			     rraux = LIST_NEXT(rraux, centry)) {
				/* Don't include rr if it's too old */
				if (rr_ttl_left(rraux) < rraux->ttl / 2)
					continue;
				pkt_add_anrr(&pkt, rraux);
			}
		}
	}

	if (pkt.h.qdcount > 0)
		if (pkt_send_allif(&pkt) == -1)
			log_warnx("can't send packet to all interfaces");
	q->count++;
	if (evtimer_pending(&q->timer, NULL))
		evtimer_del(&q->timer);
	evtimer_add(&q->timer, &tv);
}

int
question_cmp(struct question *a, struct question *b)
{
	return (rrset_cmp(&a->rrs, &b->rrs));
}

struct question *
question_dup(struct question *qst)
{
	struct question *qdup;

	if ((qdup = malloc(sizeof(*qdup))) == NULL)
		fatal("malloc");
	memcpy(qdup, qst, sizeof(*qdup));
	
	return (qdup);
}

int
rr_notify_in(struct rr *rr)
{
	struct ctl_conn		*c;
	struct query		*q, *nq;
	struct question		*qst;
	struct rrset		*rrs;
	int			 query_done;
	
	if ((qst = question_lookup(&rr->rrs)) == NULL)
		return (0);
	
	TAILQ_FOREACH(c, &ctl_conns, entry) {
		for (q = LIST_FIRST(&c->qlist); q != NULL; q = nq) {
			nq = LIST_NEXT(q, entry);
			query_done = 0;
			LIST_FOREACH(rrs, &q->rrslist, entry) {
				
				if (rrset_cmp(rrs, &rr->rrs) != 0)
					continue;
				/*
				 * Notify controller with full RR.
				 */
				switch (q->style) {
				case QUERY_LOOKUP:
					if (control_send_rr(c, rr,
					    IMSG_CTL_LOOKUP) == -1)
					query_remove(q);
					query_done = 1;
					break;
				case QUERY_BROWSE:
					if (control_send_rr(c, rr,
					    IMSG_CTL_BROWSE_ADD) == -1)
						log_warnx("control_send_rr error");
					break;
				case QUERY_RESOLVE:
					if (control_try_answer_ms(c,
					    q->ms_srv->dname) == 1) {
						query_remove(q);
						query_done = 1;
					}
					break;
				default:
					log_warnx("Unknown query style");
					return (-1);
				}
				
				if (query_done)
					break;
			}
		}
	}
	
	return (0);
}

int
rr_notify_out(struct rr *rr)
{
	struct ctl_conn *c;
	struct query	*q;
	struct question *qst;
	struct rrset	*rrs;

	if ((qst = question_lookup(&rr->rrs)) == NULL)
		return (0);
	
	TAILQ_FOREACH(c, &ctl_conns, entry) {
		LIST_FOREACH(q, &c->qlist, entry) {
			if (q->style != QUERY_BROWSE)
				continue;
			LIST_FOREACH(rrs, &q->rrslist, entry) {
				if (rrset_cmp(rrs, &rr->rrs) != 0)
					continue;
				/*
				 * Notify controller with full RR.
				 */
				if (control_send_rr(c, rr, IMSG_CTL_BROWSE_DEL)
				    == -1)
					log_warnx("control_send_rr error");
			}
		}
	}

	return (0);
}

/*
 * This function is crap crap crap.
 */
struct pge *
pge_from_ms(struct pg *pg, struct mdns_service *ms, struct iface *iface)
{
	struct pge	*pge;
	struct rr	*srv, *txt, *rr, *ptr_proto, *ptr_services;
	struct question *qst;
	struct pge_if	*pge_if;
	struct iface	*ifaux = NULL;
	char		 servname[MAXHOSTNAMELEN], proto[MAXHOSTNAMELEN];
	
	srv = txt = rr = ptr_proto = ptr_services = NULL;
	qst = NULL;
	
	if (snprintf(servname, sizeof(servname),
	    "%s._%s._%s.local",  ms->name, ms->app, ms->proto)
	    >= (int)sizeof(servname)) {
		log_warnx("pge_from_ms: name too long");
		return (NULL);
	}
	if (snprintf(proto, sizeof(proto),
	    "_%s._%s.local",  ms->app, ms->proto)
	    >= (int)sizeof(proto)) {
		log_warnx("pge_from_ms: proto too long");
		return (NULL);
	}
	/* Alloc and init pge structure */
	if ((pge = calloc(1, sizeof(*pge))) == NULL)
		fatal("calloc");
	pge->pg		= pg;
	pge->pge_type   = PGE_TYPE_SERVICE;
	pge->pge_flags |= PGE_FLAG_INC_A;
	LIST_INIT(&pge->pge_if_list);
	
	/* T_SRV */
	if ((srv = calloc(1, sizeof(*srv))) == NULL)
		fatal("calloc");
	(void)strlcpy(srv->rdata.SRV.target, conf->myname,
	    sizeof(srv->rdata.SRV.target));
	srv->rdata.SRV.priority = ms->priority;
	srv->rdata.SRV.weight = ms->weight;
	srv->rdata.SRV.port = ms->port;
	(void)rr_set(srv, servname, T_SRV, C_IN, TTL_SRV, 1,
	    &srv->rdata, sizeof(srv->rdata));
	(void)strlcpy(srv->rdata.SRV.target, ms->target,
	    sizeof(srv->rdata.SRV.target));
	/* Question */
	if ((qst = calloc(1, sizeof(*qst))) == NULL)
		fatal("calloc");
	qst->rrs.type  = T_ANY;
	qst->rrs.class = C_IN;
	(void)strlcpy(qst->rrs.dname, srv->rrs.dname,
	    sizeof(qst->rrs.dname));
	/* T_TXT */
	if ((txt = calloc(1, sizeof(*txt))) == NULL)
		fatal("calloc");
	(void)rr_set(txt, servname, T_TXT, C_IN, TTL_TXT, 1,
	    ms->txt, sizeof(ms->txt));
	/* T_PTR proto */
	if ((ptr_proto = calloc(1, sizeof(*ptr_proto))) == NULL)
		fatal("calloc");
	(void)rr_set(ptr_proto, proto, T_PTR, C_IN, TTL_PTR,
	    0, servname, sizeof(servname));
	/* T_PTR services */
	if ((ptr_services = calloc(1, sizeof(*ptr_services))) == NULL)
		fatal("calloc");
	(void)rr_set(ptr_services, "_services._dns-sd._udp.local",
	    T_PTR, C_IN, TTL_PTR, 0, proto, sizeof(proto));
	
	/* Check for conflicts */
	if (pg_rr_in_conflict(srv)		||
	    pg_rr_in_conflict(txt)		||
	    pg_rr_in_conflict(ptr_proto)	||
	    pg_rr_in_conflict(ptr_services)) {
		log_warnx("Conflict for rr %s", rrs_str(&rr->rrs));
		LIST_REMOVE(srv, gentry);
		LIST_REMOVE(txt, gentry);
		LIST_REMOVE(ptr_proto, gentry);
		LIST_REMOVE(ptr_services, gentry);
		free(srv);
		free(txt);
		free(ptr_proto);
		free(ptr_services);
		free(qst);
		free(pge);
	}
	
	/*
	 * If iface is NULL, alloc one fsm for each iface, otherwise only one
	 * for the selected interface, bail out the loop.
	 */
	/*
	 * We need this goto since conf->iface_list may not yet have the iface,
	 * this happens if this function gets called in if_new()
	 */
	if (iface != NULL)
		goto dontloop;
	LIST_FOREACH(ifaux, &conf->iface_list, entry) {
	dontloop:
		if (iface != NULL)
			ifaux = iface;
		if ((pge_if = calloc(1, sizeof(*pge_if))) == NULL)
			err(1, "calloc");
		LIST_INIT(&pge_if->rr_list);
		pge_if->pge	 = pge;
		pge_if->iface	 = ifaux;
		pge_if->if_state = PGE_IF_STA_UNPUBLISHED;
		evtimer_set(&pge_if->if_timer, pge_if_fsm,
		    pge_if);
		LIST_INSERT_HEAD(&pge->pge_if_list, pge_if, entry);
		/* Add the Question and the Resource Records */
		pge_if->pqst = qst;
		LIST_INSERT_HEAD(&pge_if->rr_list, srv, gentry);
		LIST_INSERT_HEAD(&pge_if->rr_list, txt, gentry);
		LIST_INSERT_HEAD(&pge_if->rr_list, ptr_proto, gentry);
		LIST_INSERT_HEAD(&pge_if->rr_list, ptr_services, gentry);
		
		if (iface != NULL || LIST_NEXT(ifaux, entry) == NULL)
			break;
		
		/*
		 * Each pge_if must hold a copy of every RR, we use rr_dup() and
		 * question_dup() so the next loop iteration will end up adding
		 * the copies.
		 */
		qst	     = question_dup(qst);
		srv	     = rr_dup(srv);
		txt	     = rr_dup(txt);
		ptr_proto    = rr_dup(ptr_proto);
		ptr_services = rr_dup(ptr_services);
	}

	/*
	 * If we got here, all is fine and we can link pge
	 */
	TAILQ_INSERT_TAIL(&pge_queue, pge, entry);
	LIST_INSERT_HEAD(&pg->pge_list, pge, pge_entry);
	
	return (pge);
}

void
pge_if_fsm_restart(struct pge_if *pge_if, struct timeval *tv)
{
	if (evtimer_pending(&pge_if->if_timer, NULL))
		evtimer_del(&pge_if->if_timer);
	evtimer_add(&pge_if->if_timer, tv);
}

void
pge_if_fsm(int unused, short event, void *v_pge_if)
{
	struct pg	*pg,  *pg_primary;
	struct pge	*pge, *pge_primary;
	struct pge_if	*pge_if, *pge_if_primary;
	struct rr	*rr;
	struct iface	*iface;
	struct timeval	 tv;
	struct pkt	 pkt;
	
	pge_if	       = v_pge_if;
	pge	       = pge_if->pge;
	pg	       = pge->pg;
	iface	       = pge_if->iface;
	pg_primary     = iface->pg_primary;
	pge_primary    = LIST_FIRST(&pg_primary->pge_list);
	pge_if_primary = LIST_FIRST(&pge_primary->pge_if_list);
	/*
	 * In order to publish services and addresses we must first make sure
	 * our primary address has been sucessfully published, if not, we delay
	 * publication for a second.
	 */
	if (pge->pge_type == PGE_TYPE_SERVICE &&
	    pge_if_primary->if_state < PGE_IF_STA_ANNOUNCING) {
		timerclear(&tv);
		tv.tv_sec = 1;
		pge_if_fsm_restart(pge_if, &tv);
		return;
	}
		
	switch (pge_if->if_state){
	case PGE_IF_STA_UNPUBLISHED:
		pge_if->if_state = PGE_IF_STA_PROBING;
		/* FALLTHROUGH */
	case PGE_IF_STA_PROBING:
		if ((pg->flags & PG_FLAG_INTERNAL) == 0 &&
		    pge_if->if_sent == 0)
			control_notify_pg(pg->c, pg,
			    IMSG_CTL_GROUP_PROBING);
		/* Build up our probe packet */
		pkt_init(&pkt);
		pkt.h.qr = MDNS_QUERY;
		if (pge_if->pqst != NULL) {
			/* Unicast question ? */
			if (pge_if->if_sent >= 2)
				pge_if->pqst->src.s_addr = 1;
			else
				pge_if->pqst->src.s_addr = 0;
			pkt_add_question(&pkt, pge_if->pqst);
		}
		/* Add the RRs in the ns section */
		LIST_FOREACH(rr, &pge_if->rr_list, gentry)
			pkt_add_nsrr(&pkt, rr);
		if (pkt_send_if(&pkt, iface) == -1)
			log_warnx("can't send probe packet "
			    "to iface %s", iface->name);
		/* Probing done, start announcing */
		if (++pge_if->if_sent == 3) {
			/* if_sent is re-used by PGE_IF_STA_ANNOUNCING */
			pge_if->if_sent	 = 0;
			pge_if->if_state = PGE_IF_STA_ANNOUNCING;
			/*
			 * Link to published resource records
			 */
			LIST_FOREACH(rr, &pge_if->rr_list, gentry) {
				LIST_INSERT_HEAD(&iface->auth_rr_list, rr,
				    centry);
			}
		}
		timerclear(&tv);
		tv.tv_usec = INTERVAL_PROBETIME;
		pge_if_fsm_restart(pge_if, &tv);
		break;
	case PGE_IF_STA_ANNOUNCING:
		if ((pg->flags & PG_FLAG_INTERNAL) == 0 &&
		    pge_if->if_sent == 0)
			control_notify_pg(pg->c, pg,
			    IMSG_CTL_GROUP_ANNOUNCING);
		/* Build up our announcing packet */
		pkt_init(&pkt);
		pkt.h.qr = MDNS_RESPONSE;
		/* Add the RRs in the AN secion */
		LIST_FOREACH(rr, &pge_if->rr_list, gentry)
	        	pkt_add_anrr(&pkt, rr);
		/*
		 * PGE_FLAG_INC_A, we should add our primary A resource record
		 * to the packet. We must look for the A record on our primary
		 */
		if (pge->pge_flags & PGE_FLAG_INC_A) {
			LIST_FOREACH(rr, &pge_if_primary->rr_list, gentry) {
				if (rr->rrs.type != T_A)
					continue;
				pkt_add_anrr(&pkt, rr);
				break;
			}
			if (rr == NULL)
				log_warnx("pge_if_fsm: T_A not found for "
				    "primary group. Not including T_A !");
		}
		if (pkt_send_if(&pkt, iface) == -1)
			log_warnx("can't send probe packet "
			    "to iface %s", iface->name);
		if (++pge_if->if_sent < 3)  {
			tv.tv_sec = pge_if->if_sent;
			pge_if_fsm_restart(pge_if, &tv);
			break;
		}
		pge_if->if_state = PGE_IF_STA_PUBLISHED;
		/* FALLTHROUGH */
	case PGE_IF_STA_PUBLISHED:
		log_debug("group %s published on iface %s",
		    pg->name, iface->name);
		/*
		 * Check if every pge_if in every pge is published, if it is
		 * we'll consider the group as published, notify controller
		 */
		if ((pg->flags & PG_FLAG_INTERNAL) == 0 &&
		    pg_published(pg))
			control_notify_pg(pg->c, pg, IMSG_CTL_GROUP_PUBLISHED);
		break;
	default:
		fatalx("invalid group state");
	}
}

/*
 * MDNS draft section 10.2
 */
void
pge_if_send_goodbye(struct pge_if *pge_if)
{
	struct pkt pkt;
	struct rr *rr;

	pkt_init(&pkt);
	pkt.h.qr = MDNS_RESPONSE;
	LIST_FOREACH(rr, &pge_if->rr_list, gentry) {
		rr->ttl = 0;
		pkt_add_anrr(&pkt, rr);
	}

	if (pkt_send_if(&pkt, pge_if->iface) == -1)
		log_warnx("can't send goodbye packet "
		    "to iface %s", pge_if->iface->name);
}

void
pge_kill(struct pge *pge)
{
	struct rr	*rr;
	struct pge_if	*pge_if;
	struct pg	*pg;

	pg = pge->pg;
	/*
	 * Cleanup pge_if
	 */
	while ((pge_if = LIST_FIRST(&pge->pge_if_list)) != NULL) {
		/* Stop pge_if machine */
		if (evtimer_pending(&pge_if->if_timer, NULL))
			evtimer_del(&pge_if->if_timer);
		/*
		 * If we've reached at least PGE_IF_STA_ANNOUNCING, send
		 * a goodbye RR.
		 */
		if (pge_if->if_state >= PGE_IF_STA_ANNOUNCING)
			pge_if_send_goodbye(pge_if);

		/* Free Resource Records */
		while ((rr = LIST_FIRST(&pge_if->rr_list)) != NULL) {
			LIST_REMOVE(rr, gentry);
			/*
			 * If we've reached at least PGE_IF_STA_ANNOUNCING,
			 * this is a published RR and is linked in auth_rr_list.
			 * Also notify any interested controller that this
			 * service has been unpublished.
			 */
			if (pge_if->if_state >= PGE_IF_STA_ANNOUNCING) {
				rr_notify_out(rr);
				LIST_REMOVE(rr, centry);
			}
			free(rr);
		}
		LIST_REMOVE(pge_if, entry);
		log_debug("group %s unpublished on iface %s",
		    pg->name, pge_if->iface->name);
		free(pge_if);
	}
	/*
	 * Unlink pge
	 */
	TAILQ_REMOVE(&pge_queue, pge, entry);
	LIST_REMOVE(pge, pge_entry);
	free(pge);
}

void
pg_init(void)
{
	TAILQ_INIT(&pg_queue);
	TAILQ_INIT(&pge_queue);
}

void
pg_publish_byiface(struct iface *iface)
{
	struct pge	*pge;
	struct pge_if	*pge_if;
	struct timeval	 tv;
	
	timerclear(&tv);
	tv.tv_usec = RANDOM_PROBETIME;

	TAILQ_FOREACH(pge, &pge_queue, entry) {
		LIST_FOREACH(pge_if, &pge->pge_if_list, entry) {
			if (pge_if->iface != iface)
				continue;
			pge_if_fsm_restart(pge_if, &tv);
		}
	}
}

struct pg *
pg_get(int alloc, char name[MAXHOSTNAMELEN], struct ctl_conn *c)
{
	struct pg *pg;
	
	TAILQ_FOREACH(pg, &pg_queue, entry) {
		if (pg->c == c && strcmp(pg->name, name) == 0)
			return (pg);
	}
	
	if (!alloc)
		return (NULL);
	if ((pg = calloc(1, sizeof(*pg))) == NULL)
		err(1, "calloc");
	(void)strlcpy(pg->name, name, sizeof(pg->name));
	pg->c	  = c;
	pg->flags = 0;
	LIST_INIT(&pg->pge_list);
	TAILQ_INSERT_TAIL(&pg_queue, pg, entry);
	
	return (pg);
}

struct pg *
pg_new_primary(struct iface *iface)
{
	struct pg	*pg;
	struct pge	*pge;
	struct pge_if	*pge_if;
	struct question	*qst;
	struct rr	*rr;
	char		 revaddr[MAXHOSTNAMELEN];
	
	/* Alloc a new internal group */
	if ((pg = calloc(1, sizeof(*pg))) == NULL)
		fatal("calloc");
	if (snprintf(pg->name, sizeof(pg->name), "%s_primary", iface->name) >=
	    (int)sizeof(pg->name))
		log_warnx("Interface name %s too long", iface->name);
	pg->flags = PG_FLAG_INTERNAL;
	pg->c	  = NULL;	/* No controller for internal pgs */
	LIST_INIT(&pg->pge_list);
	TAILQ_INSERT_TAIL(&pg_queue, pg, entry);
	/* Alloc one single group entry */
	if ((pge = calloc(1, sizeof(*pge))) == NULL)
		fatal("calloc");
	pge->pge_flags = 0;
	pge->pg	       = pg;
	LIST_INIT(&pge->pge_if_list);
	/* Double linked */
	LIST_INSERT_HEAD(&pg->pge_list, pge, pge_entry);
	TAILQ_INSERT_TAIL(&pge_queue, pge, entry);
	/* Get a pge_if for this interface */
	if ((pge_if = calloc(1, sizeof(*pge_if))) == NULL)
		fatal("calloc");
	LIST_INIT(&pge_if->rr_list);
	pge_if->pge	 = pge;
	pge_if->iface	 = iface;
	pge_if->if_sent	 = 0;
	pge_if->if_state = PGE_IF_STA_UNPUBLISHED;
	evtimer_set(&pge_if->if_timer, pge_if_fsm, pge_if);
	LIST_INSERT_HEAD(&pge->pge_if_list, pge_if, entry);
	/* Set up primary question */
	if ((qst = calloc(1, sizeof(*qst))) == NULL)
		fatal("calloc");
	(void)strlcpy(qst->rrs.dname, conf->myname, sizeof(qst->rrs.dname));
	qst->rrs.type  = T_ANY;
	qst->rrs.class = C_IN;
	pge_if->pqst = qst;
	/* Must add T_A, T_PTR(rev) and T_HINFO */
	/* T_A record */
	if ((rr = calloc(1, sizeof(*rr))) == NULL)
		fatal("calloc");
	rr_set(rr, conf->myname, T_A, C_IN, TTL_HNAME, 1,
	    &iface->addr, sizeof(iface->addr));
	LIST_INSERT_HEAD(&pge_if->rr_list, rr, gentry);
	/* T_PTR record reverse address */
	if ((rr = calloc(1, sizeof(*rr))) == NULL)
		fatal("calloc");
	reversstr(revaddr, &iface->addr);
	rr_set(rr, revaddr, T_PTR, C_IN, TTL_HNAME, 1,
	    conf->myname, sizeof(conf->myname));
	LIST_INSERT_HEAD(&pge_if->rr_list, rr, gentry);
	/* T_HINFO record */
	if ((rr = calloc(1, sizeof(*rr))) == NULL)
		fatal("calloc");
	rr_set(rr, conf->myname, T_HINFO, C_IN, TTL_HNAME, 1,
	    &conf->hi, sizeof(conf->hi));
	LIST_INSERT_HEAD(&pge_if->rr_list, rr, gentry);
	
	return (pg);
}

struct pg *
pg_new_workstation(struct iface *iface)
{
	struct mdns_service	 ms;
	struct pg		*pg;
	
	/* Alloc a new internal group */
	if ((pg = calloc(1, sizeof(*pg))) == NULL)
		fatal("calloc");
	/* TODO turn this into a function, same as pg_new_primary() */
	if (snprintf(pg->name, sizeof(pg->name), "%s_workstation", iface->name)
	    >= (int)sizeof(pg->name))
		errx(1, "workstation name too big");
	pg->flags = PG_FLAG_INTERNAL;
	pg->c	  = NULL;	/* No controller for internal pgs */
	LIST_INIT(&pg->pge_list);
	TAILQ_INSERT_TAIL(&pg_queue, pg, entry);
	/* Build our service */
	bzero(&ms, sizeof(ms));
	ms.port = 9;	/* workstation stuff */
	strlcpy(ms.app, "Workstation", sizeof(ms.app));
	strlcpy(ms.proto, "tcp", sizeof(ms.app));
	if (snprintf(ms.name, sizeof(ms.name),
	    "%s [%s:%s]", conf->myname, iface->name,
	    ether_ntoa(&iface->ea)) >= (int)sizeof(ms.name))
		log_warnx("Workstation name too long");
	strlcpy(ms.target, conf->myname, sizeof(ms.target));
	/* Will link pge in pg */
	pge_from_ms(pg, &ms, iface);
	
	return (pg);
}

/*
 * Reset/Cleanup/Unpublish a group.
 */
void
pg_kill(struct pg *pg)
{
	struct pge *pge;

	while ((pge = LIST_FIRST(&pg->pge_list)) != NULL)
		pge_kill(pge);
		
	TAILQ_REMOVE(&pg_queue, pg, entry);
	free(pg);
}

/*
 * True if group is published
 */
int
pg_published(struct pg *pg)
{
	struct pge	*pge;
	struct pge_if	*pge_if;
	
	LIST_FOREACH(pge, &pg->pge_list, pge_entry) {
		LIST_FOREACH(pge_if, &pge->pge_if_list, entry) {
			if (pge_if->if_state != PGE_IF_STA_PUBLISHED)
				return (0);
		}
	}
	
	return (1);
}

int
pg_rr_in_conflict(struct rr *rr)
{
	struct pge	*pge;
	struct pge_if	*pge_if;
	struct rr	*rraux;
	/* Conflicts only in unique records */
	if (!RR_UNIQ(rr))
		return (0);
	
	TAILQ_FOREACH(pge, &pge_queue, entry) {
		LIST_FOREACH(pge_if, &pge->pge_if_list, entry) {
			LIST_FOREACH(rraux, &pge_if->rr_list, gentry) {
				if (!RR_UNIQ(rraux))
					continue;
				if (rrset_cmp(&rr->rrs, &rraux->rrs) == 0) {
					log_warnx("pg_rr_in_conflict %s",
					    rrs_str(&rr->rrs));
					    return (1);
				}
			}
		}
	}
	
	return (0);
}

/*
 * Check if we have a RR that answers the given question.
 */
struct rr *
auth_lookup_rr(struct iface *iface, struct rrset *qrrs)
{
	struct rr *rr;
	struct iface *ifaux;

	LIST_FOREACH(ifaux, &conf->iface_list, entry) {
		if (iface != NULL)
			ifaux = iface;
		LIST_FOREACH(rr, &ifaux->auth_rr_list, centry) {
			if (ANSWERS(qrrs, &rr->rrs))
				return (rr);
		}
		if (iface != NULL)
			break;
	}
	
	return (NULL);
}

