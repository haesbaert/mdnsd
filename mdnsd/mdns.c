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

int		 question_cmp(struct question *, struct question *);
struct question *question_lookup(struct rrset *);

RB_HEAD(cache_tree, cache_node) cache_tree;
RB_PROTOTYPE(cache_tree, cache_node, entry, cache_node_cmp);
RB_GENERATE(cache_tree, cache_node, entry, cache_node_cmp);

RB_HEAD(question_tree, question);
RB_PROTOTYPE(question_tree, question, qst_entry, question_cmp);
RB_GENERATE(question_tree, question, qst_entry, question_cmp);

extern struct mdnsd_conf	*conf;
struct question_tree		 question_tree;
struct cache_tree		 cache_tree;

/*
 * RR cache
 */

void
cache_init(void)
{
	RB_INIT(&cache_tree);
}

int
cache_node_cmp(struct cache_node *a, struct cache_node *b)
{
	return (strcmp(a->dname, b->dname));
}

struct rr *
cache_next_by_rrs(struct rr *rr)
{
	struct rr *rr_aux;

	for (rr_aux = LIST_NEXT(rr, centry);
	     rr_aux != NULL;
	     rr_aux = LIST_NEXT(rr_aux, centry)) {
		if (rrset_cmp(&rr->rrs, &rr_aux->rrs) == 0)
			return (rr_aux);
	}

	return (NULL);
}

struct cache_node *
cache_lookup_dname(const char *dname)
{
	struct cache_node s;

	bzero(&s, sizeof(s));
	strlcpy(s.dname, dname, sizeof(s.dname));

	return (RB_FIND(cache_tree, &cache_tree, &s));
}

struct rr *
cache_lookup(struct rrset *rrs)
{
	struct cache_node	*cn;
	struct rr		*rr;

	cn = cache_lookup_dname(rrs->dname);
	if (cn == NULL)
		return (NULL);
	LIST_FOREACH(rr, &cn->rr_list, centry) {
		if (rrset_cmp(&rr->rrs, rrs) == 0)
			return (rr);
	}

	return (NULL);
}

/* Process an external rr */
int
cache_process(struct rr *rr)
{
	struct cache_node *cn = NULL;
	struct rr *rr_aux, *next;

	/* Sanity check */
	if (RR_AUTH(rr)) {
		log_warnx("cache_process on auth rr");
		return (-1);
	}

	/* Consider received RR as published */
	rr->flags |= RR_FLAG_PUBLISHED;

	/* Record receiving time */
	evtimer_set(&rr->timer, cache_rev, rr);
	if (clock_gettime(CLOCK_MONOTONIC, &rr->age) == -1)
		fatal("clock_gettime");

	/*
	 * If no entries go forward and insert
	 */
	if ((cn = cache_lookup_dname(rr->rrs.dname)) == NULL)
		return (cache_insert(rr));

	/*
	 * Check if we already have a matching RR which is ours.
	 */
	for (rr_aux = cache_lookup(&rr->rrs);
	     rr_aux != NULL;
	     rr_aux = next) {
		next = cache_next_by_rrs(rr_aux);
		if (rrset_cmp(&rr->rrs, &rr_aux->rrs) != 0)
			continue;

		if (RR_AUTH(rr_aux)) {
			/* Same rdata */
			if (rr_rdata_cmp(rr, rr_aux) == 0) {
				/*
				 * This may be a goodbye, defend our RR batman.
				 */
				if (rr->ttl <= rr_aux->ttl / 2) {
					log_info("cache_process: defending %s",
					    rrs_str(&rr->rrs));
					rr_send_an(rr_aux);
				} else {
					/* TODO Cancel possible deletion */
					log_info("cache_process: recover %s",
					    rrs_str(&rr->rrs));
					return (0);
				}
				return (0);
			}
			/*
			 * RDATA isn't equal, if either we, or they are unique,
			 * this is a conflict.
			 */
			if (RR_UNIQ(rr) || RR_UNIQ(rr_aux)) {
				log_warnx("cache_process: conflict for %s",
				    rrs_str(&rr->rrs));
				conflict_resolve_by_rr(rr_aux);
				return (-1);
			}
		}
		else { /* Not ours */
			/* Same rdata */
			if (rr_rdata_cmp(rr, rr_aux) == 0) {
				/* A goodbye RR */
				if (rr->ttl == 0) {
					log_info("cache_process: goodbye %s",
					    rrs_str(&rr->rrs));
					cache_delete(rr_aux);
					return (0);
				}
				/* Cache refresh */
				log_info("cache_process: refresh %s",
				    rrs_str(&rr->rrs));
				rr_aux->ttl = rr->ttl;
				rr_aux->revision = 0;
				cache_schedrev(rr_aux);

				return (0);
			}
		}
	}
	/* Got a goodbye for a record we don't have */
	if (rr->ttl == 0)
		return (0);

	return (cache_insert(rr));
}

int
cache_insert(struct rr *rr)
{
	struct cache_node *cn;
	struct rr *rr_aux, *next;
	/*
	 * If no entries, make a new node
	 */
	if ((cn = cache_lookup_dname(rr->rrs.dname)) == NULL) {
		if ((cn = calloc(1, sizeof(*cn))) == NULL)
			fatal("calloc");
		(void)strlcpy(cn->dname, rr->rrs.dname,
		    sizeof(cn->dname));
		rr->cn = cn;
		LIST_INIT(&cn->rr_list);
		if (RB_INSERT(cache_tree, &cache_tree, cn) != NULL)
			fatal("cache_process: RB_INSERT");
	}

	/*
	 * If this is a unique record, we must disregard everything we know so
	 * far about that RRSet.
	 */
	if (RR_UNIQ(rr)) {
		/* Clean up all records and substitute */
		for (rr_aux = cache_lookup(&rr->rrs);
		     rr_aux != NULL;
		     rr_aux = next) {
			next = cache_next_by_rrs(rr_aux);
			if (rrset_cmp(&rr->rrs, &rr_aux->rrs) != 0)
				continue;
			/* This should not happen */
			if (RR_AUTH(rr))
				fatalx("cache_process: Unexpected auth");
			log_debug("cache_delete 1");
			if (cache_delete(rr_aux) == 1)
				break;
		}
		/* cache_delete() may free cn, so we need to lookup again */
		/* XXX make a function for this */
		if ((cn = cache_lookup_dname(rr->rrs.dname)) == NULL) {
			if ((cn = calloc(1, sizeof(*cn))) == NULL)
				fatal("calloc");
			(void)strlcpy(cn->dname, rr->rrs.dname,
			    sizeof(cn->dname));
			LIST_INIT(&cn->rr_list);
			if (RB_INSERT(cache_tree, &cache_tree, cn) != NULL)
				fatal("cache_process: RB_INSERT");
		}
		log_debug("cache_insert: (new, cleaned up) (%p) %s",
		    rr, rrs_str(&rr->rrs));
		/* Go on, cn is fine now. */
	}

	if (cn == NULL)
		fatalx("cache_insert: cn is NULL !");
	rr->cn = cn;
	LIST_INSERT_HEAD(&cn->rr_list, rr, centry);
	if (rr->flags & RR_FLAG_PUBLISHED)
		rr_notify_in(rr);

	/* Only do revisions for external RR */
	if (!RR_AUTH(rr))
		cache_schedrev(rr);

	return (0);
}

int
cache_delete(struct rr *rr)
{
	struct cache_node *cn;

	log_debug("cache_delete: %s", rrs_str(&rr->rrs));
	if (rr->flags & RR_FLAG_PUBLISHED &&
	    RR_AUTH(rr))
		rr_send_goodbye(rr);
	if (rr->flags & RR_FLAG_PUBLISHED)
		rr_notify_out(rr);
	cn = rr->cn;
	if (evtimer_pending(&rr->timer, NULL))
		evtimer_del(&rr->timer);
	LIST_REMOVE(rr, centry);
	free(rr);
	if (LIST_EMPTY(&cn->rr_list)) {
		RB_REMOVE(cache_tree, &cache_tree, cn);
		free(cn);

		return (1);	/* cache_node freed */
	}

	return (0);
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
/*	log_debug("cache_schedrev: schedule rr type: %s, name: %s (%d)", */
/*	    rr_type_name(rr->rrs.type), rr->rrs.dname, tv.tv_sec); */

	rr->revision++;

	if (evtimer_pending(&rr->timer, NULL))
		evtimer_del(&rr->timer);
	if (evtimer_add(&rr->timer, &tv) == -1)
		fatal("rrt_sched_rev");
}

void
cache_rev(int unused, short event, void *v_rr)
{
	struct rr	*rr = v_rr;
	struct question	*qst;
	struct pkt	 pkt;

/*	log_debug("cache_rev: timeout rr type: %s, name: %s (%u)", */
/*	    rr_type_name(rr->rrs.type), rr->rrs.dname, rr->ttl); */

	/* If we have an active question, try to renew the answer */
	if ((qst = question_lookup(&rr->rrs)) != NULL) {
		pkt_init(&pkt);
		pkt.h.qr = MDNS_QUERY;
		pkt_add_question(&pkt, qst);
		if (pkt_send(&pkt, ALL_IFACE) == -1)
			log_warnx("can't send packet to all interfaces");
	}

	if (rr->revision <= 3)
		cache_schedrev(rr);
	else
		cache_delete(rr);
}

void
auth_release(struct rr *rr)
{
	/* Sanity check */
	if (!RR_AUTH(rr))
		fatalx("auth_release on non auth rr");
	if (rr->auth_refcount == 1)
		cache_delete(rr);
	else
		rr->auth_refcount--;
}

struct rr *
auth_get(struct rr *rr)
{
	struct rr *rr_cache;

	CACHE_FOREACH_RRS(rr_cache, &rr->rrs) {
		/* Have an entry already */
		if (rr_rdata_cmp(rr, rr_cache) == 0) {
			rr_cache->auth_refcount++;
			return (rr_cache);
		}
		/*
		 * Not the same, only ok if not UNIQ.
		 */
		if (RR_UNIQ(rr_cache) || RR_UNIQ(rr)) {
			log_warnx("auth_get: conflict for %s (1)",
			    rrs_str(&rr->rrs));
			return (NULL);
		}
	}

	/* Duplicate and insert */
	rr_cache = rr_dup(rr);
	rr_cache->auth_refcount = 1;

	if (cache_insert(rr_cache) == 0)
		return (rr_cache);

	return (NULL);
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
			CACHE_FOREACH_RRS(rraux, rrs) {
				/* Don't include rr if it's too old */
				if (rr_ttl_left(rraux) < rraux->ttl / 2)
					continue;
				pkt_add_anrr(&pkt, rraux);
			}
		}
	}

	if (pkt.h.qdcount > 0)
		if (pkt_send(&pkt, ALL_IFACE) == -1)
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

	/* See if we have a question matching this rr */
	if ((qst = question_lookup(&rr->rrs)) == NULL)
		return (0);

	/* Loop through controllers and check who wants it */
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
					/*
					 * If this is a SRV, make sure we're
					 * asking for the target
					 */
					if (rr->rrs.type == T_SRV &&
					    q->ms_a == NULL) {
						if ((q->ms_a = calloc(1,
						    sizeof(*q->ms_a))) == NULL)
							err(1, "calloc");
						strlcpy(q->ms_a->dname,
						    rr->rdata.SRV.target,
						    sizeof(q->ms_a->dname));
						q->ms_a->class = C_IN;
						q->ms_a->type = T_A;
						LIST_INSERT_HEAD(&q->rrslist,
						    q->ms_a, entry);
						if (question_add(q->ms_a) ==
						    NULL)
							log_warnx("Can't add "
							    "question");
					}
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

struct pge *
pge_from_ms(struct pg *pg, struct mdns_service *ms, struct iface *iface)
{
	struct pge	*pge;
	struct rr	srv, txt, ptr_proto, ptr_services;
	struct question *qst;
	char		 servname[MAXHOSTNAMELEN], proto[MAXHOSTNAMELEN];


	qst = NULL;
	bzero(&srv, sizeof(srv));
	bzero(&txt, sizeof(txt));
	bzero(&ptr_proto, sizeof(ptr_proto));
	bzero(&ptr_services, sizeof(ptr_services));
	bzero(proto, sizeof(proto));
	bzero(servname, sizeof(servname));

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
	/* T_SRV */
	(void)rr_set(&srv, servname, T_SRV, C_IN, TTL_SRV,
	    RR_FLAG_CACHEFLUSH, NULL, 0);
	(void)strlcpy(srv.rdata.SRV.target, ms->target,
	    sizeof(srv.rdata.SRV.target));
	srv.rdata.SRV.priority = ms->priority;
	srv.rdata.SRV.weight = ms->weight;
	srv.rdata.SRV.port = ms->port;
	/* T_TXT */
	(void)rr_set(&txt, servname, T_TXT, C_IN, TTL_TXT,
	    RR_FLAG_CACHEFLUSH,
	    ms->txt, sizeof(ms->txt));
	/* T_PTR proto */
	(void)rr_set(&ptr_proto, proto, T_PTR, C_IN, TTL_PTR,
	    0, servname, sizeof(servname));
	/* T_PTR services */
	(void)rr_set(&ptr_services, "_services._dns-sd._udp.local",
	    T_PTR, C_IN, TTL_PTR, 0, proto, sizeof(proto));

	/* Question */
	if ((qst = calloc(1, sizeof(*qst))) == NULL)
		fatal("calloc");
	qst->rrs.type  = T_ANY;
	qst->rrs.class = C_IN;
	(void)strlcpy(qst->rrs.dname, srv.rrs.dname,
	    sizeof(qst->rrs.dname));

	/* Alloc and init pge structure */
	if ((pge = calloc(1, sizeof(*pge))) == NULL)
		fatal("calloc");
	pge->pg		= pg;
	pge->pge_type   = PGE_TYPE_SERVICE;
	pge->pge_flags |= PGE_FLAG_INC_A;
	pge->iface	= iface;
	pge->state	= PGE_STA_UNPUBLISHED;
	evtimer_set(&pge->timer, pge_fsm, pge);
	pge->pqst = qst;
	/* Insert everyone in auth */
	if ((pge->rr[0] = auth_get(&srv)) == NULL)
		goto bad;
	pge->nrr++;
	if ((pge->rr[1] = auth_get(&txt)) == NULL) {
		auth_release(pge->rr[0]);
		goto bad;
	}
	pge->nrr++;
	if ((pge->rr[2] = auth_get(&ptr_proto)) == NULL) {
		auth_release(pge->rr[0]);
		auth_release(pge->rr[1]);
		goto bad;
	}
	pge->nrr++;
	if ((pge->rr[3] = auth_get(&ptr_services)) == NULL) {
		auth_release(pge->rr[0]);
		auth_release(pge->rr[1]);
		auth_release(pge->rr[2]);
		goto bad;
	}
	pge->nrr++;

	/*
	 * If we got here, all is fine and we can link pge
	 */
	TAILQ_INSERT_TAIL(&pge_queue, pge, entry);
	if (pg != NULL)
		LIST_INSERT_HEAD(&pg->pge_list, pge, pge_entry);

	return (pge);

bad:
	free(pge->pqst);
	free(pge);

	return (NULL);
}

void
pge_fsm_restart(struct pge *pge, struct timeval *tv)
{
	if (evtimer_pending(&pge->timer, NULL))
		evtimer_del(&pge->timer);
	evtimer_add(&pge->timer, tv);
}

void
pge_fsm(int unused, short event, void *v_pge)
{
	struct pg	*pg;
	struct pge	*pge, *pge_primary;
	struct timeval	 tv;
	struct pkt	 pkt;
	int		 i;

	pge = v_pge;
	pg  = pge->pg;

	/*
	 * In order to publish services and addresses we must first make sure
	 * our primary address has been sucessfully published, if not, we delay
	 * publication for a second. We don't really need this if the service is
	 * not on our local address.
	 */
	if (pge->pge_type == PGE_TYPE_SERVICE) {
		pge_primary = conf->pge_primary;
		if (pge_primary->state < PGE_STA_ANNOUNCING) {
			timerclear(&tv);
			tv.tv_sec = 1;
			pge_fsm_restart(pge, &tv);
			return;
		}
	}

	switch (pge->state){
	case PGE_STA_UNPUBLISHED:
		pge->state = PGE_STA_PROBING;
		/* FALLTHROUGH */
	case PGE_STA_PROBING:
		if ((pge->pge_flags & PGE_FLAG_INTERNAL) == 0 &&
		    pge->sent == 0)
			control_notify_pg(pg->c, pg,
			    IMSG_CTL_GROUP_PROBING);
		/* Build up our probe packet */
		pkt_init(&pkt);
		pkt.h.qr = MDNS_QUERY;
		if (pge->pqst != NULL) {
			/* Unicast question ? */
			if (pge->sent < 2)
				pge->pqst->flags |= QST_FLAG_UNIRESP;
			else
				pge->pqst->flags &= ~QST_FLAG_UNIRESP;
			pkt_add_question(&pkt, pge->pqst);
		}
		/* Add the RRs in the NS section */
		for (i = 0; i < pge->nrr; i++)
			pkt_add_nsrr(&pkt, pge->rr[i]);
		/* Always probe for all interfaces, this is safer */
		if (pkt_send(&pkt, ALL_IFACE) == -1)
			log_warnx("can't send probe packet");
		/* Probing done, start announcing */
		if (++pge->sent == 3) {
			/* sent is re-used by PGE_STA_ANNOUNCING */
			pge->sent  = 0;
			pge->state = PGE_STA_ANNOUNCING;
			/*
			 * Consider records published
			 */
			for (i = 0; i < pge->nrr; i++) {
				if ((pge->rr[i]->flags & RR_FLAG_PUBLISHED) == 0)
					rr_notify_in(pge->rr[i]);
				pge->rr[i]->flags |= RR_FLAG_PUBLISHED;
			}
		}
		timerclear(&tv);
		tv.tv_usec = INTERVAL_PROBETIME;
		pge_fsm_restart(pge, &tv);
		break;
	case PGE_STA_ANNOUNCING:
		if ((pge->pge_flags & PGE_FLAG_INTERNAL) == 0 &&
		    pge->sent == 0)
			control_notify_pg(pg->c, pg,
			    IMSG_CTL_GROUP_ANNOUNCING);
		/* Build up our announcing packet */
		pkt_init(&pkt);
		pkt.h.qr = MDNS_RESPONSE;
		/* Add the RRs in the AN secion */
		for (i = 0; i < pge->nrr; i++)
			pkt_add_anrr(&pkt, pge->rr[i]);
		/*
		 * PGE_FLAG_INC_A, we should add our primary A resource record
		 * to the packet.
		 */
		if (pge->pge_flags & PGE_FLAG_INC_A)
			pkt_add_anrr(&pkt, conf->pge_primary->rr[PGE_RR_PRIM]);

		if (pkt_send(&pkt, ALL_IFACE) == -1) {
			log_warnx("can't send announce packet");
			return;
		}

		if (pge->pge_flags & PGE_FLAG_INC_A) {
			LIST_REMOVE(conf->pge_primary->rr[PGE_RR_PRIM], pentry);
			pkt.h.ancount--; /* XXX */
		}

		if (++pge->sent < 3)  {
			timerclear(&tv);
			tv.tv_sec = pge->sent;
			pge_fsm_restart(pge, &tv);
			break;
		}
		pge->state = PGE_STA_PUBLISHED;
		/* FALLTHROUGH */
	case PGE_STA_PUBLISHED:
		if ((pge->pge_flags & PGE_FLAG_INTERNAL) == 0)
			log_debug("group %s published", pg->name);
		/*
		 * Check if every pge in pg is published, if it is
		 * we'll consider the group as published, notify controller
		 */
		if ((pge->pge_flags & PGE_FLAG_INTERNAL) == 0 &&
		    pg_published(pg))
			control_notify_pg(pg->c, pg, IMSG_CTL_GROUP_PUBLISHED);
		break;
	default:
		fatalx("invalid group state");
	}
}

void
pge_kill(struct pge *pge)
{
	int i;
	struct rr *rr;

	/* Stop pge machine */
	if (evtimer_pending(&pge->timer, NULL))
		evtimer_del(&pge->timer);

	/*
	 * Release our records.
	 */
	for (i = 0; i < pge->nrr; i++) {
		rr = pge->rr[i];
		if (rr == NULL)
			continue;
		auth_release(rr);
		pge->rr[i] = NULL;
	}
	/*
	 * Unlink pge
	 */
	TAILQ_REMOVE(&pge_queue, pge, entry);
	if ((pge->pge_flags & PGE_FLAG_INTERNAL) == 0) {
		LIST_REMOVE(pge, pge_entry);
	}
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

	TAILQ_FOREACH(pge, &pge_queue, entry) {
		/* XXX this is so wrong.... */
		if (pge->iface == ALL_IFACE || pge->iface == iface) {
			/* XXX must be a random probe time */
			pge_revert_probe(pge);
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

void
pge_initprimary(void)
{
	struct pge	*pge;
	struct question	*qst;
	struct iface	*iface;
	struct rr	 rr;
	char		 revaddr[MAXHOSTNAMELEN];
	struct in_addr	 inaddrany;
	struct iface_addr *ifa;

	if ((conf->pge_primary = calloc(1, sizeof(*pge))) == NULL)
		fatal("calloc");
	pge	       = conf->pge_primary;
	pge->pge_flags = PGE_FLAG_INTERNAL;
	pge->pg	       = NULL;
	pge->sent      = 0;
	pge->state     = PGE_STA_UNPUBLISHED;
	pge->iface     = ALL_IFACE;
	evtimer_set(&pge->timer, pge_fsm, pge);
	/* Link to global pge */
	TAILQ_INSERT_TAIL(&pge_queue, pge, entry);
	/* Set up primary question */
	if ((qst = calloc(1, sizeof(*qst))) == NULL)
		fatal("calloc");
	(void)strlcpy(qst->rrs.dname, conf->myname, sizeof(qst->rrs.dname));
	qst->rrs.type  = T_ANY;
	qst->rrs.class = C_IN;
	pge->pqst = qst;
	/* Must add T_A, T_PTR(rev) and T_HINFO */
	/* T_A record, NOTE: must be first to match PGE_RR_PRIM */
	inaddrany.s_addr = INADDR_ANY;
	bzero(&rr, sizeof(rr));
	rr_set(&rr, conf->myname, T_A, C_IN, TTL_HNAME,
	    RR_FLAG_CACHEFLUSH,
	    &inaddrany, sizeof(inaddrany));
	if ((pge->rr[pge->nrr++] = auth_get(&rr)) == NULL)
		goto bad;
	bzero(&rr, sizeof(rr));
	rr_set(&rr, conf->myname, T_AAAA, C_IN, TTL_HNAME,
	    RR_FLAG_CACHEFLUSH,
	    &in6addr_any, sizeof(struct in6_addr));
	if ((pge->rr[pge->nrr++] = auth_get(&rr)) == NULL)
		goto bad;
	/* T_PTR record reverse address, one for every address */
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		LIST_FOREACH(ifa, &iface->addr_list, entry) {
			bzero(&rr, sizeof(rr));
			reversstr(revaddr, sstosa(&ifa->addr));
			rr_set(&rr, revaddr, T_PTR, C_IN, TTL_HNAME,
			    RR_FLAG_CACHEFLUSH,
			    conf->myname, sizeof(conf->myname));
			if ((pge->rr[pge->nrr++] = auth_get(&rr)) == NULL)
				goto bad;
		}
	}
	/* T_HINFO record */
	bzero(&rr, sizeof(rr));
	rr_set(&rr, conf->myname, T_HINFO, C_IN, TTL_HNAME,
	    RR_FLAG_CACHEFLUSH,
	    &conf->hi, sizeof(conf->hi));
	if ((pge->rr[pge->nrr++] = auth_get(&rr)) == NULL)
		goto bad;

	return;
bad:
	log_warnx("Can't init primary addresses");
	fatalx("internal error");
}


struct pge *
pge_new_workstation(struct iface *iface)
{
	struct mdns_service	 ms;
	struct pge		*pge;
	char			 myname[MAXLABELLEN], *cp;

	/* Build our service */
	bzero(&ms, sizeof(ms));
	ms.port = 9;	/* workstation stuff */
	(void)strlcpy(ms.app, "workstation", sizeof(ms.app));
	(void)strlcpy(ms.proto, "tcp", sizeof(ms.proto));
	(void)strlcpy(myname, conf->myname, sizeof(myname));
	/* Chomp .local suffix */
	if ((cp = strchr(myname, '.')) != NULL)
		*cp = '\0';
	if (snprintf(ms.name, sizeof(ms.name),
	    "%s [%s:%s]", myname, iface->name,
	    ether_ntoa(&iface->ea)) >= (int)sizeof(ms.name))
		log_warnx("Workstation name too long");
	strlcpy(ms.target, conf->myname, sizeof(ms.target));

	pge = pge_from_ms(NULL, &ms, iface);
	pge->pge_flags |= PGE_FLAG_INTERNAL;

	return (pge);
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
	log_debug("group %s unpublished", pg->name);
	free(pg);
}

/*
 * True if group is published
 */
int
pg_published(struct pg *pg)
{
	struct pge	*pge;

	LIST_FOREACH(pge, &pg->pge_list, pge_entry) {
		if (pge->state != PGE_STA_PUBLISHED)
			return (0);
	}

	return (1);
}

int
rr_send_goodbye(struct rr *rr)
{
	u_int32_t	old_ttl;
	int		r = 0;

	if ((rr->flags & RR_FLAG_PUBLISHED) == 0)
		return (0);
	old_ttl = rr->ttl;
	/*
	 * Send a goodbye for published records
	 */
	rr->ttl = 0;
	r	= rr_send_an(rr);
	rr->ttl = old_ttl;

	return (r);
}

int
rr_send_an(struct rr *rr)
{
	struct pkt pkt;

	pkt_init(&pkt);
	pkt.h.qr = MDNS_RESPONSE;
	pkt_add_anrr(&pkt, rr);
	if (pkt_send(&pkt, ALL_IFACE) == -1) {
		log_warnx("rr_send_an error %s", rrs_str(&rr->rrs));

		return (-1);
	}

	return (0);
}

void
conflict_resolve_by_rr(struct rr *rr)
{
	struct pge *pge, *next;
	int i;

	for (pge = TAILQ_FIRST(&pge_queue); pge != NULL; pge = next) {
		next = TAILQ_NEXT(pge, entry);
		for (i = 0; i < pge->nrr; i++) {
			if (rr != pge->rr[i])
				continue;
			/*
			 * If unpublished or probing, give up !
			 */
			if (pge->state < PGE_STA_ANNOUNCING)
				pge_conflict_drop(pge);
			else {/* Reset to probing state */
				log_warnx("Got a conflict revert to probe, "
				    "HIGHLY experimental");
				pge_revert_probe(pge);
			}
		}
	}
}

/*
 * Drop this pge
 */
void
pge_conflict_drop(struct pge *pge)
{
	struct pg *pg;

	log_debug("pge_conflict_drop: %p", pge);

	if (pge->pge_flags & PGE_FLAG_INTERNAL) {
		log_warnx("conflict for internal pge, unimplemented");
		return;
	}

	pg = pge->pg;
	control_notify_pg(pg->c, pg, IMSG_CTL_GROUP_ERR_COLLISION);
	pg_kill(pg);
}

void
pge_revert_probe(struct pge *pge)
{
	struct timeval tv;
	struct rr *rr;
	int i;

	timerclear(&tv);
	pge->state	= PGE_STA_PROBING;
	pge->sent	= 0;

	for (i = 0; i < pge->nrr; i++) {
		rr = pge->rr[i];
		/* Stop answering for these RR */
		/* XXX not sure about this */
		rr->flags &= ~RR_FLAG_PUBLISHED;
	}
	/* Restart the machine */
	pge_fsm_restart(pge, &tv);
}
