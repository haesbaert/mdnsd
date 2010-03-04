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

#include <sys/queue.h>

#include <stdlib.h>
#include <string.h>

#include "mdnsd.h"
#include "mdns.h"
#include "log.h"

static int		cache_insert(struct mdns_rr *);
static int		cache_delete(struct mdns_rr *);
static void		cache_schedrev(struct mdns_rr *);
static void		cache_rev(int, short, void *);

static struct rrt_tree	rrt_cache;

void
cache_init(void)
{
	RB_INIT(&rrt_cache);
}

int
cache_process(struct mdns_rr *rr)
{

	evtimer_set(&rr->rev_timer, cache_rev, rr);
	if (rr->ttl == 0)
		return cache_delete(rr);
	if (cache_insert(rr) == -1)
		return -1;
	
	return 0;
}
	
struct mdns_rr *
cache_lookup(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	return rrt_lookup(&rrt_cache, dname, type, class);
}


static int
cache_insert(struct mdns_rr *rr)
{
	struct rr_head	*hrr;
	struct rrt_node *n;
	struct mdns_rr	*rraux;
	
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
cache_delete(struct mdns_rr *rr)
{
	struct mdns_rr	*rraux, *next;
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
cache_schedrev(struct mdns_rr *rr)
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
	struct mdns_rr *rr = v_rr;
	
	log_debug("cache_rev: timeout rr type: %s, name: %s (%u)",
	    rr_type_name(rr->type), rr->dname, rr->ttl);
	
/* 	if (rr->active && rr->revision <= 3) */
	if (rr->revision <= 3)
		cache_schedrev(rr);
	else
		cache_delete(rr);
/* 	rrt_dump(); */
}

