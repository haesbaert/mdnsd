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

static int		 rra_delete(struct mdns_rr *);
static int		 rra_insert(struct mdns_rr *rr);
static struct rrt_node	*rra_lookup_node(char dname[], u_int16_t, u_int16_t);
static struct rr_head	*rra_lookup_head(char [MAXHOSTNAMELEN], u_int16_t, u_int16_t);

RB_HEAD(rra_tree, rrt_node) rra;
RB_PROTOTYPE(rra_tree, rrt_node, entry, rrt_compare);
RB_GENERATE(rra_tree, rrt_node, entry, rrt_compare);

void
rra_init(void)
{
	RB_INIT(&rra);
}

struct mdns_rr *
rra_lookup(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rr_head	*hrr;
	
	hrr = rra_lookup_head(dname, type, class);
	if (hrr)
		return LIST_FIRST(hrr);
	return NULL;
}

void
rra_dump(void)
{
	struct mdns_rr	*rr;
	struct rrt_node *n;

	log_debug("rra_dump");
	RB_FOREACH(n, rra_tree, &rra) {
		rr = LIST_FIRST(&n->hrr);
		LIST_FOREACH(rr, &n->hrr, entry)
		    log_debug_rrdata(rr);
	}
}

static int
rra_insert(struct mdns_rr *rr)
{
	struct rr_head	*hrr;
	struct rrt_node *n;
	struct mdns_rr	*rraux;
	
	log_debug("rra_insert: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	
	hrr = rra_lookup_head(rr->dname, rr->type, rr->class);
	if (hrr == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		
		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, entry);
		if (RB_INSERT(rra_tree, &rra, n) != NULL)
			fatal("rra_insert: RB_INSERT");
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
		
		return 0;
	}
	
	/* rr is not unique, see if this is a cache refresh */
	while ((rraux = LIST_FIRST(hrr)) != NULL) {
		if (memcmp(&rr->rdata, &rraux->rdata, rraux->rdlen) == 0) {
			rraux->ttl = rr->ttl;
			rraux->revision = 0;
			free(rr);
			
			return 0;
		}
	}
	
	/* not a refresh, so add */
	LIST_INSERT_HEAD(hrr, rr, entry);
	
	return 0;
}

static int
rra_delete(struct mdns_rr *rr)
{
	struct mdns_rr	*rraux;
	struct rrt_node	*s;
	int		 n = 0;
	
	log_debug("rra_delete: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	s = rra_lookup_node(rr->dname, rr->type, rr->class);
	if (s == NULL)
		return 0;
	
	while ((rraux = LIST_FIRST(&s->hrr)) != NULL) {
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
		RB_REMOVE(rra_tree, &rra, s);
		free(s);
	}
	
	return n;
}
	
static struct rrt_node *
rra_lookup_node(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rrt_node	s, *tmp;
	struct mdns_rr	rr;
	
	bzero(&s, sizeof(s));
	bzero(&rr, sizeof(rr));
	rr.type	 = type;
	rr.class = class;
	strlcpy(rr.dname, (const char *)dname, MAXHOSTNAMELEN);

	LIST_INIT(&s.hrr);
	LIST_INSERT_HEAD(&s.hrr, &rr, entry);
	
	tmp = RB_FIND(rra_tree, &rra, &s);
	if (tmp == NULL)
		return NULL;
	
	return tmp;
}

static struct rr_head *
rra_lookup_head(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rrt_node	*tmp;
	
	tmp = rra_lookup_node(dname, type, class);
	if (tmp == NULL)
		return NULL;
	
	return &tmp->hrr;
}
