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

/* resource record cache node */
struct rrc_node {
	RB_ENTRY(rrc_node)	entry;
	LIST_HEAD(rr_head, mdns_rr) hrr; /* head rr */
};

static int		 rrc_compare(struct rrc_node *, struct rrc_node *);
static int		 rrc_delete(struct mdns_rr *);
static struct rrc_node	*rrc_lookup_node(char dname[], u_int16_t, u_int16_t);

RB_HEAD(rrc_tree, rrc_node) rrt;
RB_PROTOTYPE(rrc_tree, rrc_node, entry, rrc_compare);
RB_GENERATE(rrc_tree, rrc_node, entry, rrc_compare);

void
rrc_init(void)
{
	RB_INIT(&rrt);
}

struct rr_head *
rrc_lookup_head(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rrc_node	*tmp;
	
	tmp = rrc_lookup_node(dname, type, class);
	if (tmp == NULL)
		return NULL;
	
	return &tmp->hrr;
}

struct mdns_rr *
rrc_lookup(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rr_head	*hrr;
	
	hrr = rrc_lookup_head(dname, type, class);
	return LIST_FIRST(hrr);
}

void
rrc_process(struct mdns_rr *rr)
{
	struct rr_head *hrr;
	struct rrc_node *n;
	struct mdns_rr *rraux;
	
	if (rr->ttl == 0) {
		rrc_delete(rr);
		return;
	}
		
	hrr = rrc_lookup_head(rr->dname, rr->type, rr->class);
	if (hrr == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, c_entry);
		RB_INSERT(rrc_tree, &rrt, n);
		return;
	}
		
	/* if an unique record, clean all previous and substitute */
	if (RR_UNIQ(rr)) {
		while ((rraux = LIST_FIRST(hrr)) != NULL) {
			LIST_REMOVE(rraux, c_entry);
			free(rraux);
		}
		LIST_INSERT_HEAD(hrr, rr, c_entry);
		return;
	}
	
	/* rr is not unique, see if this is a cache refresh */
	while ((rraux = LIST_FIRST(hrr)) != NULL) {
		if (memcmp(&rr->rdata, &rraux->rdata, rraux->rdlen) == 0) {
			rraux->ttl = rr->ttl;
			free(rr);
			return;
		}
	}
	
	/* not a refresh, so add */
	LIST_INSERT_HEAD(hrr, rr, c_entry);
}
	
void
rrc_dump(void)
{
	struct mdns_rr	*rr;
	struct rrc_node *n;

	log_debug("rrc_dump");
	
	RB_FOREACH(n, rrc_tree, &rrt) {
		rr = LIST_FIRST(&n->hrr);
		LIST_FOREACH(rr, &n->hrr, c_entry)
		    log_debug_rrdata(rr);
	}
}

static int
rrc_compare(struct rrc_node *a, struct rrc_node *b)
{
	struct mdns_rr *rra, *rrb;
	
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

static int
rrc_delete(struct mdns_rr *rr)
{
	struct mdns_rr	*rraux;
	struct rrc_node	 *s;
	int n = 0;
	
	log_debug("rrc_delete %s data:", rr->dname);
	log_debug_rrdata(rr);
	s = rrc_lookup_node(rr->dname, rr->type, rr->class);
	if (s == NULL)
		return 0;
	
	while ((rraux = LIST_FIRST(&s->hrr)) != NULL) {
		if (RR_UNIQ(rr) ||
		    (memcmp(&rr->rdata, &rraux->rdata,
		    rraux->rdlen) == 0)) {
			LIST_REMOVE(rraux, c_entry);
			free(rraux);
			n++;
		}
	}

	if (LIST_EMPTY(&s->hrr))
		RB_REMOVE(rrc_tree, &rrt, s);
	
	return n;
}
	
static struct rrc_node *
rrc_lookup_node(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rrc_node	 		s, *tmp;
	struct mdns_rr			rr;
	
	bzero(&s, sizeof(s));
	bzero(&rr, sizeof(rr));
	rr.type	 = type;
	rr.class = class;
	strlcpy(rr.dname, (const char *)dname, MAXHOSTNAMELEN);

	LIST_INIT(&s.hrr);
	LIST_INSERT_HEAD(&s.hrr, &rr, c_entry);
	
	tmp = RB_FIND(rrc_tree, &rrt, &s);
	if (tmp == NULL)
		return NULL;
	
	return tmp;
}
