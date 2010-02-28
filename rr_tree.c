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

static int		 rrt_compare(struct rrt_node *, struct rrt_node *);

RB_GENERATE(rrt_tree, rrt_node, entry, rrt_compare);

struct rr_head *
rrt_lookup_head(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN],
    u_int16_t type, u_int16_t class)
{
	struct rrt_node	*tmp;
	
	tmp = rrt_lookup_node(rrt, dname, type, class);
	if (tmp == NULL)
		return NULL;
	
	return &tmp->hrr;
}

struct mdns_rr *
rrt_lookup(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rr_head	*hrr;
	
	hrr = rrt_lookup_head(rrt, dname, type, class);
	if (hrr)
		return LIST_FIRST(hrr);
	return NULL;
}

void
rrt_dump(struct rrt_tree *rrt)
{
	struct mdns_rr	*rr;
	struct rrt_node *n;

	log_debug("rrt_dump");
	RB_FOREACH(n, rrt_tree, rrt) {
		rr = LIST_FIRST(&n->hrr);
		LIST_FOREACH(rr, &n->hrr, entry)
		    log_debug_rrdata(rr);
	}
}

struct rrt_node *
rrt_lookup_node(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
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
	
	tmp = RB_FIND(rrt_tree, rrt, &s);
	if (tmp == NULL)
		return NULL;
	
	return tmp;
}

static int
rrt_compare(struct rrt_node *a, struct rrt_node *b)
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

