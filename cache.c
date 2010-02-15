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

static int	rrc_compare(struct rrc_node *, struct rrc_node *);

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
	struct rrc_node	 		s, *tmp;
	struct mdns_rr			rr;
	
	bzero(&s, sizeof(s));
	rr.type	 = type;
	rr.class = class;
	strlcpy(rr.dname, (const char *)dname, MAXHOSTNAMELEN);

	/* Yes, we use a dummy head to find the node */
	LIST_INIT(&s.hrr);
	LIST_INSERT_HEAD(&s.hrr, &rr, c_entry);
	
	tmp = RB_FIND(rrc_tree, &rrt, &s);
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
rrc_insert(struct mdns_rr *rr)
{
	struct rr_head *hrr;
	
	/* Check if shared RR */
	hrr = rrc_lookup_head(rr->dname, rr->type, rr->class);
	if (hrr == NULL) {
		struct rrc_node *n;
		
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		LIST_INIT(&n->hrr);
		hrr = &n->hrr;
	}
	
	LIST_INSERT_HEAD(hrr, rr, c_entry);
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
