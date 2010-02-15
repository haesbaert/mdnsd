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

#include <string.h>

#include "mdnsd.h"
#include "mdns.h"
#include "log.h"

/* resource record cache node */
struct rrc_node {
	RB_ENTRY(rrc_node)	entry;
	LIST_HEAD(, mdns_rr) hrr; /* head rr */
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
