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

#include "mdnsd.h"
#include "log.h"

#include <err.h>
#include <stdlib.h>

LIST_HEAD(, query)	qlist;

void
query_init(void)
{
	LIST_INIT(&qlist);
}

struct query *
query_place(int type, struct mdns_question *mq, struct ctl_conn *c)
{
	struct query	*q;

	/* avoid having two equivalent questions */
	LIST_FOREACH(q, &qlist, entry)
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
	LIST_INSERT_HEAD(&qlist, q, entry);
	
	return q;
}

/* notify about this new rr to all interested peers */
int
query_notifyin(struct mdns_rr *rr)
{
	struct query	*q;
	struct ctl_conn *c;
	int		 match	   = 0;
	LIST_FOREACH(q, &qlist, entry) {
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
query_notifyout(struct mdns_rr *rr)
{
	struct query	*q;
	int		 match = 0;
	
	LIST_FOREACH(q, &qlist, entry) {
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

int
query_cleanbyconn(struct ctl_conn *c)
{
	struct query	*q;
	struct ctl_conn *qc;
	int		 match = 0;
	
	LIST_FOREACH(q, &qlist, entry) {
		LIST_FOREACH(qc, &q->ctl_list, qentry) {
			if (qc->iev.ibuf.fd != c->iev.ibuf.fd)
				continue;
			LIST_REMOVE(qc, qentry);
			if (LIST_EMPTY(&q->ctl_list)) {
				LIST_REMOVE(q, entry);
				free(q->mq);
				free(q);
			}
			match++;
		}
	}
	
	return match;
}
