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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "mdnsd.h"
#include "log.h"

static void	publish_fsm(int, short, void *_pub);

enum publish_state {
	PUB_INITIAL,
	PUB_PROBE,
	PUB_ANNOUNCE,
	PUB_DONE
};

struct publish {
	struct mdns_pkt	 pkt;
	struct event	 timer;	/* used in probe and announce */
	struct iface	*iface;
	int		 state;	/* enum publish state */
	int		 sent;
};

extern struct mdnsd_conf *conf;

#define RANDOM_PROBETIME (random() % 250000)

/* TODO: Turn all the publishing types into functions */
void
publish_init(void)
{
	struct iface	*iface;
	struct mdns_rr	*rr;
	char		 revaddr[MAXHOSTNAMELEN];
	
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		/* myname */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		rr_set(rr, conf->myname, T_A, C_IN, MDNS_TTL_HNAME, 1,
		    &iface->addr, sizeof(iface->addr));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");

		/* publish reverse address */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		reversstr(revaddr, &iface->addr);
		rr_set(rr, revaddr, T_PTR, C_IN, MDNS_TTL_HNAME, 1,
		    conf->myname, sizeof(conf->myname));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");
		
		/* publish hinfo */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		rr_set(rr, conf->myname, T_HINFO, C_IN, MDNS_TTL_HNAME, 1,
		    &conf->hi, sizeof(conf->hi));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");
 	}
}

void
publish_allrr(struct iface *iface)
{
	struct mdns_question	*mq;
	struct mdns_rr		*rr, *rrcopy;
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
	question_set(mq, conf->myname, T_ANY, C_IN, 1, 1);
	pkt_add_question(&pub->pkt, mq);
	
	RB_FOREACH(n, rrt_tree, &iface->rrt) {
		/* now go through all our rr and add to the same packet */
		LIST_FOREACH(rr, &n->hrr, entry) {
			if ((rrcopy = calloc(1, sizeof(struct mdns_rr))) == NULL)
				fatal("calloc");
			memcpy(rrcopy, rr, sizeof(struct mdns_rr));
			pkt_add_nsrr(&pub->pkt, rrcopy);
		}
	}
	
	timerclear(&tv);
	tv.tv_usec = RANDOM_PROBETIME;
	evtimer_set(&pub->timer, publish_fsm, pub);
	evtimer_add(&pub->timer, &tv);
}

int
publish_delete(struct iface *iface, struct mdns_rr *rr)
{
	struct mdns_rr	*rraux, *next;
	struct rrt_node	*s;
	int		 n = 0;
	
	log_debug("publish_delete: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	s = rrt_lookup_node(&iface->rrt, rr->dname, rr->type, rr->class);
	if (s == NULL)
		return 0;
	
	for (rraux = LIST_FIRST(&s->hrr); rraux != NULL; rraux = next) {
		next = LIST_NEXT(rraux, entry);
		if (RR_UNIQ(rr) ||
		    (memcmp(&rr->rdata, &rraux->rdata,
		    rraux->rdlen) == 0)) {
			LIST_REMOVE(rraux, entry);
			free(rraux);
			n++;
		}
	}	
	
	if (LIST_EMPTY(&s->hrr)) {
		RB_REMOVE(rrt_tree, &iface->rrt, s);
		free(s);
	}
	
	return n;
}

int
publish_insert(struct iface *iface, struct mdns_rr *rr)
{
	struct rr_head	*hrr;
	struct rrt_node *n;
	struct mdns_rr	*rraux;
	
	log_debug("publish_insert: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	
	hrr = rrt_lookup_head(&iface->rrt, rr->dname, rr->type, rr->class);
	if (hrr == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");
		
		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, entry);
		if (RB_INSERT(rrt_tree, &iface->rrt, n) != NULL)
			fatal("rrt_insert: RB_INSERT");
		
		return 0;
	}
		
	/* if an unique record, clean all previous and substitute */
	if (RR_UNIQ(rr)) {
		while ((rraux = LIST_FIRST(hrr)) != NULL) {
			LIST_REMOVE(rraux, entry);
			free(rraux);
		}
		LIST_INSERT_HEAD(hrr, rr, entry);
		
		return 0;
	}
	
	/* not unique, just add */
	LIST_INSERT_HEAD(hrr, rr, entry);
	
	return 0;
}

static void
publish_fsm(int unused, short event, void *v_pub)
{
	struct publish		*pub = v_pub;
	struct timeval		 tv;
	struct mdns_rr		*rr;
	struct mdns_question	*mq;

	switch (pub->state) {
	case PUB_INITIAL:	
		pub->state = PUB_PROBE;
		/* FALLTHROUGH */
	case PUB_PROBE:
		pub->pkt.qr = 0;
		if (pkt_send_allif(&pub->pkt) == -1)
			log_debug("can't send packet to all interfaces");
		pub->sent++;
		if (pub->sent == 3) { /* enough probing, start announcing */
			pub->state  = PUB_ANNOUNCE;
			pub->sent   = 0;
			pub->pkt.qr = 1;
			/* remove questions */
			while ((mq = (LIST_FIRST(&pub->pkt.qlist))) != NULL) {
				LIST_REMOVE(mq, entry);
				pub->pkt.qdcount--;
				free(mq);
			}
			/* move all ns records to answer records */
			while ((rr = (LIST_FIRST(&pub->pkt.nslist))) != NULL) {
				LIST_REMOVE(rr, entry);
				pub->pkt.nscount--;
				if (pkt_add_anrr(&pub->pkt, rr) == -1)
					log_debug("publish_fsm: "
					    "pkt_add_anrr failed");
			}
			publish_fsm(unused, event, pub);
			return;
		}
		tv.tv_usec = RANDOM_PROBETIME;
		evtimer_add(&pub->timer, &tv);
		break;
	case PUB_ANNOUNCE:
		if (pkt_send_allif(&pub->pkt) == -1)
			log_debug("can't send packet to all interfaces");
		pub->sent++;
		if (pub->sent < 3) {
			timerclear(&tv);
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
			LIST_REMOVE(rr, entry);
			pub->pkt.ancount--;
			free(rr);
		}
		while ((rr = LIST_FIRST(&pub->pkt.nslist)) != NULL) {
			LIST_REMOVE(rr, entry);
			pub->pkt.nscount--;
			free(rr);
		}
		while ((rr = LIST_FIRST(&pub->pkt.arlist)) != NULL) {
			LIST_REMOVE(rr, entry);
			pub->pkt.arcount--;
			free(rr);
		}
		while ((mq = LIST_FIRST(&pub->pkt.qlist)) != NULL) {
			LIST_REMOVE(mq, entry);
			pub->pkt.qdcount--;
			free(mq);
		}
		free(pub);
		break;
	default:
		fatalx("Unknown publish state, report this");
		break;
	}
}

struct mdns_rr *
publish_lookupall(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct iface	*iface;
	struct mdns_rr	*rr;
	
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		rr = rrt_lookup(&iface->rrt, dname, type, class);
		if (rr != NULL)
			return rr;
	}
	
	return NULL;
}
