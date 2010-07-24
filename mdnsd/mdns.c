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
#include <err.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "mdnsd.h"
#include "log.h"

#define INTERVAL_PROBETIME	250000
#define RANDOM_PROBETIME	arc4random_uniform((u_int32_t) 250000)
#define MAX_QUERYTIME		(60 * 60) /* one hour */

struct query_node {
	RB_ENTRY(query_node)	entry;
	struct query		q;
};

static void	publish_fsm(int, short, void *_pub);

static int	cache_insert(struct rr *);
static int	cache_delete(struct rr *);
static void	cache_schedrev(struct rr *);
static void	cache_rev(int, short, void *);

void			 rrt_dump(struct rrt_tree *);
static int		 rrt_compare(struct rrt_node *, struct rrt_node *);
static struct rr	*rrt_lookup(struct rrt_tree *, char [MAXHOSTNAMELEN],
    u_int16_t, u_int16_t);
static struct rr_head	*rrt_lookup_head(struct rrt_tree *,
    char [MAXHOSTNAMELEN],  u_int16_t, u_int16_t);
static struct rrt_node	*rrt_lookup_node(struct rrt_tree *,
    char [MAXHOSTNAMELEN], u_int16_t, u_int16_t);

static int	query_node_compare(struct query_node *, struct query_node *);
static void	query_fsm(int, short, void *);
static struct query_node *query_lookup_node(char [MAXHOSTNAMELEN], u_int16_t,
    u_int16_t);

RB_GENERATE(rrt_tree,  rrt_node, entry, rrt_compare);

RB_HEAD(query_tree, query_node);
RB_PROTOTYPE(query_tree, query_node, entry, query_node_compare)
RB_GENERATE(query_tree, query_node, entry, query_node_compare)

extern struct mdnsd_conf	*conf;
static struct query_tree	 qtree;
static struct rrt_tree		 rrt_cache;

/*
 * Publishing
 */

void
publish_init(void)
{
	struct iface	*iface;
	struct rr	*rr;
	char		 revaddr[MAXHOSTNAMELEN];

	/* init probing list used in name conflicts */
	LIST_INIT(&probing_list);

	/* insert default records in all our interfaces */
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		/* myname */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		rr_set(rr, conf->myname, T_A, C_IN, TTL_HNAME, 1,
		    &iface->addr, sizeof(iface->addr));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");

		/* publish reverse address */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		reversstr(revaddr, &iface->addr);
		rr_set(rr, revaddr, T_PTR, C_IN, TTL_HNAME, 1,
		    conf->myname, sizeof(conf->myname));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");

		/* publish hinfo */
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			fatal("calloc");
		rr_set(rr, conf->myname, T_HINFO, C_IN, TTL_HNAME, 1,
		    &conf->hi, sizeof(conf->hi));
		if (publish_insert(iface, rr) == -1)
			log_debug("publish_init: can't insert rr");
	}
}

void
publish_allrr(struct iface *iface)
{
	struct question		*mq;
	struct rr		*rr, *rrcopy;
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
	question_set(mq, conf->myname, T_ANY, C_IN, 1);
	pkt_add_question(&pub->pkt, mq);

	RB_FOREACH(n, rrt_tree, &iface->rrt) {
		/* now go through all our rr and add to the same packet */
		LIST_FOREACH(rr, &n->hrr, centry) {
			if ((rrcopy = calloc(1, sizeof(struct rr))) == NULL)
				fatal("calloc");
			memcpy(rrcopy, rr, sizeof(struct rr));
			pkt_add_nsrr(&pub->pkt, rrcopy);
		}
	}

	timerclear(&tv);
	tv.tv_usec = RANDOM_PROBETIME;
	evtimer_set(&pub->timer, publish_fsm, pub);
	evtimer_add(&pub->timer, &tv);
}

int
publish_delete(struct iface *iface, struct rr *rr)
{
	struct rr	*rraux, *next;
	struct rrt_node	*s;
	int		 n = 0;

	log_debug("publish_delete: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	s = rrt_lookup_node(&iface->rrt, rr->dname, rr->type, rr->class);
	if (s == NULL)
		return (0);

	for (rraux = LIST_FIRST(&s->hrr); rraux != NULL; rraux = next) {
		next = LIST_NEXT(rraux, centry);
		if (RR_UNIQ(rr) || /* XXX: Revise this */
		    (rr_rdata_cmp(rr, rraux) == 0)) {
			LIST_REMOVE(rraux, centry);
			free(rraux);
			n++;
		}
	}

	if (LIST_EMPTY(&s->hrr)) {
		RB_REMOVE(rrt_tree, &iface->rrt, s);
		free(s);
	}

	return (n);
}

int
publish_insert(struct iface *iface, struct rr *rr)
{
	struct rr_head	*hrr;
	struct rrt_node *n;
	struct rr	*rraux;

	log_debug("publish_insert: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);

	hrr = rrt_lookup_head(&iface->rrt, rr->dname, rr->type, rr->class);
	if (hrr == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");

		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, centry);
		if (RB_INSERT(rrt_tree, &iface->rrt, n) != NULL)
			fatal("rrt_insert: RB_INSERT");

		return (0);
	}

	/* if an unique record, clean all previous and substitute */
	if (RR_UNIQ(rr)) {
		while ((rraux = LIST_FIRST(hrr)) != NULL) {
			LIST_REMOVE(rraux, centry);
			free(rraux);
		}
		LIST_INSERT_HEAD(hrr, rr, centry);

		return (0);
	}

	/* not unique, just add */
	LIST_INSERT_HEAD(hrr, rr, centry);

	return (0);
}

/* XXX: if query type is ANY, won't match. */
struct rr *
publish_lookupall(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct iface	*iface;
	struct rr	*rr;

	LIST_FOREACH(iface, &conf->iface_list, entry) {
		rr = rrt_lookup(&iface->rrt, dname, type, class);
		if (rr != NULL)
			return (rr);
	}

	return (NULL);
}

static void
publish_fsm(int unused, short event, void *v_pub)
{
	struct publish		*pub = v_pub;
	struct timeval		 tv;
	struct rr		*rr;
	struct question		*mq;
	static unsigned long	pubid;
	
	timerclear(&tv);
	switch (pub->state) {
	case PUB_INITIAL:
		pub->state = PUB_PROBE;
		pub->id = ++pubid;
		/* Register probing in our probing list so we can deal with
		 * name conflicts */
		LIST_INSERT_HEAD(&probing_list, pub, entry);
		/* FALLTHROUGH */
	case PUB_PROBE:
		pub->pkt.h.qr = 0;
		if (pkt_send_allif(&pub->pkt) == -1)
			log_debug("can't send packet to all interfaces");
		pub->sent++;
		if (pub->sent == 3) { /* enough probing, start announcing */
			/* cool, so now that we're done, remove it from
			 * probing list, now the record is ours. */
			LIST_REMOVE(pub, entry);
			pub->state  = PUB_ANNOUNCE;
			pub->sent   = 0;
			pub->pkt.h.qr = 1;
			/* remove questions */
			while ((mq = (LIST_FIRST(&pub->pkt.qlist))) != NULL) {
				LIST_REMOVE(mq, entry);
				pub->pkt.h.qdcount--;
				free(mq);
			}
			/* move all ns records to answer records */
			while ((rr = (LIST_FIRST(&pub->pkt.nslist))) != NULL) {
				LIST_REMOVE(rr, pentry);
				pub->pkt.h.nscount--;
				if (pkt_add_anrr(&pub->pkt, rr) == -1)
					log_debug("publish_fsm: "
					    "pkt_add_anrr failed");
			}
			publish_fsm(unused, event, pub);
			return;
		}
		tv.tv_usec = INTERVAL_PROBETIME;
		evtimer_add(&pub->timer, &tv);
		break;
	case PUB_ANNOUNCE:
		if (pkt_send_allif(&pub->pkt) == -1)
			log_debug("can't send packet to all interfaces");
		pub->sent++;
		if (pub->sent < 3) {
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
			LIST_REMOVE(rr, pentry);
			pub->pkt.h.ancount--;
			free(rr);
		}
		while ((rr = LIST_FIRST(&pub->pkt.nslist)) != NULL) {
			LIST_REMOVE(rr, pentry);
			pub->pkt.h.nscount--;
			free(rr);
		}
		while ((rr = LIST_FIRST(&pub->pkt.arlist)) != NULL) {
			LIST_REMOVE(rr, pentry);
			pub->pkt.h.arcount--;
			free(rr);
		}
		while ((mq = LIST_FIRST(&pub->pkt.qlist)) != NULL) {
			LIST_REMOVE(mq, entry);
			pub->pkt.h.qdcount--;
			free(mq);
		}
		free(pub);
		break;
	default:
		fatalx("Unknown publish state, report this");
		break;
	}
}

/*
 * RR cache
 */

void
cache_init(void)
{
#ifdef DUMMY_ENTRIES
	char **nptr;
	struct rr *rr;
	char *tnames[] = {
		"teste1.local",
		"teste2.local",
		"teste3.local",
		"teste4.local",
		"teste5.local",
		"teste6.local",
		"teste7.local",
		"teste8.local",
		"teste9.local",
		"teste10.local",
		"teste11.local",
		"teste12.local",
		"teste13.local",
		"teste14.local",
		"teste15.local",
		"teste16.local",
		"teste17.local",
		"teste18.local",
		"teste19.local",
		"teste20.local",
		"teste21.local",
		"teste22.local",
		"teste23.local",
		"teste24.local",
		"teste25.local",
		"teste26.local",
		"teste27.local",
		"teste28.local",
		"teste29.local",
		"teste30.local",
		"teste31.local",
		"teste32.local",
		"teste33.local",
		"teste34.local",
		"teste35.local",
		"teste36.local",
		"teste37.local",
		"teste38.local",
		"teste39.local",
		"teste40.local",
		"teste41.local",
		"teste42.local",
		"teste43.local",
		"teste44.local",
		"teste45.local",
		"teste46.local",
		"teste47.local",
		"teste48.local",
		"teste49.local",
		"teste50.local",
		0
	};
#endif
	RB_INIT(&rrt_cache);
#ifdef DUMMY_ENTRIES
	for (nptr = tnames; *nptr != NULL; nptr++) {
		if ((rr = calloc(1, sizeof(*rr))) == NULL)
			err(1, "calloc");
		strlcpy(rr->dname, "_http._tcp.local", sizeof(rr->dname));
		rr->type = T_PTR;
		rr->class = C_IN;
		rr->ttl = 60;
		strlcpy(rr->rdata.PTR, *nptr, sizeof(rr->rdata.PTR));
		rr->rdlen = strlen(*nptr);
		evtimer_set(&rr->rev_timer, cache_rev, rr);
		cache_insert(rr);

	}

#endif

}

int
cache_process(struct rr *rr)
{
	evtimer_set(&rr->rev_timer, cache_rev, rr);
	if (rr->ttl == 0)
		return (cache_delete(rr));
	if (cache_insert(rr) == -1)
		return (-1);

	return (0);
}

struct rr *
cache_lookup(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	return (rrt_lookup(&rrt_cache, dname, type, class));
}

static int
cache_insert(struct rr *rr)
{
	struct rr_head	*hrr;
	struct rrt_node *n;
	struct rr	*rraux;

/* 	log_debug("cache_insert: type: %s name: %s", rr_type_name(rr->type), */
/* 	    rr->dname); */

	hrr = rrt_lookup_head(&rrt_cache, rr->dname, rr->type, rr->class);
	if (hrr == NULL) {
		if ((n = calloc(1, sizeof(*n))) == NULL)
			fatal("calloc");

		LIST_INIT(&n->hrr);
		LIST_INSERT_HEAD(&n->hrr, rr, centry);
		if (RB_INSERT(rrt_tree, &rrt_cache, n) != NULL)
			fatal("rrt_insert: RB_INSERT");
		cache_schedrev(rr);
		query_notify(rr, 1);

		return (0);
	}

	/* if an unique record, clean all previous and substitute */
	if (RR_UNIQ(rr)) {
		while ((rraux = LIST_FIRST(hrr)) != NULL) {
			LIST_REMOVE(rraux, centry);
			if (evtimer_pending(&rraux->rev_timer, NULL))
				evtimer_del(&rraux->rev_timer);
			free(rraux);
		}
		LIST_INSERT_HEAD(hrr, rr, centry);
		cache_schedrev(rr);
		query_notify(rr, 1);

		return (0);
	}

	/* rr is not unique, see if this is a cache refresh */
	LIST_FOREACH(rraux, hrr, centry) {
		if (rr_rdata_cmp(rr, rraux) == 0) {
			rraux->ttl = rr->ttl;
			rraux->revision = 0;
			cache_schedrev(rraux);
			free(rr);

			return (0);
		}
	}

	/* not a refresh, so add */
	LIST_INSERT_HEAD(hrr, rr, centry);
	query_notify(rr, 1);
	cache_schedrev(rr);
	/* XXX: should we cache_schedrev ? */

	return (0);
}

static int
cache_delete(struct rr *rr)
{
	struct rr	*rraux, *next;
	struct rrt_node	*s;
	int		 n = 0;

	log_debug("cache_delete: type: %s name: %s", rr_type_name(rr->type),
	    rr->dname);
	s = rrt_lookup_node(&rrt_cache, rr->dname, rr->type, rr->class);
	query_notify(rr, 0);
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
		RB_REMOVE(rrt_tree, &rrt_cache, s);
		free(s);
	}

	return (n);
}

static void
cache_schedrev(struct rr *rr)
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

/* 	log_debug("cache_schedrev: schedule rr type: %s, name: %s (%d)", */
/* 	    rr_type_name(rr->type), rr->dname, tv.tv_sec); */

	rr->revision++;

	if (evtimer_pending(&rr->rev_timer, NULL))
		evtimer_del(&rr->rev_timer);
	if (evtimer_add(&rr->rev_timer, &tv) == -1)
		fatal("rrt_sched_rev");
}

static void
cache_rev(int unused, short event, void *v_rr)
{
	struct rr	*rr = v_rr;
	struct query	*q;
	struct pkt	 pkt;

	log_debug("cache_rev: timeout rr type: %s, name: %s (%u)",
	    rr_type_name(rr->type), rr->dname, rr->ttl);

	/* If we have an active query, try to renew the answer */
	if ((q = query_lookup(rr->dname, rr->type, rr->class)) != NULL) {
		pkt_init(&pkt);
		pkt_add_question(&pkt, &q->mq);
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
		    log_debug_rrdata(rr);
	}
}

static struct rr_head *
rrt_lookup_head(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN],
    u_int16_t type, u_int16_t class)
{
	struct rrt_node	*tmp;

	tmp = rrt_lookup_node(rrt, dname, type, class);
	if (tmp == NULL)
		return (NULL);

	return (&tmp->hrr);
}

static struct rr *
rrt_lookup(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rr_head	*hrr;

	hrr = rrt_lookup_head(rrt, dname, type, class);
	if (hrr)
		return (LIST_FIRST(hrr));
	return (NULL);
}

static struct rrt_node *
rrt_lookup_node(struct rrt_tree *rrt, char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct rrt_node	s, *tmp;
	struct rr	rr;

	bzero(&s, sizeof(s));
	bzero(&rr, sizeof(rr));
	rr.type	 = type;
	rr.class = class;
	strlcpy(rr.dname, (const char *)dname, MAXHOSTNAMELEN);

	LIST_INIT(&s.hrr);
	LIST_INSERT_HEAD(&s.hrr, &rr, centry);

	tmp = RB_FIND(rrt_tree, rrt, &s);
	if (tmp == NULL)
		return (NULL);

	return (tmp);
}

static int
rrt_compare(struct rrt_node *a, struct rrt_node *b)
{
	struct rr *rra, *rrb;

	rra = LIST_FIRST(&a->hrr);
	rrb = LIST_FIRST(&b->hrr);

	if (rra->class < rrb->class)
		return (-1);
	if (rra->class > rrb->class)
		return (1);
	if (rra->type < rrb->type)
		return (-1);
	if (rra->type > rrb->type)
		return (1);

	return (strcmp(rra->dname, rrb->dname));
}

/*
 * Querier
 */

void
query_init(void)
{
	RB_INIT(&qtree);
}

struct query *
query_lookup(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct query_node *qn;

	qn = query_lookup_node(dname, type, class);
	if (qn != NULL)
		return (&qn->q);
	return (NULL);
}

struct query *
query_place(int s, char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct query		*q;
	struct query_node	*qn;

	q = query_lookup(dname, type, class);
	/* existing query, increase active */
	if (q != NULL) {
		if (s != q->style) {
			log_warnx("trying to change a query style");
			return (NULL);
		}
		q->active++;
		log_debug("existing query active = %d", q->active);
		return (q);
	}
	/* no query, make a new one */
	log_debug("making new query");
	if ((qn = calloc(1, sizeof(*qn))) == NULL)
		fatal("calloc");
	q = &qn->q;
	question_set(&q->mq, dname, type, class, 0);
	q->style = s;
	q->active++;
	if (RB_INSERT(query_tree, &qtree, qn) != NULL)
		fatal("query_place: RB_INSERT");
	/* start the sending machine */
	event_once(-1, EV_TIMEOUT, query_fsm, q, NULL); /* THIS IS PROBABLY WRONG */
	return (q);
}

void
query_remove(struct query *qrem)
{
	struct query *qfound;
	struct query_node *qn;

	qn = query_lookup_node(qrem->mq.dname, qrem->mq.qtype, qrem->mq.qclass);
	if (qn == NULL)
		return;
	qfound = &qn->q;
	if (--qfound->active == 0) {
		RB_REMOVE(query_tree, &qtree, qn);
		if (evtimer_pending(&qn->q.timer, NULL))
			evtimer_del(&qn->q.timer);
		free(qn);
	}
}

/* RR in/out, 1 = in, 0 = out */
int
query_notify(struct rr *rr, int in)
{
	struct ctl_conn *c;
	struct query	*q;
	int		 tosee;
	int		 msgtype;

	q = query_lookup(rr->dname, rr->type, rr->class);
	if (q == NULL)
		return (0);
	/* try to answer the controllers */
	tosee = q->active;
	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (!tosee)
			break;
		if (!control_hasq(c, q))
			continue;
		/* sanity check */
		if (!ANSWERS(&q->mq, rr)) {
			log_warnx("Bogus pointer, report me");
			return (0);
		}
		/* notify controller */
		switch (q->style) {
		case QUERY_LKUP:
			msgtype = IMSG_CTL_LOOKUP;
			break;
		case QUERY_BROWSE:
			msgtype = in ? IMSG_CTL_BROWSE_ADD
			    : IMSG_CTL_BROWSE_DEL;
			break;
		default:
			log_warnx("Unknown query style");
			return (-1);
		}
		if (query_answerctl(c, rr, msgtype) == -1)
			log_warnx("Query_answerctl error");
	}

	/* number of notified controllers */
	return (q->active - tosee);
}

int
query_answerctl(struct ctl_conn *c, struct rr *rr, int msgtype)
{
	log_debug("query_answerctl (%s) %s", rr_type_name(rr->type),
	    rr->dname);
	switch (rr->type) {
	case T_A:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.A, sizeof(rr->rdata.A));
		break;
	case T_PTR:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.PTR, sizeof(rr->rdata.PTR));
		break;
	case T_HINFO:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.HINFO, sizeof(rr->rdata.HINFO));
		break;
	case T_SRV:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.SRV, sizeof(rr->rdata.SRV));
		break;
	case T_TXT:
		mdnsd_imsg_compose_ctl(c, msgtype,
		    &rr->rdata.TXT, sizeof(rr->rdata.TXT));
		break;
	default:
		log_warnx("Unknown question type, report this");
		return (-1);
		break;		/* NOTREACHED */
	}

	return (0);
}

static void
query_fsm(int unused, short event, void *v_query)
{
	struct pkt	 pkt;
	struct timeval	 tv;
	struct query	*q;
	struct rr	*rr;

	q = v_query;
	pkt_init(&pkt);
	pkt_add_question(&pkt, &q->mq);

	if (q->style == QUERY_BROWSE) {
		/* This will send at seconds 0, 1, 2, 4, 8, 16... */
		if (!q->sleep)
			q->sleep = 1;
		else
			q->sleep = q->sleep * 2;
		if (q->sleep > MAX_QUERYTIME)
			q->sleep = MAX_QUERYTIME;
		timerclear(&tv);
		tv.tv_sec = q->sleep;
		evtimer_set(&q->timer, query_fsm, q);
		evtimer_add(&q->timer, &tv);

		/* Known Answer Supression */
		for (rr = cache_lookup(q->mq.dname, q->mq.qtype, q->mq.qclass);
		     rr != NULL; rr = LIST_NEXT(rr, centry))
			if (pkt_add_arrr(&pkt, rr) == -1)
				log_warnx("KNA error pkt_add_arrr: %s", rr->dname);
	}

	if (pkt_send_allif(&pkt) == -1)
		log_warnx("can't send packet to all interfaces");
	q->sleep++;
}

static int
query_node_compare(struct query_node *a, struct query_node *b)
{
	if (a->q.mq.qtype < b->q.mq.qtype)
		return (-1);
	if (a->q.mq.qtype > b->q.mq.qtype)
		return (1);
	if (a->q.mq.qclass < b->q.mq.qclass)
		return (-1);
	if (a->q.mq.qclass > b->q.mq.qclass)
		return (1);
	return (strcmp(a->q.mq.dname, b->q.mq.dname));
}

static struct query_node *
query_lookup_node(char dname[MAXHOSTNAMELEN], u_int16_t type, u_int16_t class)
{
	struct query_node qn;

	bzero(&qn, sizeof(qn));
	question_set(&qn.q.mq, dname, type, class, 0);

	return (RB_FIND(query_tree, &qtree, &qn));
}
