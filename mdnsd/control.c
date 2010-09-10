/*
 * Copyright (c) 2010 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdnsd.h"
#include "mdns.h"
#include "log.h"
#include "control.h"

#define	CONTROL_BACKLOG	5

struct ctl_conn	*control_connbyfd(int);
struct ctl_conn	*control_connbypid(pid_t);
void		 control_close(int);
void		 control_lookup(struct ctl_conn *, struct imsg *);
void		 control_browse_add(struct ctl_conn *, struct imsg *);
void		 control_browse_del(struct ctl_conn *, struct imsg *);
void		 control_resolve(struct ctl_conn *, struct imsg *);

void
control_lookup(struct ctl_conn *c, struct imsg *imsg)
{
	struct rrset	 mlkup, *rrs;
	struct rr	*rr;
	struct query 	*q;
	struct timeval	 tv;

	if ((imsg->hdr.len - IMSG_HEADER_SIZE) != sizeof(mlkup))
		return;

	memcpy(&mlkup, imsg->data, sizeof(mlkup));
	mlkup.dname[MAXHOSTNAMELEN - 1] = '\0'; /* assure clients are nice */

	switch (mlkup.type) {
	case T_A:		/* FALLTHROUGH */
	case T_HINFO:		/* FALLTHROUGH */
	case T_PTR:		/* FALLTHROUGH */
	case T_SRV:		/* FALLTHROUGH */
	case T_TXT:		/* FALLTHROUGH */
		break;
	default:
		log_warnx("Lookup type %d not supported/implemented",
		    mlkup.type);
		return;
	}

	if (mlkup.class != C_IN) {
		log_warnx("Lookup class %d not supported/implemented",
		    mlkup.class);
		return;
	}
	
	/* Check if control has this query already, if so don't do anything */
	LIST_FOREACH(q, &c->qlist, entry) {
		if (q->style != QUERY_LOOKUP)
			continue;
		LIST_FOREACH(rrs, &q->rrslist, entry)
		    if (rrset_cmp(rrs, &mlkup) == 0) {
			    log_debug("control already querying for %s",
				rrs_str(rrs));
			    return;
		    }
	}

	log_debug("looking up %s (%s %d)", mlkup.dname, rr_type_name(mlkup.type),
	    mlkup.class);

	rr = cache_lookup(&mlkup);
	/* cache hit */
	if (rr != NULL) {
		if (control_send_rr(c, rr, IMSG_CTL_LOOKUP) == -1)
			log_warnx("query_answer error");
		return;
	}

	if (question_add(&mlkup) == NULL) {
		log_warnx("Can't add question for %s (%s)", rrs_str(&mlkup));
		return;
	}
	
	/* cache miss */
	if ((q = calloc(1, sizeof(*q))) == NULL)
		fatal("calloc");
	if ((rrs = calloc(1, sizeof(*rrs))) == NULL)
		fatal("calloc");
	LIST_INIT(&q->rrslist);
	q->style = QUERY_LOOKUP;
	q->ctl = c;
	*rrs = mlkup;
	LIST_INSERT_HEAD(&q->rrslist, rrs, entry);
	LIST_INSERT_HEAD(&c->qlist, q, entry);
	timerclear(&tv);
	tv.tv_usec = FIRST_QUERYTIME;
	evtimer_set(&q->timer, query_fsm, q);
	evtimer_add(&q->timer, &tv);
}

void
control_browse_add(struct ctl_conn *c, struct imsg *imsg)
{
	struct rrset	 mlkup, *rrs;
	struct rr	*rr;
	struct query 	*q;
	struct timeval	 tv;

	if ((imsg->hdr.len - IMSG_HEADER_SIZE) != sizeof(mlkup))
		return;

	memcpy(&mlkup, imsg->data, sizeof(mlkup));
	mlkup.dname[MAXHOSTNAMELEN - 1] = '\0'; /* assure clients were nice */

	if (mlkup.type != T_PTR) {
		log_warnx("Browse type %d not supported/implemented",
		    mlkup.type);
		return;
	}

	if (mlkup.class != C_IN) {
		log_warnx("Browse class %d not supported/implemented",
		    mlkup.class);
		return;
	}
	
	/* Check if control has this query already, if so don't do anything */
	LIST_FOREACH(q, &c->qlist, entry) {
		if (q->style != QUERY_BROWSE)
			continue;
		LIST_FOREACH(rrs, &q->rrslist, entry)
		    if (rrset_cmp(rrs, &mlkup) == 0) {
			    log_debug("control already querying for %s",
				rrs_str(rrs));
			    return;
		    }
	}
	
	log_debug("Browse add %s (%s %d)", mlkup.dname, rr_type_name(mlkup.type),
	    mlkup.class);

	rr = cache_lookup(&mlkup);
	while (rr != NULL) {
		if (control_send_rr(c, rr, IMSG_CTL_BROWSE_ADD) == -1)
			log_warnx("control_send_rr error");
		rr = LIST_NEXT(rr, centry);
	}

	if (question_add(&mlkup) == NULL) {
		log_warnx("Can't add question for %s", rrs_str(&mlkup));
		return;
	}
	
	if ((q = calloc(1, sizeof(*q))) == NULL)
		fatal("calloc");
	if ((rrs = calloc(1, sizeof(*rrs))) == NULL)
		fatal("calloc");
	LIST_INIT(&q->rrslist);
	q->style = QUERY_BROWSE;
	q->ctl = c;
	*rrs = mlkup;
	LIST_INSERT_HEAD(&q->rrslist, rrs, entry);
	LIST_INSERT_HEAD(&c->qlist, q, entry);
	timerclear(&tv);
	tv.tv_usec = FIRST_QUERYTIME;
	evtimer_set(&q->timer, query_fsm, q);
	evtimer_add(&q->timer, &tv);
}

void
control_browse_del(struct ctl_conn *c, struct imsg *imsg)
{
/* 	struct rrset	 mlkup; */
/* 	struct query 	*q; */

/* 	if ((imsg->hdr.len - IMSG_HEADER_SIZE) != sizeof(mlkup)) */
/* 		return; */

/* 	memcpy(&mlkup, imsg->data, sizeof(mlkup)); */
/* 	mlkup.dname[MAXHOSTNAMELEN - 1] = '\0'; /\* assure clients were nice *\/ */

/* 	if (mlkup.type != T_PTR) { */
/* 		log_warnx("Browse type %d not supported/implemented", */
/* 		    mlkup.type); */
/* 		return; */
/* 	} */

/* 	if (mlkup.class != C_IN) { */
/* 		log_warnx("Browse class %d not supported/implemented", */
/* 		    mlkup.class); */
/* 		return; */
/* 	} */
/* 	q = query_lookup(&mlkup); */
/* 	if (q != NULL) */
/* 		control_remq(c, q); */
}	

void
control_resolve(struct ctl_conn *c, struct imsg *imsg)
{
	char			 msg[MAXHOSTNAMELEN];
	struct rrset		 *rrs_srv, *rrs_txt, *rrs_a, *rrs_aux;
	struct rr		*srv_cache;
	struct query		*q;
	struct timeval		 tv;
	
	if ((imsg->hdr.len - IMSG_HEADER_SIZE) != sizeof(msg)) {
		log_warnx("control_resolve: Invalid msg len");
		return;
	}

	memcpy(msg, imsg->data, sizeof(msg));
	msg[sizeof(msg) - 1] = '\0';
	
	/* Check if control has this query already, if so don't do anything */
	LIST_FOREACH(q, &c->qlist, entry) {
		if (q->style != QUERY_RESOLVE)
			continue;
		if (strcmp(msg, q->ms_srv->dname) == 0) {
			log_debug("control already resolving %s",
			    q->ms_srv->dname);
			return;
		}
	}
	
	log_debug("Resolve %s", msg);
	
	/*
	 * Try get answer with our cache entries
	 */
	if (control_try_answer_ms(c, msg) == 1) {
		log_debug("Resolve for %s all in cache", msg);
		return;
	}
	
	/*
	 * If we got here we need to make a query.
	 */
	if ((q = calloc(1, sizeof(*q))) == NULL)
		fatal("calloc");
	LIST_INSERT_HEAD(&c->qlist, q, entry);
	LIST_INIT(&q->rrslist);
	q->style = QUERY_RESOLVE;
	q->ctl = c;
	timerclear(&tv);
	tv.tv_usec = FIRST_QUERYTIME;
	evtimer_set(&q->timer, query_fsm, q);
	evtimer_add(&q->timer, &tv);
	
	if ((rrs_srv = calloc(1, sizeof(*rrs_srv))) == NULL)
		err(1, "calloc");
	if ((rrs_txt = calloc(1, sizeof(*rrs_txt))) == NULL)
		err(1, "calloc");
	
	if (strlcpy(rrs_srv->dname, msg, sizeof(rrs_srv->dname)) >=
	    sizeof(rrs_srv->dname)) {
		log_warnx("control_resolve: msg too long, dropping");
		free(rrs_srv);
		free(rrs_txt);
		return;
	}
	rrs_srv->class = C_IN;
	rrs_srv->type  = T_SRV;
	strlcpy(rrs_txt->dname, msg, sizeof(rrs_txt->dname));
	rrs_txt->class = C_IN;
	rrs_txt->type = T_TXT;
	q->ms_srv = rrs_srv;
	LIST_INSERT_HEAD(&q->rrslist, rrs_srv, entry);
	LIST_INSERT_HEAD(&q->rrslist, rrs_txt, entry);
	if ((srv_cache = cache_lookup(rrs_srv)) != NULL) {
		if ((rrs_a = calloc(1, sizeof(*rrs_a))) == NULL)
			err(1, "calloc");
		strlcpy(rrs_a->dname, srv_cache->rdata.SRV.dname,
		    sizeof(rrs_a->dname));
		rrs_a->class = C_IN;
		rrs_a->type = T_A;
		LIST_INSERT_HEAD(&q->rrslist, rrs_a, entry);
	}
	
	LIST_FOREACH(rrs_aux, &q->rrslist, entry) {
		if (question_add(rrs_aux) == NULL) {
			log_warnx("control_resolve: question_add error");
			query_remove(q);
			return;
		}
	}
}

int
control_init(void)
{
	struct sockaddr_un	 sun;
	int			 fd;
	mode_t			 old_umask;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		log_warn("control_init: socket");
		return (-1);
	}

	bzero(&sun, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, MDNSD_SOCKET, sizeof(sun.sun_path));

	if (unlink(MDNSD_SOCKET) == -1)
		if (errno != ENOENT) {
			log_warn("control_init: unlink %s", MDNSD_SOCKET);
			close(fd);
			return (-1);
		}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		log_warn("control_init: bind: %s", MDNSD_SOCKET);
		close(fd);
		umask(old_umask);
		return (-1);
	}
	umask(old_umask);

	if (chmod(MDNSD_SOCKET, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) == -1) {
		log_warn("control_init: chmod");
		close(fd);
		(void)unlink(MDNSD_SOCKET);
		return (-1);
	}

	session_socket_blockmode(fd, BM_NONBLOCK);
	control_state.fd = fd;

	return (0);
}

int
control_listen(void)
{

	if (listen(control_state.fd, CONTROL_BACKLOG) == -1) {
		log_warn("control_listen: listen");
		return (-1);
	}

	event_set(&control_state.ev, control_state.fd, EV_READ | EV_PERSIST,
	    control_accept, NULL);
	event_add(&control_state.ev, NULL);

	return (0);
}

void
control_cleanup(void)
{
	unlink(MDNSD_SOCKET);
}

void
control_accept(int listenfd, short event, void *bula)
{
	int			 connfd;
	socklen_t		 len;
	struct sockaddr_un	 sun;
	struct ctl_conn		*c;

	len = sizeof(sun);
	if ((connfd = accept(listenfd,
	    (struct sockaddr *)&sun, &len)) == -1) {
		if (errno != EWOULDBLOCK && errno != EINTR)
			log_warn("control_accept: accept");
		return;
	}

	session_socket_blockmode(connfd, BM_NONBLOCK);

	if ((c = calloc(1, sizeof(struct ctl_conn))) == NULL) {
		log_warn("control_accept");
		close(connfd);
		return;
	}
	
	LIST_INIT(&c->qlist);
	imsg_init(&c->iev.ibuf, connfd);
	c->iev.handler = control_dispatch_imsg;
	c->iev.events = EV_READ;
	event_set(&c->iev.ev, c->iev.ibuf.fd, c->iev.events,
	    c->iev.handler, &c->iev);
	event_add(&c->iev.ev, NULL);

	TAILQ_INSERT_TAIL(&ctl_conns, c, entry);
}

struct ctl_conn *
control_connbyfd(int fd)
{
	struct ctl_conn	*c;

	for (c = TAILQ_FIRST(&ctl_conns); c != NULL && c->iev.ibuf.fd != fd;
	     c = TAILQ_NEXT(c, entry))
		;	/* nothing */

	return (c);
}

struct ctl_conn *
control_connbypid(pid_t pid)
{
	struct ctl_conn	*c;

	for (c = TAILQ_FIRST(&ctl_conns); c != NULL && c->iev.ibuf.pid != pid;
	     c = TAILQ_NEXT(c, entry))
		;	/* nothing */

	return (c);
}

void
control_close(int fd)
{
	struct ctl_conn	*c;
	struct query	*q;

	if ((c = control_connbyfd(fd)) == NULL) {
		log_warn("control_close: fd %d: not found", fd);
		return;
	}
	msgbuf_clear(&c->iev.ibuf.w);
	TAILQ_REMOVE(&ctl_conns, c, entry);

	event_del(&c->iev.ev);
	close(c->iev.ibuf.fd);
	while ((q = LIST_FIRST(&c->qlist)) != NULL)
		query_remove(q);
	free(c);
}

void
control_dispatch_imsg(int fd, short event, void *bula)
{
	struct ctl_conn	*c;
	struct imsg	 imsg;
	ssize_t		 n;

	if ((c = control_connbyfd(fd)) == NULL) {
		log_warn("control_dispatch_imsg: fd %d: not found", fd);
		return;
	}

	if (event & EV_READ) {
		if ((n = imsg_read(&c->iev.ibuf)) == -1 || n == 0) {
			control_close(fd);
			return;
		}
	}
	if (event & EV_WRITE) {
		if (msgbuf_write(&c->iev.ibuf.w) == -1) {
			control_close(fd);
			return;
		}
	}

	for (;;) {
		if ((n = imsg_get(&c->iev.ibuf, &imsg)) == -1) {
			control_close(fd);
			return;
		}

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_LOOKUP:
			control_lookup(c, &imsg);
			break;
		case IMSG_CTL_BROWSE_ADD:
			control_browse_add(c, &imsg);
			break;
		case IMSG_CTL_BROWSE_DEL:
			control_browse_del(c, &imsg);
			break;
		case IMSG_CTL_RESOLVE:
			control_resolve(c, &imsg);
			break;
		default:
			log_debug("control_dispatch_imsg: "
			    "error handling imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}

	imsg_event_add(&c->iev);
}

void
session_socket_blockmode(int fd, enum blockmodes bm)
{
	int	flags;

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl F_GETFL");

	if (bm == BM_NONBLOCK)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	if ((flags = fcntl(fd, F_SETFL, flags)) == -1)
		fatal("fcntl F_SETFL");
}

int
control_send_rr(struct ctl_conn *c, struct rr *rr, int msgtype)
{
	log_debug("control_send_rr (%s) %s", rr_type_name(rr->rrs.type),
	    rr->rrs.dname);
	
	return (mdnsd_imsg_compose_ctl(c, msgtype, rr, sizeof(*rr)));
}

int
control_send_ms(struct ctl_conn *c, struct mdns_service *ms, int msgtype)
{
	log_debug("control_send_ms");

	return (mdnsd_imsg_compose_ctl(c, msgtype, ms, sizeof(*ms)));
}

/*
 * 1 = Success, 0 = Fail
 */
int
control_try_answer_ms(struct ctl_conn *c, char dname[MAXHOSTNAMELEN])
{
	struct rr *srv, *txt, *a;
	struct rrset rrs;
	struct mdns_service ms;
	
	log_debug("control_try_answer_ms ");
	strlcpy(rrs.dname, dname, sizeof(rrs.dname));
	rrs.class = C_IN;
	rrs.type = T_SRV;
	if ((srv = cache_lookup(&rrs)) == NULL)
		return (0);
	rrs.type = T_TXT;
	if ((txt = cache_lookup(&rrs)) == NULL)
		return (0);
	strlcpy(rrs.dname, srv->rdata.SRV.dname, sizeof(rrs.dname));
	rrs.type = T_A;
	if ((a = cache_lookup(&rrs)) == NULL)
		return (0);
	
	bzero(&ms, sizeof(ms));
	strlcpy(ms.name, srv->rrs.dname, sizeof(ms.name));
	strlcpy(ms.txt, txt->rdata.TXT, sizeof(ms.txt));
	ms.priority = srv->rdata.SRV.priority;
	ms.weight = srv->rdata.SRV.weight;
	ms.port = srv->rdata.SRV.port;
	ms.addr = a->rdata.A;
	if (control_send_ms(c, &ms, IMSG_CTL_RESOLVE) == -1)
		log_warnx("control_send_ms error");
	
	return (1);
}
