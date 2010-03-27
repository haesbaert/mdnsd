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

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdnsd.h"
#include "log.h"
#include "control.h"

#define	CONTROL_BACKLOG	5

struct ctl_conn	*control_connbyfd(int);
struct ctl_conn	*control_connbypid(pid_t);
void		 control_close(int);
static void	 control_lookup(struct ctl_conn *, struct imsg *);
static void	 control_lookupaddr(struct ctl_conn *, struct imsg *);
static void	 control_lookuphinfo(struct ctl_conn *, struct imsg *);

static void
control_lookup(struct ctl_conn *c, struct imsg *imsg)
{
	struct pkt		 pkt;
	struct rr		*rr;
	struct question 	*mq;
	char			 hostname[MAXHOSTNAMELEN];
	
	if ((imsg->hdr.len - IMSG_HEADER_SIZE) != sizeof(hostname))
		return;

	memcpy(hostname, imsg->data, sizeof(hostname));
	log_debug("looking up %s (A)", hostname);
	rr = cache_lookup(hostname, T_A, C_IN);
	/* cache hit */
	if (rr != NULL) {
		log_debug("hostname %s: %s", hostname, inet_ntoa(rr->rdata.A));
		mdnsd_imsg_compose_ctl(c, imsg->hdr.type,
		    &rr->rdata.A, sizeof(rr->rdata.A));
		return;
	}
	/* cache miss */
	if ((mq = calloc(1, sizeof(*mq))) == NULL)
		fatal("calloc");
	question_set(mq, hostname, T_A, C_IN, 0, 0);
	pkt_init(&pkt);
	pkt_add_question(&pkt, mq);
	if (pkt_send_allif(&pkt) == -1)
		log_debug("can't send packet to all interfaces");
	c->q = query_place(QUERY_LOOKUP, mq, c);
}

static void
control_lookupaddr(struct ctl_conn *c, struct imsg *imsg)
{
	struct rr		*rr;
	struct pkt		 pkt;
	struct question 	*mq;
	struct in_addr		 addr;
	char			 name[MAXHOSTNAMELEN];
	
	if ((imsg->hdr.len - IMSG_HEADER_SIZE) != sizeof(struct in_addr))
		return;

	memcpy(&addr, imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE);
	reversstr(name, &addr);
	rr = cache_lookup(name, T_PTR, C_IN);
	/* cache hit */
	if (rr != NULL) {
		log_debug("PTR name %s: %s", rr->rdata.PTR, inet_ntoa(rr->rdata.A));
		mdnsd_imsg_compose_ctl(c, imsg->hdr.type,
		    &rr->rdata.PTR, sizeof(rr->rdata.PTR));
		return;
	}
	/* cache miss */
	if ((mq = calloc(1, sizeof(*mq))) == NULL)
		fatal("calloc");
	question_set(mq, name, T_PTR, C_IN, 0, 0);
	pkt_init(&pkt);
	pkt_add_question(&pkt, mq);
	if (pkt_send_allif(&pkt) == -1)
		log_debug("can't send packet to all interfaces");
	c->q = query_place(QUERY_LOOKUP_ADDR, mq, c);
}

static void
control_lookuphinfo(struct ctl_conn *c, struct imsg *imsg)
{
	struct pkt		 pkt;
	struct rr		*rr;
	struct question 	*mq;
	char			 hostname[MAXHOSTNAMELEN];
	
	if ((imsg->hdr.len - IMSG_HEADER_SIZE) != sizeof(hostname))
		return;

	memcpy(hostname, imsg->data, sizeof(hostname));
	rr = cache_lookup(hostname, T_HINFO, C_IN);
	/* cache hit */
	if (rr != NULL) {
		mdnsd_imsg_compose_ctl(c, IMSG_CTL_LOOKUP_HINFO,
		    &rr->rdata.HINFO, sizeof(rr->rdata.HINFO));
		return;
	}
	/* cache miss */
	if ((mq = calloc(1, sizeof(*mq))) == NULL)
		fatal("calloc");
	question_set(mq, hostname, T_HINFO, C_IN, 0, 0);
	pkt_init(&pkt);
	pkt_add_question(&pkt, mq);
	if (pkt_send_allif(&pkt) == -1)
		log_debug("can't send packet to all interfaces");
	c->q = query_place(QUERY_LOOKUP_HINFO, mq, c);
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

/* ARGSUSED */
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

	if ((c = malloc(sizeof(struct ctl_conn))) == NULL) {
		log_warn("control_accept");
		close(connfd);
		return;
	}

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
	
	if ((c = control_connbyfd(fd)) == NULL) {
		log_warn("control_close: fd %d: not found", fd);
		return;
	}
	msgbuf_clear(&c->iev.ibuf.w);
	TAILQ_REMOVE(&ctl_conns, c, entry);

	event_del(&c->iev.ev);
	close(c->iev.ibuf.fd);
	query_cleanbyconn(c);
	free(c);
}

void
control_dispatch_imsg(int fd, short event, void *bula)
{
	struct ctl_conn	*c;
	struct imsg	 imsg;
	ssize_t		 n;
	
	log_debug("control_dispatch_imsg");
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
		case IMSG_CTL_LOOKUP_ADDR:
			control_lookupaddr(c, &imsg);
			break;
		case IMSG_CTL_LOOKUP_HINFO:
			control_lookuphinfo(c, &imsg);
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

