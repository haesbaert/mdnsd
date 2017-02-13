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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <imsg.h>

#include "../mdnsd/mdnsd.h"
#include "mdns.h"

static int	mdns_connect(void);
static int 	mdns_lookup_do(struct mdns *, const char [MAXHOSTNAMELEN],
    u_int16_t, u_int16_t);
static int	ibuf_send_imsg(struct imsgbuf *, u_int32_t,
    void *, u_int16_t);
static int	splitdname(char [MAXHOSTNAMELEN], char [MAXHOSTNAMELEN],
    char [MAXLABEL], char [4], int *);
static int	imsgctl_to_event(int);

static int mdns_browse_adddel(struct mdns *, const char *, const char *, u_int);
static int mdns_handle_lookup(struct mdns *, struct rr *, int);
static int mdns_handle_browse(struct mdns *, struct rr *, int);
static int mdns_handle_resolve(struct mdns *, struct mdns_service *, int);
static int mdns_handle_group(struct mdns *, char [MAXHOSTNAMELEN], int);

int
mdns_open(struct mdns *m)
{
	int sockfd;
	
	bzero(m, sizeof(*m));
	if ((sockfd = mdns_connect()) == -1)
		return (-1);
	imsg_init(&m->ibuf, sockfd);
	
	return (sockfd);
}

void
mdns_close(struct mdns *m)
{
	imsg_clear(&m->ibuf);
}

void
mdns_set_lookup_A_hook(struct mdns *m, lookup_A_hook lhk)
{
	m->lhk_A = lhk;
}

void
mdns_set_lookup_PTR_hook(struct mdns *m, lookup_PTR_hook lhk)
{
	m->lhk_PTR = lhk;
}

void
mdns_set_lookup_HINFO_hook(struct mdns *m, lookup_HINFO_hook hhk)
{
	m->lhk_HINFO = hhk;
}

void
mdns_set_browse_hook(struct mdns *m, browse_hook bhk)
{
	m->bhk = bhk;
}

void
mdns_set_resolve_hook(struct mdns *m, resolve_hook rhk)
{
	m->rhk = rhk;
}

void
mdns_set_udata(struct mdns *m, void *udata)
{
	m->udata = udata;
}

void
mdns_set_group_hook(struct mdns *m, group_hook ghk)
{
	m->ghk = ghk;
}

int
mdns_lookup_A(struct mdns *m, const char *host)
{
	return (mdns_lookup_do(m, host, T_A, C_IN));
}

int
mdns_lookup_PTR(struct mdns *m, const char *ptr)
{
	return (mdns_lookup_do(m, ptr, T_PTR, C_IN));
}

int
mdns_lookup_rev(struct mdns *m, struct in_addr *addr)
{
	char	name[MAXHOSTNAMELEN];

	reversstr(name, addr);
	name[sizeof(name) - 1] = '\0';
	
	return (mdns_lookup_PTR(m, name));
}

int
mdns_lookup_HINFO(struct mdns *m, const char *host)
{
	return (mdns_lookup_do(m, host, T_HINFO, C_IN));
}

static int
mdns_lookup_do(struct mdns *m, const char name[MAXHOSTNAMELEN], u_int16_t type,
    u_int16_t class)
{
	struct rrset rrs;
	
	bzero(&rrs, sizeof(rrs));
	rrs.type  = type;
	rrs.class = class;
	if (strlcpy(rrs.dname, name, sizeof(rrs.dname)) >= sizeof(rrs.dname)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	if (ibuf_send_imsg(&m->ibuf, IMSG_CTL_LOOKUP,
	    &rrs, sizeof(rrs)) == -1)
		return (-1); /* XXX: set errno */
	
	return (0);
}

int
mdns_browse_add(struct mdns *m, const char *app, const char *proto)
{
	return (mdns_browse_adddel(m, app, proto, IMSG_CTL_BROWSE_ADD));
}

int
mdns_browse_del(struct mdns *m, const char *app, const char *proto)
{
	return (mdns_browse_adddel(m, app, proto, IMSG_CTL_BROWSE_DEL));
}

static int
mdns_browse_adddel(struct mdns *m, const char *app, const char *proto,
    u_int msgtype)
{
	struct rrset mlkup;

	if (app != NULL && strlen(app) > MAXHOSTNAMELEN) {
		errno = ENAMETOOLONG;
		return (-1);
	}

	bzero(&mlkup, sizeof(mlkup));

	/* browsing for service types */
	if (app == NULL && proto == NULL)
		(void)strlcpy(mlkup.dname, "_services._dns-sd._udp.local",
		    sizeof(mlkup.dname));
	else if (snprintf(mlkup.dname, sizeof(mlkup.dname),
	    "_%s._%s.local", app, proto) >= (int) sizeof(mlkup.dname)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	mlkup.type  = T_PTR;
	mlkup.class = C_IN;
	
	if (ibuf_send_imsg(&m->ibuf, msgtype,
	    &mlkup, sizeof(mlkup)) == -1)
		return (-1); /* XXX: set errno */

	return (0);
}

int
mdns_resolve(struct mdns *m, const char *name, const char *app,
    const char *proto)
{
	char buf[MAXHOSTNAMELEN];
	
	if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
		errno = EINVAL;
		return (-1);
	}
	
	if (snprintf(buf, sizeof(buf), "%s._%s._%s.local",
	    name, app, proto) >= (int) sizeof(buf)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	
	buf[sizeof(buf) - 1] = '\0';

	if (ibuf_send_imsg(&m->ibuf, IMSG_CTL_RESOLVE,
	    buf, sizeof(buf)) == -1)
		return (-1); /* XXX: set errno */

	return (0);
}

int
mdns_group_add(struct mdns *m, const char *group)
{
	char msg[MAXHOSTNAMELEN];

	bzero(msg, sizeof(msg));
	if (strlcpy(msg, group, sizeof(msg))
	    >= sizeof(msg))
		return (-1);
	if (ibuf_send_imsg(&m->ibuf, IMSG_CTL_GROUP_ADD,
	    msg, sizeof(msg)) == -1)
		return (-1);

	return (0);
}

int
mdns_group_reset(struct mdns *m, const char *group)
{
	char msg[MAXHOSTNAMELEN];

	bzero(msg, sizeof(msg));
	if (strlcpy(msg, group, sizeof(msg))
	    >= sizeof(msg))
		return (-1);
	if (ibuf_send_imsg(&m->ibuf, IMSG_CTL_GROUP_RESET,
	    msg, sizeof(msg)) == -1)
		return (-1);

	return (0);
}

int
mdns_group_add_service(struct mdns *m, const char *group,
    struct mdns_service *ms)
{
	if (strcmp(group, ms->name) != 0)
		return (-1);
	if (ibuf_send_imsg(&m->ibuf, IMSG_CTL_GROUP_ADD_SERVICE,
	    ms, sizeof(*ms)) == -1)
		return (-1);
	
	return (0);
}

int
mdns_group_commit(struct mdns *m, const char *group)
{
	char msg[MAXHOSTNAMELEN];

	if (strlcpy(msg, group, sizeof(msg))
	    >= sizeof(msg))
		return (-1);
	if (ibuf_send_imsg(&m->ibuf, IMSG_CTL_GROUP_COMMIT,
	    msg, sizeof(msg)) == -1)
		return (-1);

	return (0);
}

int
mdns_service_init(struct mdns_service *ms, const char *name, const char *app,
    const char *proto, u_int16_t port, const char *txt, const char *target,
    struct in_addr *addr)
{
	bzero(ms, sizeof(*ms));
	
	if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0)
		return (-1);
	if (strlcpy(ms->name, name, sizeof(ms->name)) >= sizeof(ms->name))
		return (-1);
	if (strlcpy(ms->app, app, sizeof(ms->app)) >= sizeof(ms->app))
		return (-1);
	if (strlcpy(ms->proto, proto, sizeof(ms->proto)) >= sizeof(ms->proto))
		return (-1);
	ms->port = port;
	if (strlcpy(ms->txt, txt, sizeof(ms->txt)) >= sizeof(ms->txt))
		return (-1);
	if (target != NULL)
		if (strlcpy(ms->target, target, sizeof(ms->target)) >= sizeof(ms->target))
			return (-1);
	if (addr != NULL)
		ms->addr = *addr;

	return (0);
}

ssize_t
mdns_read(struct mdns *m)
{
	int			ev;
	size_t			r;
	ssize_t			n;
	struct imsg		imsg;
	struct rr		rr;
	struct mdns_service	ms;
	char			groupname[MAXHOSTNAMELEN];

	n = imsg_read(&m->ibuf);

	if (n == -1 || n == 0)
		return (n);

	/* TODO call imsgctl_to_event() */
	while ((r = imsg_get(&m->ibuf, &imsg)) > 0) {
		switch (imsg.hdr.type) {
		case IMSG_CTL_LOOKUP: /* FALLTHROUGH */
		case IMSG_CTL_LOOKUP_FAILURE:
			if ((imsg.hdr.len - IMSG_HEADER_SIZE) != sizeof(rr))
				return (-1);
			ev = imsg.hdr.type == IMSG_CTL_LOOKUP  ?
			    MDNS_LOOKUP_SUCCESS : MDNS_LOOKUP_FAILURE;
			memcpy(&rr, imsg.data, sizeof(rr));
			r = mdns_handle_lookup(m, &rr, ev);
			break;
		case IMSG_CTL_BROWSE_ADD:
		case IMSG_CTL_BROWSE_DEL:
			if ((imsg.hdr.len - IMSG_HEADER_SIZE) != sizeof(rr))
				return (-1);
			ev = imsg.hdr.type == IMSG_CTL_BROWSE_ADD  ?
			    MDNS_SERVICE_UP : MDNS_SERVICE_DOWN;
			memcpy(&rr, imsg.data, sizeof(rr));
			r = mdns_handle_browse(m, &rr, ev);
			break;
		case IMSG_CTL_RESOLVE:
		case IMSG_CTL_RESOLVE_FAILURE:
			if ((imsg.hdr.len - IMSG_HEADER_SIZE) != sizeof(ms))
				return (-1);
			ev = imsg.hdr.type == IMSG_CTL_RESOLVE  ?
			    MDNS_RESOLVE_SUCCESS : MDNS_RESOLVE_FAILURE;
			memcpy(&ms, imsg.data, sizeof(ms));
			r = mdns_handle_resolve(m, &ms, ev);
			break;
		case IMSG_CTL_GROUP_ADD:
		case IMSG_CTL_GROUP_RESET:
		case IMSG_CTL_GROUP_ADD_SERVICE:
		case IMSG_CTL_GROUP_COMMIT:
		case IMSG_CTL_GROUP_ERR_COLLISION:
		case IMSG_CTL_GROUP_ERR_NOT_FOUND:
		case IMSG_CTL_GROUP_ERR_DOUBLE_ADD:
		case IMSG_CTL_GROUP_PROBING:
		case IMSG_CTL_GROUP_ANNOUNCING:
		case IMSG_CTL_GROUP_PUBLISHED:
			if ((imsg.hdr.len - IMSG_HEADER_SIZE) !=
			    sizeof(groupname))
				return (-1);
			if ((ev = imsgctl_to_event(imsg.hdr.type)) == -1)
				return (-1);
			memcpy(groupname, imsg.data, sizeof(groupname));
			r = mdns_handle_group(m, groupname, ev);
			break;
		default:
			/* TODO remove this once in the wild */
			warnx("Unknown imsg type %d", imsg.hdr.type);
			return (-1);
		}
		
		imsg_free(&imsg);
	}

	return (n);
}

static int
mdns_handle_lookup(struct mdns *m, struct rr *rr, int ev)
{
	struct hinfo *h;
	switch (rr->rrs.type) {
	case T_A:
		if (m->lhk_A == NULL)
			return (0);
		m->lhk_A(m, ev, rr->rrs.dname, rr->rdata.A);
		break;
	case T_PTR:
		if (m->lhk_PTR == NULL)
			return (0);
		m->lhk_PTR(m, ev, rr->rrs.dname, rr->rdata.PTR);
		break;
	case T_HINFO:
		if (m->lhk_HINFO == NULL)
			return (0);
		h = &rr->rdata.HINFO;
		m->lhk_HINFO(m, ev, rr->rrs.dname, h->cpu, h->os);
		break;
	default:
		return (-1);
	}

	return (0);
}

static int
mdns_handle_browse(struct mdns *m, struct rr *rr, int ev)
{
	char	name[MAXHOSTNAMELEN];
	char	app[MAXLABELLEN];
	char	proto[MAXPROTOLEN];
	int	hasname;
	
	if (rr->rrs.type != T_PTR)
		return (-1);
	
	if (m->bhk == NULL)
		return (0);
	
	if (splitdname(rr->rdata.PTR, name, app, proto, &hasname) == -1)
		return (-1);

	if (hasname)
		m->bhk(m, ev, name, app, proto);
	else
		m->bhk(m, ev, NULL, app, proto);

	return (0);
}

static int
mdns_handle_resolve(struct mdns *m, struct mdns_service *ms, int ev)
{
	int hasname;

	if (m->rhk == NULL)
		return (0);
	if (splitdname(ms->name, ms->name, ms->app, ms->proto, &hasname) == -1)
		return (-1);
	if (hasname == 0)
		return (-1);

	m->rhk(m, ev, ms);
	
	return (0);
}

static int
mdns_handle_group(struct mdns *m, char groupname[MAXHOSTNAMELEN], int ev)
{
	if (m->ghk == NULL)
		return (0);
	
	m->ghk(m, ev, groupname);
	
	return (0);
}

static int
mdns_connect(void)
{
	struct sockaddr_un	sun;
	int			sockfd;

	bzero(&sun, sizeof(sun));
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return (-1);
	sun.sun_family = AF_UNIX;
	(void)strlcpy(sun.sun_path, MDNSD_SOCKET,
	    sizeof(sun.sun_path));
	if (connect(sockfd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		if (errno == ENOENT)
			errno = ECONNREFUSED;
		close(sockfd);
		return (-1);
	}

	return (sockfd);
}

static int
ibuf_send_imsg(struct imsgbuf *ibuf, u_int32_t type,
    void *data, u_int16_t datalen)
{
	struct ibuf	*wbuf;

	if ((wbuf = imsg_create(ibuf, type, 0,
	    0, datalen)) == NULL)
		return (-1);

	if (imsg_add(wbuf, data, datalen) == -1)
		return (-1);

	wbuf->fd = -1;

	imsg_close(ibuf, wbuf);

	if (msgbuf_write(&ibuf->w) == -1)
		return (-1);

	return (0);
}

/* XXX: Too ugly, code me again with love */
static int
splitdname(char fname[MAXHOSTNAMELEN], char sname[MAXHOSTNAMELEN],
    char app[MAXLABEL], char proto[MAXPROTOLEN], int *hasname)
{
	char namecp[MAXHOSTNAMELEN];
	char *p, *start;

	*hasname = 1;
/*	 ubuntu810desktop [00:0c:29:4d:22:ce]._workstation._tcp.local */
/*	_workstation._tcp.local */
	/* work on a copy */
	(void)strlcpy(namecp, fname, sizeof(namecp));

	/* check if we have a name, or only an application protocol */
	if ((p = strstr(namecp, "._")) != NULL) {
		p += 2;
		if ((p = strstr(p, "._")) == NULL)
			*hasname = 0;
	}

	p = start = namecp;

	/* if we have a name, copy */
	if (*hasname == 1 && sname != NULL) {
		if ((p = strstr(start, "._")) == NULL)
			return (-1);
		*p++ = 0;
		p++;
		(void)strlcpy(sname, start, MAXHOSTNAMELEN);
		start = p;
	}
	else
		start++;

	if ((p = strstr(start, "._")) == NULL)
		return (-1);
	*p++ = 0;
	p++;
	(void)strlcpy(app, start, MAXLABEL);
	start = p;

	if ((p = strstr(start, ".")) == NULL)
		return (-1);
	*p++ = 0;
	(void)strlcpy(proto, start, MAXPROTOLEN);

	return (0);
}

static int
imsgctl_to_event(int msgtype)
{
	switch (msgtype) {
	case IMSG_CTL_GROUP_ERR_COLLISION:
		return
		    (MDNS_GROUP_ERR_COLLISION);
		break;
	case IMSG_CTL_GROUP_ERR_NOT_FOUND:
		return
		    (MDNS_GROUP_ERR_NOT_FOUND);
		break;
	case IMSG_CTL_GROUP_ERR_DOUBLE_ADD:
		return
		    (MDNS_GROUP_ERR_DOUBLE_ADD);
		break;
	case IMSG_CTL_GROUP_PROBING:
		return
		    (MDNS_GROUP_PROBING);
		break;
	case IMSG_CTL_GROUP_ANNOUNCING:
		return
		    (MDNS_GROUP_ANNOUNCING);
		break;
	case IMSG_CTL_GROUP_PUBLISHED:
		return
		    (MDNS_GROUP_PUBLISHED);
		break;
	default:
		/* TODO remove this once in the wild */
		warnx("imsgctl_to_event: Unknown imsgctl %d",
		    msgtype);
	}
	/* NOTREACHED */
	return (-1);
}

void
reversstr(char str[MAXHOSTNAMELEN], struct in_addr *addr)
{
	const u_char *uaddr = (const u_char *)addr;

	(void) snprintf(str, MAXHOSTNAMELEN, "%u.%u.%u.%u.in-addr.arpa",
	    (uaddr[3] & 0xff), (uaddr[2] & 0xff),
	    (uaddr[1] & 0xff), (uaddr[0] & 0xff));
}

