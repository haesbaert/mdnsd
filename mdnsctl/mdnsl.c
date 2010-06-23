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

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <imsg.h>

#include "mdns.h"

static void	reversstr(char [MAXHOSTNAMELEN], struct in_addr *);
static int	mdns_connect(void);
static int	mdns_lkup_do(const char *, u_int16_t, void *, size_t);
static int	mdns_browse_adddel(struct mdns_browse *, const char *,
    const char *, int);
static int	ibuf_read_imsg(struct imsgbuf *, struct imsg *);
static int	ibuf_send_imsg(struct imsgbuf *, u_int32_t,
    void *, u_int16_t);
static int	splitdname(char [MAXHOSTNAMELEN], char [MAXHOSTNAMELEN],
    char [MAXLABEL], char [4], int *);

int
mdns_lkup(const char *hostname, struct in_addr *addr)
{
	return (mdns_lkup_do(hostname, T_A, addr, sizeof(*addr)));
}

int
mdns_lkup_hinfo(const char *hostname, struct hinfo *h)
{
	return (mdns_lkup_do(hostname, T_HINFO, h, sizeof(*h)));
}

int
mdns_lkup_addr(struct in_addr *addr, char *hostname, size_t len)
{
	char	name[MAXHOSTNAMELEN];
	char	res[MAXHOSTNAMELEN];
	int	r;
	
	reversstr(name, addr);
	name[sizeof(name) - 1] = '\0';
	r = mdns_lkup_do(name, T_PTR, res, sizeof(res));
	if (r == 1)
		strlcpy(hostname, res, len);
	
	return (r);
}

int
mdns_lkup_srv(const char *hostname, struct srv *srv)
{
	return (mdns_lkup_do(hostname, T_SRV, srv, sizeof(*srv)));
}

int
mdns_lkup_txt(const char *hostname, char *txt, size_t len)
{
	char	res[MAXHOSTNAMELEN];
	int	r;
	
	r = mdns_lkup_do(hostname, T_TXT, res, sizeof(res));
	if (r == 1)
		strlcpy(txt, res, len);
	
	return (r);
}

/* XXX: Find me a better name.
 *  We're not ready for it yet, lots of more important stuff to do, won't get
 *  back at resolving service prior to having browsing working properly.
 */
/* int */
/* mdns_res_service(char *name, char *app, char *proto, struct mdns_service *ms) */
/* { */
/* 	char		srvname[MAXHOSTNAMELEN]; */
/* 	struct srv	srv; */
	
/* 	if (mksrvstr(srvname, name, app, proto) == -1) */
/* 		return (-1); */
	
/* 	bzero(ms, sizeof(*ms)); */
/* 	bzero(&srv, sizeof(srv)); */
	
/* 	if (mdns_lkup_srv(srvname, &srv) != 1) */
/* 		return (-1); */
/* 	ms->priority = srv.priority; */
/* 	ms->weight   = srv.weight; */
/* 	ms->port     = srv.port; */
/* 	strlcpy(ms->dname, srv.dname, sizeof(ms->dname)); */
/* 	printf("srv.dname = %s\n", srv.dname); */
/* 	if (mdns_lkup_txt(srvname, ms->txt, sizeof(ms->txt)) != 1) */
/* 		return (-1); */
/* 	if (mdns_lkup(ms->dname, &ms->addr) != 1) */
/* 		return (-1); */

/* 	return (1); */
/* } */

int
mdns_browse_open(struct mdns_browse *mb, browse_hook bhk, void *udata)
{
	int sockfd;
	
	if ((sockfd = mdns_connect()) == -1)
		return (-1);
	imsg_init(&mb->ibuf, sockfd);
	mb->bhk = bhk;
	mb->udata = udata;
	return (sockfd);
}

void
mdns_browse_close(struct mdns_browse *mb)
{
	imsg_clear(&mb->ibuf);
}

int
mdns_browse_add(struct mdns_browse *mb, const char *app, const char *proto)
{
	return (mdns_browse_adddel(mb, app, proto, IMSG_CTL_BROWSE_ADD));
}

int
mdns_browse_del(struct mdns_browse *mb, const char *app, const char *proto)
{
	return (mdns_browse_adddel(mb, app, proto, IMSG_CTL_BROWSE_DEL));
}

ssize_t
mdns_browse_read(struct mdns_browse *mb)
{
	int		ev, r, hasname;
	ssize_t		n;
	struct imsg	imsg;
	char		name[MAXHOSTNAMELEN], app[MAXLABEL], proto[4];

	n = imsg_read(&mb->ibuf);

	if (n == -1 || n == 0) 
		return (n);

	while ((r = imsg_get(&mb->ibuf, &imsg)) > 0) {
		if (imsg.hdr.type != IMSG_CTL_BROWSE_ADD &&
		    imsg.hdr.type != IMSG_CTL_BROWSE_DEL)
			return (-1);
		if ((imsg.hdr.len - IMSG_HEADER_SIZE) != MAXHOSTNAMELEN)
			return (-1);
		ev = imsg.hdr.type == IMSG_CTL_BROWSE_ADD ?
		    SERVICE_UP : SERVICE_DOWN;
		if (splitdname(imsg.data, name, app, proto, &hasname) == 0) {
			if (hasname)
				mb->bhk(name, app, proto, ev, mb->udata);
			else
				mb->bhk(NULL, app, proto, ev, mb->udata);
		}

		imsg_free(&imsg);
	}
	
	if (r == -1)
		return (-1);
	
	return (n);
}

char *
mdns_browse_evstr(int ev)
{
	if (ev == SERVICE_UP)
		return ("SERVICE_UP");
	else if(ev == SERVICE_DOWN)
		return ("SERVICE_DOWN");
	return ("UNKNOWN");
}

static int
mdns_browse_adddel(struct mdns_browse *mb, const char *app, const char *proto,
    int msgtype)
{
	struct mdns_msg_lkup	mlkup;

 	if (app != NULL && strlen(app) > MAXHOSTNAMELEN) {
 		errno = ENAMETOOLONG;
 		return (-1);
 	}
	
 	bzero(&mlkup, sizeof(mlkup));
	
	/* browsing for service types */
	if (app == NULL && proto == NULL)
		strlcpy(mlkup.dname, "_services._dns-sd._udp.local",
		    sizeof(mlkup.dname));
	else if (snprintf(mlkup.dname, sizeof(mlkup.dname),
	    "_%s._%s.local", app, proto) >= (int) sizeof(mlkup.dname)) {
		errno = ENAMETOOLONG;
		return (-1);
	}
 	mlkup.type  = T_PTR;
 	mlkup.class = C_IN;
 	if (ibuf_send_imsg(&mb->ibuf, msgtype,
 	    &mlkup, sizeof(mlkup)) == -1)
 		return (-1); /* XXX: set errno */
	
	return (0);
}

static int
mdns_connect(void)
{
	struct sockaddr_un	sun;
	int			sockfd;
/* 	int			flags; */
	
	bzero(&sun, sizeof(sun));
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return (-1);
	/* use nonblocking mode so we can use it with edge triggered syscalls */
/* 	if ((flags = fcntl(sockfd, F_GETFL, 0)) == -1) */
/* 		return (-1); */
/* 	if ((flags = fcntl(sockfd, F_SETFL, flags |= O_NONBLOCK)) == -1) */
/* 		return (-1); */
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, MDNSD_SOCKET, sizeof(sun.sun_path));
	if (connect(sockfd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		if (errno == ENOENT)
			errno = ECONNREFUSED;
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
	
	if (msgbuf_write(&ibuf->w))
		return (-1);

	return (0);
}

static int
ibuf_read_imsg(struct imsgbuf *ibuf, struct imsg *imsg)
{
	ssize_t		 n;
	struct timeval	 tv;
	int		 r;
	fd_set		 rset;

	if ((n = imsg_get(ibuf, imsg)) == -1)
		return (-1);
	if (n == 0) {
		FD_ZERO(&rset);
		FD_SET(ibuf->fd, &rset);
		timerclear(&tv);
		tv.tv_sec = MDNS_TIMEOUT;
		
		r = select(ibuf->fd + 1, &rset, NULL, NULL, &tv);

		if (r == -1)
			return (-1);
		else if (r == 0) {
			errno = ETIMEDOUT;
			return (-1);
		}
		if ((n = imsg_read(ibuf)) == -1)
			return (-1);
	}
	
	if ((n = imsg_get(ibuf, imsg)) <= 0)
		return (-1);
	
	return (0);
}

static void
reversstr(char str[MAXHOSTNAMELEN], struct in_addr *addr)
{
	const u_char *uaddr = (const u_char *)addr;

	(void) snprintf(str, MAXHOSTNAMELEN, "%u.%u.%u.%u.in-addr.arpa",
	    (uaddr[3] & 0xff), (uaddr[2] & 0xff),
	    (uaddr[1] & 0xff), (uaddr[0] & 0xff));
}

static int
mdns_lkup_do(const char *name, u_int16_t type, void *data, size_t len)
{
	struct imsg		imsg;
	struct mdns_msg_lkup	mlkup;
	struct imsgbuf		ibuf;
	int			err, sockfd;
	
	switch (type) {
	case T_A:		/* FALLTHROUGH */
	case T_HINFO:		/* FALLTHROUGH */
	case T_PTR:		/* FALLTHROUGH */
	case T_SRV:		/* FALLTHROUGH */
	case T_TXT:		/* FALLTHROUGH */
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	if (strlen(name) > MAXHOSTNAMELEN) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	
	if ((sockfd = (mdns_connect())) == -1)
		return (-1);
	
	imsg_init(&ibuf, sockfd);

	bzero(&mlkup, sizeof(mlkup));
	strlcpy(mlkup.dname, name, sizeof(mlkup.dname));
	mlkup.type  = type;
	mlkup.class = C_IN;
	if (ibuf_send_imsg(&ibuf, IMSG_CTL_LOOKUP,
	    &mlkup, sizeof(mlkup)) == -1)
		return (-1); /* XXX: set errno */
	if (ibuf_read_imsg(&ibuf, &imsg) == -1) {
		err = errno;
		imsg_clear(&ibuf);
		if (err == ETIMEDOUT) 
			return (0);
		return (-1);
	}
	if (imsg.hdr.type != IMSG_CTL_LOOKUP) {
		errno = EMSGSIZE; /* think of a better errno */
		imsg_clear(&ibuf);
		imsg_free(&imsg);
		return (-1);
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != len) {
		errno = EMSGSIZE;
		imsg_clear(&ibuf);
		imsg_free(&imsg);
		return (-1);
	}
	
	memcpy(data, imsg.data, len);
	imsg_free(&imsg);
	imsg_clear(&ibuf);
	return (1);
}

/* XXX: Too ugly, code me again with love */
static int
splitdname(char fname[MAXHOSTNAMELEN], char sname[MAXHOSTNAMELEN],
    char app[MAXLABEL], char proto[4], int *hasname)
{
	char namecp[MAXHOSTNAMELEN];
	char *p, *start;
	
	*hasname = 1;
/* 	ubuntu810desktop [00:0c:29:4d:22:ce]._workstation._tcp.local */
/* 	_workstation._tcp.local */
	/* work on a copy */
	strlcpy(namecp, fname, sizeof(namecp));
	
	/* check if we have a name, or only and application protocol */
	if ((p = strstr(namecp, "._")) != NULL) {
		p += 2;
		if ((p = strstr(p, "._")) == NULL)
			*hasname = 0;
	}
	
	p = start = namecp;
	
	/* if we have a name, copy */
	if (*hasname) {
		if ((p = strstr(start, "._")) == NULL)
			return (-1);
		*p++ = 0;
		p++;
		strlcpy(sname, start, MAXHOSTNAMELEN);
		start = p;
	}
	else
		start++;
	
	if ((p = strstr(start, "._")) == NULL)
		return (-1);
	*p++ = 0;
	p++;
	strlcpy(app, start, MAXLABEL);
	start = p;
	
	if ((p = strstr(start, ".")) == NULL)
		return (-1);
	*p++ = 0;
	strlcpy(proto, start, 4);
	start = p;
	
	return (0);
}

