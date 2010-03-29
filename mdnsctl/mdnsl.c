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
#include <sys/un.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "mdns.h"
#include "imsg.h"	/* XXX this shouldn't be here */

struct mdns_state {
	struct imsgbuf ibuf;
};

static int	mdns_connect(struct mdns_state *);
static void	mdns_finish(struct mdns_state *);
static int	mdns_read_imsg(struct mdns_state *, struct imsg *);
static int	mdns_send_imsg(struct mdns_state *, u_int32_t,
    void *, u_int16_t);

int
mdns_lkup(const char *hostname, struct in_addr *addr)
{
	struct mdns_state mst;
	struct imsg imsg;
	char hname[MAXHOSTNAMELEN];
	int err;
	
	if (strlen(hostname) > MAXHOSTNAMELEN) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	
	if (mdns_connect(&mst) == -1)
		return (-1);
	
	strlcpy(hname, hostname, sizeof(hname));
	if (mdns_send_imsg(&mst, IMSG_CTL_LOOKUP,
	    hname, sizeof(hname)) == -1) {
		mdns_finish(&mst);
		return (-1);
	}

	if (mdns_read_imsg(&mst, &imsg) == -1) {
		err = errno;
		mdns_finish(&mst);
		if (err == ETIMEDOUT) 
			return (0);
		return (-1);
	}
	if (imsg.hdr.type != IMSG_CTL_LOOKUP) {
		errno = EMSGSIZE; /* think of a better errno */
		mdns_finish(&mst);
		imsg_free(&imsg);
		return (-1);
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE !=
	    sizeof(struct in_addr)) {
		errno = EMSGSIZE;
		mdns_finish(&mst);
		imsg_free(&imsg);
		return (-1);
	}
	memcpy(addr, imsg.data, imsg.hdr.len - IMSG_HEADER_SIZE);
	mdns_finish(&mst);
	imsg_free(&imsg);
	
	return (1);
}

int
mdns_lkup_addr(struct in_addr *addr, char *hostname, size_t len)
{
	struct mdns_state mst;
	struct imsg imsg;
	int err;
	
	if (mdns_connect(&mst) == -1)
		return (-1);
	
	if (mdns_send_imsg(&mst, IMSG_CTL_LOOKUP_ADDR,
	    addr, sizeof(struct in_addr)) == -1) {
		mdns_finish(&mst);
		return (-1);
	}
	if (mdns_read_imsg(&mst, &imsg) == -1) {
		err = errno;
		mdns_finish(&mst);
		if (err == ETIMEDOUT)
			return (0);
		return (-1);
	}
	if (imsg.hdr.type != IMSG_CTL_LOOKUP_ADDR) {
		errno = EMSGSIZE; /* think of a better errno */
		mdns_finish(&mst);
		imsg_free(&imsg);
		    return (-1);
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE != MAXHOSTNAMELEN) {
		errno = EMSGSIZE;
		mdns_finish(&mst);
		imsg_free(&imsg);
		    return (-1);
	}
	if (len > MAXHOSTNAMELEN)
		len = MAXHOSTNAMELEN;
	strlcpy(hostname, imsg.data, len);
	imsg_free(&imsg);
	mdns_finish(&mst);
	
	return (1);
}

int
mdns_lkup_hinfo(const char *hostname, struct hinfo *h)
{
	struct mdns_state mst;
	struct imsg imsg;
	char hname[MAXHOSTNAMELEN];
	int err;
	
	if (strlen(hostname) > MAXHOSTNAMELEN) {
		errno = ENAMETOOLONG;
		return (-1);
	}
	
	if (mdns_connect(&mst) == -1)
		return (-1);
	
	strlcpy(hname, hostname, sizeof(hname));
	if (mdns_send_imsg(&mst, IMSG_CTL_LOOKUP_HINFO,
	    hname, sizeof(hname)) == -1) {
		mdns_finish(&mst);
		return (-1);
	}

	if (mdns_read_imsg(&mst, &imsg) == -1) {
		err = errno;
		mdns_finish(&mst);
		if (err == ETIMEDOUT) 
			return (0);
		return (-1);
	}
	if (imsg.hdr.type != IMSG_CTL_LOOKUP_HINFO) {
		errno = EMSGSIZE; /* think of a better errno */
		mdns_finish(&mst);
		imsg_free(&imsg);
		return (-1);
	}
	if (imsg.hdr.len - IMSG_HEADER_SIZE !=
	    sizeof(struct hinfo)) {
		errno = EMSGSIZE;
		mdns_finish(&mst);
		imsg_free(&imsg);
		return (-1);
	}
	memcpy(h, imsg.data, imsg.hdr.len - IMSG_HEADER_SIZE);
	mdns_finish(&mst);
	imsg_free(&imsg);
	
	return (1);
}

static int
mdns_connect(struct mdns_state *mst)
{
	struct sockaddr_un	sun;
	int			sockfd;
	
	bzero(mst, sizeof(struct mdns_state));
	bzero(&sun, sizeof(sun));
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		return (-1);
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, MDNSD_SOCKET, sizeof(sun.sun_path));
	if (connect(sockfd, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
		if (errno == ENOENT)
			errno = ECONNREFUSED;
		return (-1);
	}
	
	imsg_init(&mst->ibuf, sockfd);
	
	return (0);
}

static void
mdns_finish(struct mdns_state *mst)
{
	imsg_clear(&mst->ibuf);
}

static int
mdns_send_imsg(struct mdns_state *mst, u_int32_t type,
    void *data, u_int16_t datalen)
{
	struct buf	*wbuf;

	if ((wbuf = imsg_create(&mst->ibuf, type, 0,
	    0, datalen)) == NULL)
		return (-1);

	if (imsg_add(wbuf, data, datalen) == -1)
		return (-1);

	wbuf->fd = -1;

	imsg_close(&mst->ibuf, wbuf);
	
	if (msgbuf_write(&mst->ibuf.w))
		return (-1);

	return (0);
}

static int
mdns_read_imsg(struct mdns_state *mst, 	struct imsg *imsg)
{
	ssize_t		 n;
	struct timeval	 tv;
	int		 r;
	fd_set		 rset;

	if ((n = imsg_get(&mst->ibuf, imsg)) == -1)
		return (-1);
	if (n == 0) {
		FD_ZERO(&rset);
		FD_SET(mst->ibuf.fd, &rset);
		timerclear(&tv);
		tv.tv_sec = MDNS_TIMEOUT;
		
		r = select(mst->ibuf.fd + 1, &rset, NULL, NULL, &tv);

		if (r == -1)
			return (-1);
		else if (r == 0) {
			errno = ETIMEDOUT;
			return (-1);
		}
		if ((n = imsg_read(&mst->ibuf)) == -1)
			return (-1);
	}
	
	if ((n = imsg_get(&mst->ibuf, imsg)) <= 0)
		return (-1);
	
	return (0);
}

