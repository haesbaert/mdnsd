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
#ifndef _MDNS_H_
#define	_MDNS_H_

#include <sys/queue.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#include <imsg.h>
#include <event.h>
#include <string.h>

#define MDNSD_SOCKET		"/var/run/mdnsd.sock"
#define ALL_MDNS_DEVICES	"224.0.0.251"
#define MDNS_TIMEOUT 		3
#define MAX_CHARSTR		256	/* we swap the length byter per the null byte */

typedef void (*browse_hook) (char *, char *, char *, int, void *);

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_END,
	IMSG_CTL_LOOKUP,
	IMSG_CTL_BROWSE_ADD,
	IMSG_CTL_BROWSE_DEL,
};

enum browse_events {
	SERVICE_DOWN,
	SERVICE_UP,
};

struct mdns_browse {
	struct imsgbuf	 ibuf;
	browse_hook	 bhk;
	void		*udata;
};

struct mdns_msg_lkup {
	char		dname[MAXHOSTNAMELEN];
	u_int16_t	type;
	u_int16_t	class;
};

/* Accepted RR: A, HINFO, CNAME, PTR, SRV, TXT, NS  */
struct hinfo {
	char	cpu[MAX_CHARSTR];
	char	os[MAX_CHARSTR];
};

struct srv {
	char		dname[MAXHOSTNAMELEN];
	u_int16_t	priority;
	u_int16_t	weight;
	u_int16_t	port;
};

/* struct mdns_service { */
/* 	char		dname[MAXHOSTNAMELEN]; */
/* 	u_int16_t	priority; */
/* 	u_int16_t	weight; */
/* 	u_int16_t	port; */
/* 	char		txt[MAX_CHARSTR]; */
/* 	struct in_addr  addr; */
/* }; */

int	mdns_browse_open(struct mdns_browse *, browse_hook, void *);
void	mdns_browse_close(struct mdns_browse *);
int	mdns_browse_add(struct mdns_browse *, const char *, const char *);
int	mdns_browse_del(struct mdns_browse *, const char *, const char *);
ssize_t	mdns_browse_read(struct mdns_browse *);
char *	mdns_browse_evstr(int);

int	mdns_lkup(const char *, struct in_addr *);
int	mdns_lkup_hinfo(const char *, struct hinfo *);
int	mdns_lkup_addr(struct in_addr *, char *, size_t);
int	mdns_lkup_srv(const char *, struct srv *);
int	mdns_lkup_txt(const char *, char *, size_t);

/* int	mdns_res_service(char *, char *, char *, struct mdns_service *); */


#endif	/* _MDNS_H_ */
