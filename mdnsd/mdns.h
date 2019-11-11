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

/*
 * This is the header shared between applications and the daemon, it will be on
 * a library someday so keep it clean, we'll need to fix all
 * symbol prefixes someday.
 */
#ifndef _MDNS_H_
#define	_MDNS_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <arpa/nameser.h>
#include <netinet/in.h>

#include <imsg.h>
#include <event.h>
#include <string.h>

#define MAXCHARSTR	MAXHOSTNAMELEN
#define MAXLABELLEN	64
#define MAXPROTOLEN	4
#define MDNSD_SOCKET    "/var/run/mdnsd.sock"

enum imsg_type {
	IMSG_NONE,
	IMSG_CTL_END,
	IMSG_CTL_LOOKUP,
	IMSG_CTL_LOOKUP_FAILURE,
	IMSG_CTL_BROWSE_ADD,
	IMSG_CTL_BROWSE_DEL,
	IMSG_CTL_RESOLVE,
	IMSG_CTL_RESOLVE_FAILURE,
	IMSG_CTL_GROUP_ADD,
	IMSG_CTL_GROUP_RESET,
	IMSG_CTL_GROUP_ADD_SERVICE,
	IMSG_CTL_GROUP_COMMIT,
	IMSG_CTL_GROUP_ERR_COLLISION,
	IMSG_CTL_GROUP_ERR_NOT_FOUND,
	IMSG_CTL_GROUP_ERR_DOUBLE_ADD,
	IMSG_CTL_GROUP_PROBING,
	IMSG_CTL_GROUP_ANNOUNCING,
	IMSG_CTL_GROUP_PUBLISHED,
};

enum client_events {
	MDNS_LOOKUP_SUCCESS,
	MDNS_LOOKUP_FAILURE,
	MDNS_SERVICE_DOWN,
	MDNS_SERVICE_UP,
	MDNS_RESOLVE_SUCCESS,
	MDNS_RESOLVE_FAILURE,
	MDNS_GROUP_ERR_COLLISION,
	MDNS_GROUP_ERR_NOT_FOUND,
	MDNS_GROUP_ERR_DOUBLE_ADD,
	MDNS_GROUP_PROBING,
	MDNS_GROUP_ANNOUNCING,
	MDNS_GROUP_PUBLISHED,
};

struct mdns;
struct mdns_service;
typedef void (*browse_hook) (struct mdns *, int event, const char *name,
    const char *app, const char *proto);
typedef void (*resolve_hook) (struct mdns *, int event, struct mdns_service *);
typedef void (*lookup_A_hook) (struct mdns *, int event, const char *name,
    struct in_addr address);
typedef void (*lookup_AAAA_hook) (struct mdns *, int event, const char *name,
    struct in6_addr address);
typedef void (*lookup_PTR_hook) (struct mdns *, int event, const char *name,
    const char *ptr);
typedef void (*lookup_HINFO_hook) (struct mdns *, int event, const char *name,
    const char *cpu, const char *os);
typedef void (*group_hook) (struct mdns *, int event, const char *name);

/* Accepted RR: A, AAAA, HINFO, CNAME, PTR, SRV, TXT, NS  */
struct mdns_service {
	LIST_ENTRY(mdns_service) entry;
	char		app[MAXLABELLEN];
	char		proto[MAXPROTOLEN];
	char		name[MAXHOSTNAMELEN];
	char		target[MAXHOSTNAMELEN];
	u_int16_t	priority;
	u_int16_t	weight;
	u_int16_t	port;
	char		txt[MAXCHARSTR];
	struct sockaddr_storage	addr;
};

/* TODO browse_udata and group_udata */
struct mdns {
	struct imsgbuf		 ibuf;
	browse_hook		 bhk;
	lookup_A_hook		 lhk_A;
	lookup_AAAA_hook	 lhk_AAAA;
	lookup_PTR_hook		 lhk_PTR;
	lookup_HINFO_hook	 lhk_HINFO;
	resolve_hook		 rhk;
	group_hook		 ghk;
	void			*udata;
};

int	mdns_browse_add(struct mdns *, const char *, const char *);
int	mdns_browse_del(struct mdns *, const char *, const char *);
int	mdns_resolve(struct mdns *, const char *, const char *, const char *);
int	mdns_open(struct mdns *);
ssize_t mdns_read(struct mdns *);
void	mdns_close(struct mdns *);
void	mdns_set_browse_hook(struct mdns *, browse_hook);
void	mdns_set_resolve_hook(struct mdns *m, resolve_hook);
void	mdns_set_lookup_A_hook(struct mdns *, lookup_A_hook);
void	mdns_set_lookup_AAAA_hook(struct mdns *, lookup_AAAA_hook);
void	mdns_set_lookup_PTR_hook(struct mdns *, lookup_PTR_hook);
void	mdns_set_lookup_HINFO_hook(struct mdns *, lookup_HINFO_hook);
void	mdns_set_group_hook(struct mdns *, group_hook);
void	mdns_set_udata(struct mdns *, void *);

int	mdns_lookup_A(struct mdns *, const char *);
int	mdns_lookup_AAAA(struct mdns *, const char *);
int	mdns_lookup_PTR(struct mdns *, const char *);
int	mdns_lookup_HINFO(struct mdns *, const char *);
int	mdns_lookup_rev(struct mdns *, struct sockaddr *);
int	mdns_service_init(struct mdns_service *, const char *, const char *,
    const char *, u_int16_t, const char *, const char *, struct sockaddr *);
int	mdns_group_add(struct mdns *, const char *);
int	mdns_group_reset(struct mdns *, const char *);
int	mdns_group_add_service(struct mdns *, const char *, struct mdns_service *);
int	mdns_group_commit(struct mdns *, const char *);

void	reversstr(char [MAXHOSTNAMELEN], struct sockaddr *);
const char*	satop(struct sockaddr *, char *);

#endif	/* _MDNS_H_ */
