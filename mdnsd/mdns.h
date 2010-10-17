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
	IMSG_CTL_GROUP,
	IMSG_CTL_GROUP_END,
	IMSG_CTL_GROUP_SERVICE,
};

enum client_events {
	MDNS_LOOKUP_SUCCESS,
	MDNS_LOOKUP_FAILURE,
	MDNS_SERVICE_DOWN,
	MDNS_SERVICE_UP,
	MDNS_RESOLVE_SUCCESS,
	MDNS_RESOLVE_FAILURE,
};

struct mdns;
struct mdns_service;
typedef void (*browse_hook) (struct mdns *, int event, const char *name,
    const char *app, const char *proto);
typedef void (*resolve_hook) (struct mdns *, int event, struct mdns_service *);
typedef void (*lookup_A_hook) (struct mdns *, int event, const char *name,
    struct in_addr address);
typedef void (*lookup_PTR_hook) (struct mdns *, int event, const char *name,
    const char *ptr);
typedef void (*lookup_HINFO_hook) (struct mdns *, int event, const char *name,
    const char *cpu, const char *os);

/* Accepted RR: A, HINFO, CNAME, PTR, SRV, TXT, NS  */
struct mdns_service {
	char		app[MAXLABELLEN];
	char		proto[MAXPROTOLEN];
	char		name[MAXHOSTNAMELEN];
	char		hostname[MAXHOSTNAMELEN];
	u_int16_t	priority;
	u_int16_t	weight;
	u_int16_t	port;
	char		txt[MAXCHARSTR];
	struct in_addr	addr;
	TAILQ_ENTRY(mdns_service) entry;
};

struct mdns_group {
	char name[MAXHOSTNAMELEN];
	TAILQ_HEAD(, mdns_service) services;
};
	
struct mdns {
	struct imsgbuf		 ibuf;
	browse_hook		 bhk;
	lookup_A_hook		 lhk_A;
	lookup_PTR_hook		 lhk_PTR;
	lookup_HINFO_hook	 lhk_HINFO;
	resolve_hook		 rhk;
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
void	mdns_set_lookup_PTR_hook(struct mdns *, lookup_PTR_hook);
void	mdns_set_lookup_HINFO_hook(struct mdns *, lookup_HINFO_hook);
void	mdns_set_udata(struct mdns *, void *);
int	mdns_lookup_A(struct mdns *, const char *);
int	mdns_lookup_PTR(struct mdns *, const char *);
int	mdns_lookup_HINFO(struct mdns *, const char *);
int	mdns_lookup_rev(struct mdns *, struct in_addr *);
int	mdns_service_init(struct mdns_service *, const char *, const char *,
    const char *, u_int16_t, const char *, struct in_addr *);
void	mdns_group_init(struct mdns_group *);
int	mdns_group_add(struct mdns_group *, struct mdns_service *);
void	mdns_group_reset(struct mdns_group *);
int	mdns_group_commit(struct mdns *, struct mdns_group *);

void	reversstr(char [MAXHOSTNAMELEN], struct in_addr *);

#endif	/* _MDNS_H_ */
