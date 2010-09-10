/*
 * Copyright (c) 2010 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2006 Michele Marchetto <mydecay@openbeer.it>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003 Henning Brauer <henning@openbsd.org>
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
#include <sys/un.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <imsg.h>

#include "mdns.h"
#include "parser.h"

__dead void	usage(void);
void		my_lookup_A_hook(struct mdns *, int, const char *, struct in_addr);
void		my_lookup_PTR_hook(struct mdns *, int, const char *, const char *);
void		my_lookup_HINFO_hook(struct mdns *, int, const char *,
    const char *, const char *);
void		my_browse_hook(struct mdns *, int, const char *, const char *,
    const char *);
void		my_resolve_hook(struct mdns *, int, struct mdns_service *);

struct parse_result	*res;

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s command [argument ...]\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		sockfd;
	struct mdns	mdns;
	/* parse options */
	if ((res = parse(argc - 1, argv + 1)) == NULL)
		exit(1);
	
	if ((sockfd = mdns_open(&mdns)) == -1)
		err(1, "mdns_open");
	
	mdns_set_lookup_A_hook(&mdns, my_lookup_A_hook);
	mdns_set_lookup_PTR_hook(&mdns, my_lookup_PTR_hook);
	mdns_set_lookup_HINFO_hook(&mdns, my_lookup_HINFO_hook);
	mdns_set_browse_hook(&mdns, my_browse_hook);
	mdns_set_resolve_hook(&mdns, my_resolve_hook);

	/* process user request */
	switch (res->action) {
	case NONE:
		usage();
		/* not reached */
		break;
	case LOOKUP:
		if (res->flags & F_A || res->flags == 0)
			if (mdns_lookup_A(&mdns, res->hostname) == -1)
				err(1, "mdns_lookup_A");

		if (res->flags & F_HINFO)
			if (mdns_lookup_HINFO(&mdns, res->hostname) == -1)
				err(1, "mdns_lookup_A");
		
		if (res->flags & F_PTR)
			if (mdns_lookup_PTR(&mdns, res->hostname) == -1)
				err(1, "mdns_lookup_A");
		break;
	case RLOOKUP:
		if (mdns_lookup_rev(&mdns, &res->addr) == -1)
			err(1, "mdns_lookup_A");
		break;
	case BROWSE_PROTO:
		printf("res->app %s res->proto %s\n",
		    res->app, res->proto);
		if (mdns_browse_add(&mdns, res->app, res->proto) == -1)
			err(1, "mdns_browse_add");
		
		break;		/* NOTREACHED */
	default:
		errx(1, "Unknown action");
		break;		/* NOTREACHED */
	}

	for (; ;) {
		ssize_t n;
		
		n = mdns_read(&mdns);
		if (n == -1)
			err(1, "mdns_read");
		if (n == 0)
			errx(1, "Server closed socket");
		if ((res->action == LOOKUP ||
		    res->action == RLOOKUP)
		    && res->flags == 0)
			exit(0);
	}
}

void
my_lookup_A_hook(struct mdns *m, int ev, const char *host, struct in_addr a)
{
	switch (ev) {
	case LOOKUP_SUCCESS:
		printf("Address: %s\n", inet_ntoa(a));
		break;
	case LOOKUP_FAILURE:
		printf("Address not found\n");
		break;
	default:
		errx(1, "Unhandled event");
		break;	/* NOTREACHED */
	}
	
	res->flags &= ~F_A;
}

void
my_lookup_PTR_hook(struct mdns *m, int ev, const char *name, const char *ptr)
{
	switch (ev) {
	case LOOKUP_SUCCESS:
		printf("Hostname: %s\n", ptr);
		break;
	case LOOKUP_FAILURE:
		printf("Hostname not found\n");
		break;
	default:
		errx(1, "Unhandled event");
		break;	/* NOTREACHED */
	}
	
	res->flags &= ~F_PTR;
}

void
my_lookup_HINFO_hook(struct mdns *m, int ev, const char *name, const char *cpu,
    const char *os)
{
	switch (ev) {
	case LOOKUP_SUCCESS:
		printf("Cpu: %s\n", cpu);
		printf("Os: %s\n", os);
		break;
	case LOOKUP_FAILURE:
		printf("HINFO not found\n");
		break;
	default:
		errx(1, "Unhandled event");
		break;	/* NOTREACHED */
	}
	
	res->flags &= ~F_HINFO;
}

void
my_browse_hook(struct mdns *m, int ev, const char *name, const char *app,
    const char *proto)
{
	switch (ev) {
	case SERVICE_UP:
		/* If no name, this is a service type */
		if (name == NULL) {
			if (mdns_browse_add(m, app, proto) == -1)
				err(1, "mdns_browse_add");
			return;
		}
		if (res->flags & F_RESOLV) {
			if (mdns_resolve(m, name, app, proto) == -1)
				err(1, "mdns_resolve");
			return;
		}
		printf("+++ %-48s %-20s %-3s\n", name, app, proto);
		break;
	case SERVICE_DOWN:
		if (name != NULL)
			printf("--- %-48s %-20s %-3s\n", name, app, proto);
		break;
	default:
		errx(1, "Unhandled event");
		break;
	}
}

void
my_resolve_hook(struct mdns *m, int ev, struct mdns_service *ms)
{
	switch (ev) {
	case RESOLVE_FAILURE:
		fprintf(stderr, "Can't resolve %s", ms->name);
		fflush(stderr);
		break;		/* NOTREACHED */
	case RESOLVE_SUCCESS:
		printf("+++ %-48s %-20s %-3s\n", ms->name, ms->app, ms->proto);
		printf(" Name: %s\n", ms->name);
		printf(" Priority: %u\n", ms->priority);
		printf(" Weight: %u\n", ms->weight);
		printf(" Port: %u\n", ms->port);
		printf(" Address: %s\n", inet_ntoa(ms->addr));
		printf(" Txt: %s\n", ms->txt);
		break;
	default:
		errx(1, "Unhandled event");
		break;
	}
}
