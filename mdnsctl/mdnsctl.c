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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdns.h"
#include "parser.h"

__dead void	 usage(void);

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
	int			 r, done = 0;
	struct in_addr		 addr;
	struct hinfo		 hi;
	struct srv		 srv;
	struct parse_result	*res;
	char			 hostname[MAXHOSTNAMELEN];
	char			 txt[MAX_CHARSTR];
	/* parse options */
	if ((res = parse(argc - 1, argv + 1)) == NULL)
		exit(1);

	done = 0;
	/* process user request */
	switch (res->action) {
	case NONE:
		usage();
		/* not reached */
		break;
	case LOOKUP:
		if (res->flags & F_A || !res->flags) { 
			r = mdns_lkup(res->hostname, &addr);
			if (r == 0)
				printf("Address not found.\n");
			else if(r == 1)
				printf("Address: %s\n", inet_ntoa(addr));
			else
				err(1, "mdns_lkup");
		}
		
		if (res->flags & F_HINFO) {
			r = mdns_lkup_hinfo(res->hostname, &hi);
			if (r == 0)
				printf("Hinfo not found.\n");
			else if (r == 1) {
				printf("Cpu: %s\n", hi.cpu);
				printf("Os: %s\n",  hi.os);
			}
			else
				err(1, "mdns_lkup_hinfo");
		}
		
		if (res->flags & F_SRV) {
			r = mdns_lkup_srv(res->hostname, &srv);
			if (r == 0)
				printf("SRV not found.\n");
			else if (r == 1) {
				printf("Name: %s\n", srv.dname);
				printf("Port: %u\n", srv.port);
				printf("Priority: %u\n", srv.priority);
				printf("Weight: %u\n", srv.weight);
			}
			else
				err(1, "mdns_lkup_srv");
		}

		if (res->flags & F_TXT) {
			r = mdns_lkup_txt(res->hostname, txt, sizeof(txt));
			if (r == 0)
				printf("TXT not found.\n");
			else if (r == 1) {
				printf("TXT: %s\n", txt);
			}
			else
				err(1, "mdns_lkup_txt");
		}

		break;
	case LOOKUP_ADDR:
		r = mdns_lkup_addr(&res->addr, hostname,
		    sizeof(hostname));
		switch (r) {
		case 0:
			printf("Name not found.\n");
			exit(1);
			break;	/* NOTREACHED */
		case 1:
			printf("Hostname: %s\n", hostname);
			exit(0);
			break;	/* NOTREACHED */
		default:
			err(1, "mdns_lkup_addr");
			break;
		}
		break;
	case BROWSE_PROTO:
		errx(1, "proto = %s, implement me", res->proto);
		break;
	}
	
	return (0);		/* NOTREACHED */
}

