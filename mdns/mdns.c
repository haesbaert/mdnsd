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

#include "mdnsd.h"
#include "parser.h"
#include "mdns_api.h"

__dead void	 usage(void);
static int	 show_lookup_msg(struct imsg *);

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
	struct parse_result	*res;
	char			 hostname[MAXHOSTNAMELEN];
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
		r = mdns_api_lookup(res->hostname, &addr);
		switch (r) {
		case 0:
			printf("Address not found.\n");
			break;
		case 1:
			printf("Address: %s\n", inet_ntoa(addr));
			break;
		default:
			warn("mdns_api_lookup");
			break;
		}
		break;
	case LOOKUP_ADDR:
		r = mdns_api_lookup_addr(&res->addr, hostname,
		    sizeof(hostname));
		switch (r) {
		case 0:
			printf("Name not found.\n");
			break;
		case 1:
			printf("Name: %s\n", hostname);
			break;
		default:
			warn("mdns_api_lookup_addr");
			break;
		}
		break;
	}
	return (0);
}

