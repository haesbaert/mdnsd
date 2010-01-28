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

#ifndef _MDNSD_H_
#define	_MDNSD_H_

#include <sys/param.h>
#include <sys/socket.h>
#include <net/if.h>

#define	MDNSD_SOCKET "/var/run/mdnsd.sock"
#define	MDNSD_USER   "_mdnsd"
#define RT_BUF_SIZE		16384
#define MAX_RTSOCK_BUF		128 * 1024

/* main children structure, one per instance */
struct mif {
	LIST_ENTRY(mif)	 entry;
	
	int		 enabled;
	int		 mdns_socket;
	int		 ppipe;
	struct kif	*k;

	/* stuff from kiface */
	char		ifname[IF_NAMESIZE];
	u_int		mtu;
	u_int16_t	flags;
	u_int8_t	linkstate;
	u_int8_t	linktype;
	u_int8_t	media_type;
	u_short		ifindex;
	
};

struct kif {
	char		 ifname[IF_NAMESIZE];
	u_int64_t	 baudrate;
	int		 flags;
	int		 mtu;
	u_short		 ifindex;
	u_int8_t	 media_type;
	u_int8_t	 link_state;
	u_int8_t	 nh_reachable;	/* for nexthop verification */
};

struct mdnsd_conf {
	/* hostname to be used, will apend .local. if not already, 
	 * that's 256 characters INCluding the null byte */
	u_int8_t	hostname[MAXHOSTNAMELEN];
	
	LIST_HEAD(, mif)	 mif_list;

	
};

/* mif.c */
struct mif *	mif_new(struct kif *);

/* kiface.c */
int		 kif_init(void);
struct kif	*kif_findname(char *);

/* kev.c */
void	kev_init(void);

#endif /* _MDNSD_H_ */
