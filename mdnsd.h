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

#define	MDNSD_SOCKET	"/var/run/mdnsd.sock"
#define	MDNSD_USER	"_mdnsd"
#define RT_BUF_SIZE	16384
#define MAX_RTSOCK_BUF	128 * 1024

/* kiface.c */
struct kif {
	char		ifname[IF_NAMESIZE];
	u_int64_t	baudrate;
	int		flags;
	int		mtu;
	u_short		ifindex;
	u_int8_t	media_type;
	u_int8_t	link_state;
};

int		 kif_init(void);
void		 kif_cleanup(void);
struct kif	*kif_findname(char *);
void		 kev_init(void);
void		 kev_cleanup(void);

/* main children structure, one per instance */
/* mif.c */

/* interface states */
enum mif_if_state {
	MIF_STA_ACTIVE,
	MIF_STA_DOWN
};

/* interface events */
enum mif_if_event {
	MIF_EVT_NOTHING,
	MIF_EVT_UP,
	MIF_EVT_DOWN
};

/* interface actions */
enum mif_if_action {
	MIF_ACT_NOTHING,
	MIF_ACT_START,
	MIF_ACT_SHUTDOWN
};

struct mif *	mif_new(struct kif *);
struct mif *    mif_find_index(u_short);
int		mif_fsm(struct mif *, enum mif_if_event ev);

struct mif {
	LIST_ENTRY(mif)	 entry;
	enum mif_if_state	state;
	pid_t			pid; /* pid in parent, 0 in child */
	int			enabled;
	int			mdns_socket;
	int			ppipe;
	char			ifname[IF_NAMESIZE];
	u_int			mtu;
	u_int16_t		flags;
	u_int8_t		linkstate;
	u_int8_t		linktype;
	u_int8_t		media_type;
	u_short			ifindex;
	
};

struct mdnsd_conf {
	/* hostname to be used, will apend .local. if not already, 
	 * that's 256 characters INCluding the null byte */
	u_int8_t	hostname[MAXHOSTNAMELEN];
	
	LIST_HEAD(, mif)	 mif_list;

	
};

/* mife.c */
pid_t	mife_start(struct mif *);

#endif /* _MDNSD_H_ */
