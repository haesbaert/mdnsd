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
#include <event.h>

#include "imsg.h"

#define	MDNSD_SOCKET	"/var/run/mdnsd.sock"
#define	MDNSD_USER	"_mdnsd"
#define RT_BUF_SIZE	16384
#define MAX_RTSOCK_BUF	128 * 1024

/* imsgev.c */
struct imsgev {
	struct imsgbuf		 ibuf;
	void			(*handler)(int, short, void *);
	struct event		 ev;
	void			*data;
	short			 events;
};

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

/* mif.c */
enum mif_if_state {
	MIF_STA_ACTIVE,
	MIF_STA_DOWN
};

enum mif_if_event {
	MIF_EVT_NOTHING,
	MIF_EVT_UP,
	MIF_EVT_DOWN
};

enum mif_if_action {
	MIF_ACT_NOTHING,
	MIF_ACT_START,
	MIF_ACT_SHUTDOWN
};

struct mif {
	LIST_ENTRY(mif)		entry;
	enum mif_if_state	state;
	pid_t			pid;
	struct imsgev		iev;
	char			ifname[IF_NAMESIZE];
	u_short			ifindex;
};

struct mif *	mif_new(struct kif *);
struct mif *    mif_find_index(u_short);
int		mif_fsm(struct mif *, enum mif_if_event);

/* mdnsd.c */
struct mdnsd_conf {
	LIST_HEAD(, mif)	 mif_list;
};

void	main_dispatch_mife(int, short, void *);
void	imsg_event_add(struct imsgev *);
void	main_imsg_compose_mife(struct mif *, int, void *, u_int16_t);
int	imsg_compose_event(struct imsgev *, u_int16_t, u_int32_t,
	    pid_t, int, void *, u_int16_t);

enum imsg_type {
	IMSG_NONE,
	IMSG_START,
	IMSG_STOP,
};

#endif /* _MDNSD_H_ */
