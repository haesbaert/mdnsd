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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdnsd.h"
#include "mife.h"
#include "log.h"

extern struct mdnsd_conf *mconf;

struct mife	*mife;
struct imsgev	*iev_main;

void	mife_dispatch_main(int, short, void *);

/* mdns interface engine main */
pid_t
mife_start(struct mif *mif, int ppipe[2])
{
	pid_t pid;
	/* setup pipe */

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		return pid;
	}
	
	if ((mife = calloc(1, sizeof(struct mife))) == NULL)
		fatal("calloc");
	
	strlcpy(mife->ifname, mif->ifname, sizeof(mif->ifname));
	mife->state = MIF_STA_DOWN;
	close(ppipe[0]);
	
	event_init();
	
	if ((iev_main = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal("calloc");
	
	/* setup events with parent */
	imsg_init(&iev_main->ibuf, ppipe[1]);
	iev_main->handler = mife_dispatch_main;
	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);
	
	log_debug("starting mife %s pid %u", mife->ifname, (u_int) getpid());
	
	event_dispatch();
	
/* 	mife_shutdown(); */
	/* NOTREACHED */
	return 0;
}

void
mife_dispatch_main(int fd, short event, void *bula)
{
	struct imsg	 imsg;
	struct imsgev	*iev = bula;
	struct imsgbuf	*ibuf = &iev->ibuf;
	ssize_t		 n;
	int		 shut = 0;

	log_debug("mife_dispatch_main called");
	
	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1)
			fatal("imsg_read error");
		if (n == 0)	/* connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if (msgbuf_write(&ibuf->w) == -1)
			fatal("msgbuf_write");
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("ripe_dispatch_main: imsg_read error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_START:
			log_debug("IMSG_START");
			mife->state = MIF_STA_ACTIVE;
			break;
		case IMSG_STOP:
			log_debug("IMSG_STOP");
			mife->state = MIF_STA_DOWN;
			break;
		default:
			log_debug("ripe_dispatch_main: error handling imsg %d",
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* this pipe is dead, so remove the event handler */  
		event_del(&iev->ev);
		event_loopexit(NULL);
	}

}

