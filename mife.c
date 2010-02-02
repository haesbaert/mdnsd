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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_types.h>
#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <event.h>

#include "mdnsd.h"
#include "mdns.h"
#include "mife.h"
#include "log.h"

extern struct mdnsd_conf *mconf;

struct mife	*mife;

void	mife_dispatch_main(int, short, void *);
int	mife_sock(struct iface *iface);
void	mife_recv_packet(int, short, void *);

/* mdns interface engine main */
pid_t
mife_start(struct iface *iface, int ppipe[2])
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
	
	
	/* show who we are */
	setproctitle("mdnsd mife %s", iface->name);

	mife->iface = iface;
	mife->iface->state = IF_STA_DOWN;
	mife->iface->fd = mife_sock(iface);
	close(ppipe[0]);
	
	event_init();
	
	/* setup events with parent */
	imsg_init(&mife->iev_main.ibuf, ppipe[1]);
	mife->iev_main.handler = mife_dispatch_main;
	mife->iev_main.events  = EV_READ;
	event_set(&mife->iev_main.ev, mife->iev_main.ibuf.fd,
	    mife->iev_main.events, mife->iev_main.handler, &mife->iev_main);
	event_add(&mife->iev_main.ev, NULL);
	
	/* setup mdns events */
	event_set(&mife->ev_mdns, mife->iface->fd, EV_READ|EV_PERSIST,
	    mife_recv_packet, NULL);
	event_add(&mife->ev_mdns, NULL);
	
	log_debug("starting mife %s pid %u", mife->iface->name, (u_int) getpid());
	
	event_dispatch();
	
/* 	mife_shutdown(); */
	/* NOTREACHED */
	exit(0);
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
			fatal("mife_dispatch_main: imsg_read error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_START:
			log_debug("IMSG_START");
			if_act_start(mife->iface);
			break;
		case IMSG_STOP:
			log_debug("IMSG_STOP");
			if_act_reset(mife->iface);
			break;
		default:
			log_debug("mife_dispatch_main: error handling imsg %d",
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

int
mife_sock(struct iface *iface)
{
	int sock;
	struct sockaddr_in addr;
	
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		fatal("socket");
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(MDNS_PORT);
 	addr.sin_addr.s_addr = iface->addr.s_addr; 

/* 	if (inet_aton(MDNS_MCAST_ADDR, &addr.sin_addr) != 1) */
/* 		fatal("inet_aton"); */
	
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
		fatal("bind");
	
	if (if_set_opt(sock) == -1)
		fatal("if_set_opt");

	if (if_set_mcast_ttl(sock, IP_DEFAULT_MULTICAST_TTL) == -1)
		fatal("if_set_mcast_ttl");

	if (if_set_mcast_loop(sock) == -1)
		fatal("if_set_mcast_loop");

/* 	if (if_set_tos(sock, IPTOS_PREC_INTERNETCONTROL) == -1) */
/* 		fatal("if_set_tos"); */

	if_set_recvbuf(sock);
	
	log_debug("mife %s bound to %s:%u", mife->iface->name,
	    inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	return sock;
}

void
mife_recv_packet(int fd, short event, void *bula)
{
	char tmpbuf[4096];
	ssize_t n;
	
	if (event != EV_READ)
		return;
	
	bzero(tmpbuf, sizeof(tmpbuf));
	
	n = read(fd, tmpbuf, sizeof(tmpbuf));
	
	switch(n) {
	case -1:
		fatal("read");
		break;		/* NOTREACHED */
	case 0:
		log_debug("mife %s mdns socket closed", mife->iface->name);
		return;
		break;		/* NOTREACHED */
	}
	
	log_debug("mife %s read %zd bytes", mife->iface->name, n);
}
