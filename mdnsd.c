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
#include <sys/wait.h>

#include <err.h>
#include <event.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "mdnsd.h"
#include "mife.h"
#include "log.h"

__dead void	usage(void);

void	main_sig_handler(int, short, void *);
void	mdnsd_conf_init(int, char *[]);
void	mdnsd_shutdown(void);
void	mdnsd_cleanup(void);
void	start_mifes(void);
int     reap_child(void);

struct mdnsd_conf	*mconf = NULL;

__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-d] ifname [ifnames...]\n",
	    __progname);
	exit(1);
}

void
mdnsd_conf_init(int argc, char *argv[])
{
	int		 found = 0;
	int		 i;
	struct kif	*k;
	struct mif	*mif;
	
	/* fetch all kernel interfaces and match argv */
	if (kif_init() != 0)
		fatal("Can't get kernel interfaces");

	for (i = 0; i < argc; i++) {
		k = kif_findname(argv[i]);
		if (k == NULL) {
			log_warnx("Unknown interface %s", argv[i]);
			continue;
		}
		
		found++;
		mif = mif_new(k);
		LIST_INSERT_HEAD(&mconf->mif_list, mif, entry);
	}
	
	if (!found)
		fatal("Couldn't find any interface");
	
	LIST_FOREACH(mif, &mconf->mif_list, entry) {
		log_debug("using iface %s index %u", mif->ifname, mif->ifindex);
	}
}

void
start_mifes(void)
{
	struct mif	*mif;
	struct kif	*kif;
	int ppipe[2];
	
	LIST_FOREACH(mif, &mconf->mif_list, entry) {
		if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC,
		    ppipe) == -1)
			fatal("socketpair");
		/* start children */
		mif->pid = mife_start(mif, ppipe);
		close(ppipe[1]);

		/* setup children events */
		imsg_init(&mif->iev.ibuf, ppipe[0]);
		mif->iev.handler = main_dispatch_mife;
		mif->iev.events = EV_READ;
		event_set(&mif->iev.ev, mif->iev.ibuf.fd, mif->iev.events,
		    mif->iev.handler, &mif->iev);
		event_add(&mif->iev.ev, NULL);
		
		kif = kif_findname(mif->ifname);
		if (kif == NULL) {
			log_warnx("couldn't find kernel iface %s", mif->ifname);
			continue;
		}
		if (LINK_STATE_IS_UP(kif->link_state)) {
			main_imsg_compose_mife(mif, IMSG_START, NULL, 0);
			mif->state = MIF_STA_ACTIVE;
		}
	}
}

void
mdnsd_cleanup(void)
{
	struct mif *mif;
	
	LIST_FOREACH(mif, &mconf->mif_list, entry) {
		kill(mif->pid, SIGKILL);
		free(mif);
	}
	kev_cleanup();
	/* control_cleanup */
	/* kiface_cleanup(); */
	/* TODO FINISH ME */
	free(mconf);
	
	exit(0);
}

/* ARGSUSED */
void
main_sig_handler(int sig, short event, void *arg)
{
	/*
	 * signal handler rules don't apply, libevent decouples for us
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		log_debug("got SIGTERM/SIGINT");
		
		/* TODO shutdown and wait for all children */
		mdnsd_shutdown();
		break;		/* NOTREACHED */
	case SIGCHLD:
		log_debug("got SIGCHLD");
		reap_child();
		break;
	case SIGHUP:
		log_debug("got SIGHUP");
		/* reconfigure */
		/* ... */
		break;
	default:
		fatalx("unexpected signal");
		/* NOTREACHED */
	}
}

int
reap_child(void)
{
	struct mif	*mif;
	int		 status, ret = 0;
	
	LIST_FOREACH(mif, &mconf->mif_list, entry) {
		if (waitpid(mif->pid, &status, WNOHANG) <= 0)
			continue;
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status)) 
				log_warnx("mif %s termination error %d",
				    mif->ifname, WEXITSTATUS(status));
			else {
				log_info("mif %s down",
				    mif->ifname);
				ret = -1;
			}
		}
		else if (WIFSIGNALED(status)) {
			log_warnx("mif %s termination with unhandled signal %d",
			    mif->ifname, WTERMSIG(status));
			ret = -2;
		}
		log_debug("child %u reaped", (unsigned int) mif->pid);
	}
	
	return ret;
}

void
mdnsd_shutdown(void)
{
	/* TODO send shutdown to children */
	/* cleanup */
	mdnsd_cleanup();

	log_info("terminating");
	exit(0);
}

int
imsg_compose_event(struct imsgev *iev, u_int16_t type,
    u_int32_t peerid, pid_t pid, int fd, void *data, u_int16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid,
	    pid, fd, data, datalen)) != -1)
		imsg_event_add(iev);
	return (ret);
}

void
main_imsg_compose_mife(struct mif *mif, int type, void *data, u_int16_t datalen)
{
	imsg_compose_event(&mif->iev, type, 0, mif->pid, -1, data, datalen);
}

void
main_dispatch_mife(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	int			 shut = 0;

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
			fatal("imsg_get");

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		default:
			log_debug("main_dispatch_ripe: error handling imsg %d",
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
	}
}

void
imsg_event_add(struct imsgev *iev)
{
	if (iev->handler == NULL) {
		imsg_flush(&iev->ibuf);
		return;
	}

	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}


int
main(int argc, char *argv[])
{
	int		 ch;
	int		 debug = 0;	
	struct passwd	*pw;
	struct event	 ev_sigint, ev_sigterm, ev_sigchld, ev_sighup;

	if ((mconf = calloc(1, sizeof(*mconf))) == NULL)
		fatal("calloc");
	
	log_init(1);	/* log to stderr until daemonized */

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	
	argc -= optind;
	argv += optind;
	
	if (!argc)
		usage();
	
	mdnsd_conf_init(argc, argv);
	
	/* check for root privileges */
	if (geteuid())
		errx(1, "need root privileges");

	/* check for mdnsd user */
	if ((pw = getpwnam(MDNSD_USER)) == NULL)
		fatal("getpwnam");
	
	log_init(debug);
	
	if (!debug)
		daemon(1, 0);
	
	/* no double running protection ? will fail in bind, ask henning */
	
	log_info("startup");
	
	/* init control before chroot */
/* 	if (control_init() == -1) */
/* 		fatalx("control socket setup failed"); */

	/* chroot */
	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	/* show who we are */
	setproctitle("mdnsd parent");
	    
	/* drop privileges */
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	/* init libevent */
	event_init();

	/* setup signals */
	signal_set(&ev_sigint, SIGINT, main_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, main_sig_handler, NULL);
	signal_set(&ev_sigchld, SIGCHLD, main_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, main_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sigchld, NULL);
	signal_add(&ev_sighup, NULL);
	signal(SIGPIPE, SIG_IGN);

	/* listen to kernel interface events */
	kev_init();
	
	/* init ifaces */
	start_mifes();
	
	/* parent mainloop */
	event_dispatch();
	
	log_debug("main event_dispatch retornou");
	return 0;
}
