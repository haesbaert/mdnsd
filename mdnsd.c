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
#include "log.h"

__dead void	usage(void);

void	main_sig_handler(int, short, void *);
void	mdnsd_conf_init(int, char *[]);
void	mdnsd_shutdown(void);
void	mdnsd_cleanup(void);
void	init_mifs(void);
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
		log_debug("using iface %s", mif->ifname);
	}
}

void
init_mifs(void)
{
	struct mif	*mif;
	
	LIST_FOREACH(mif, &mconf->mif_list, entry) {
		if (LINK_STATE_IS_UP(mif->linkstate))
			mif_fsm(mif, MIF_EVT_UP);
	}
}

void
mdnsd_cleanup(void)
{
	struct mif *mif;
	
	LIST_FOREACH(mif, &mconf->mif_list, entry) {
		free(mif);
	}
	kev_cleanup();
	/* control_cleanup */
	/* kiface_cleanup(); */
	/* TODO FINISH ME */
	free(mconf);
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
	init_mifs();
	
	/* parent mainloop */
	event_dispatch();
	
	/* NOTREACHED */
	return 0;
}
