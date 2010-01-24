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

#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mdnsd.h"
#include "mdnse.h"
#include "log.h"



__dead void	usage(void);

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-d]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int			 ch;
	int			 debug = 0;	
	struct mdnsd_conf	 mconf;
	struct passwd		*pw;

	bzero(&mconf, sizeof(mconf));
	
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
	if (argc != 0)
		usage();
	
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
	setproctitle("mdns daemon");
	    
	/* drop priviledges */
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	/* init mdns engine */
	mdnse(&mconf);

	/* NOTREACHED */
	return 0;
}
