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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/utsname.h>
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
#include "mdns.h"
#include "log.h"
#include "control.h"

__dead void		 usage(void);
static void		 mdnsd_sig_handler(int, short, void *);
static void		 mdnsd_conf_init(int, char *[]);
static void		 mdnsd_shutdown(void);
static int		 mdns_sock(void);
static void		 fetchmyname(char [MAXHOSTNAMELEN]);
static void		 fetchhinfo(struct hinfo *);

struct mdnsd_conf	*conf = NULL;
extern char 		*malloc_options;

__dead void
usage(void)
{
	extern char	*__progname;

	fprintf(stderr, "usage: %s [-d] ifname [ifnames...]\n",
	    __progname);
	exit(1);
}

static void
mdnsd_conf_init(int argc, char *argv[])
{
	int		 found = 0;
	int		 i;
	struct kif	*k;
	struct iface	*iface;
	
	if ((conf = calloc(1, sizeof(*conf))) == NULL)
		fatal("calloc");
	
	LIST_INIT(&conf->iface_list);
	
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
		iface = if_new(k);
		RB_INIT(&iface->rrt);
		LIST_INSERT_HEAD(&conf->iface_list, iface, entry);
	}
	
	if (!found)
		fatal("Couldn't find any interface");
	
	fetchmyname(conf->myname);
	fetchhinfo(&conf->hi);
	
	LIST_FOREACH(iface, &conf->iface_list, entry) 
		log_debug("using iface %s index %u", iface->name, iface->ifindex);
}

/* ARGSUSED */
static void
mdnsd_sig_handler(int sig, short event, void *arg)
{
	/*
	 * signal handler rules don't apply, libevent decouples for us
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		mdnsd_shutdown();
		break;		/* NOTREACHED */
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

static void
mdnsd_shutdown(void)
{
	struct iface	*iface;
	
	while ((iface = LIST_FIRST(&conf->iface_list)) != NULL) {
		LIST_REMOVE(iface, entry);
		free(iface);
	}
	
	kev_cleanup();
	kif_cleanup();
	control_cleanup();
	free(conf);
	
	log_info("terminating");
	exit(0);
}


static int
mdns_sock(void)
{
	int sock;
	struct sockaddr_in addr;
	
	if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		fatal("socket");
	
	addr.sin_family = AF_INET;
	addr.sin_port = htons(MDNS_PORT);
	addr.sin_addr.s_addr = INADDR_ANY;

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
	
	log_debug("mdns sock bound to %s:%u", inet_ntoa(addr.sin_addr),
	    ntohs(addr.sin_port));
	
	return (sock);
}

static void
fetchmyname(char myname[MAXHOSTNAMELEN])
{
	char			*end;
	
	if (gethostname(myname, MAXHOSTNAMELEN) == -1)
		fatal("gethostname");
	end = strchr(myname, '.');
	if (end != NULL)
		*end = '\0';	/* use short hostnames */
	if (strlen(myname) <= 6)
		strlcat(myname, ".local", MAXHOSTNAMELEN);
	else
		if (strcmp(&myname[strlen(myname) - 6], ".local") != 0) {
			strlcat(myname, ".local", MAXHOSTNAMELEN);
			/* now check if name was truncated */
			if (strcmp(&myname[strlen(myname) - 6], ".local") != 0) {
				myname[strlen(myname) - 6] = '\0';
				strlcat(myname, ".local", MAXHOSTNAMELEN);
			}
		}
}

static void
fetchhinfo(struct hinfo *hi)
{
	struct utsname	utsname;
	
	if (uname(&utsname) == -1)
		fatal("uname");
	bzero(hi, sizeof(*hi));
	strlcpy(hi->cpu, utsname.machine, sizeof(hi->cpu));
	snprintf(hi->os, sizeof(hi->os), "%s %s", utsname.sysname,
	    utsname.release);
}

int
main(int argc, char *argv[])
{
	int		 ch;
	int		 debug = 0;	
	struct passwd	*pw;
	struct iface	*iface;
	struct event	 ev_sigint, ev_sigterm, ev_sighup;

	log_init(1);	/* log to stderr until daemonized */

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			malloc_options = "AFGJPX";
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
	
	log_info("startup");
	
	/* init control before chroot */
	if (control_init() == -1)
		fatalx("control socket setup failed");

	/* chroot */
	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	/* show who we are */
	setproctitle("mdnsd");
	    
	/* drop privileges */
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("error droping privileges");

	/* init libevent */
	event_init();

	/* setup signals */
	signal_set(&ev_sigint, SIGINT, mdnsd_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, mdnsd_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, mdnsd_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal(SIGPIPE, SIG_IGN);

	/* init querier */
	query_init();
	
	/* init RR cache */
	cache_init();
	
	/* init publish */
	publish_init();
	
	/* listen to kernel interface events */
	kev_init();
	
	/* create mdns socket */
	conf->mdns_sock = mdns_sock();
	
	/* setup mdns events */
	event_set(&conf->ev_mdns, conf->mdns_sock, EV_READ|EV_PERSIST,
	    recv_packet, NULL);
	event_add(&conf->ev_mdns, NULL);
	
	/* start interfaces */
	LIST_FOREACH(iface, &conf->iface_list, entry) {
		/* XXX yep it seems wrong indeed */
		iface->fd = conf->mdns_sock;
		if (if_fsm(iface, IF_EVT_UP))
			log_warnx("error starting interface %s", iface->name);
	}
	
	/* listen on mdns control socket */
	TAILQ_INIT(&ctl_conns);
	control_listen();
	
	/* parent mainloop */
	event_dispatch();
	
	return (0);
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
mdnsd_imsg_compose_ctl(struct ctl_conn *c, u_int16_t type,
    void *data, u_int16_t datalen)
{
	return (imsg_compose_event(&c->iev, type, 0, 0, -1, data, datalen));
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

int
peersuser(int fd)
{
	uid_t	euid;
	
	if (getpeereid(fd, &euid, NULL) == -1)
		fatal("getpeereid");
	return (euid == 0);
}

void
reversstr(char str[MAXHOSTNAMELEN], struct in_addr *addr)
{
	const u_char *uaddr = (const u_char *)addr;

	(void) snprintf(str, MAXHOSTNAMELEN, "%u.%u.%u.%u.in-addr.arpa",
	    (uaddr[3] & 0xff), (uaddr[2] & 0xff),
	    (uaddr[1] & 0xff), (uaddr[0] & 0xff));
}

