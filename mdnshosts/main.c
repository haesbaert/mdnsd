/*
 * Copyright (c) 2017 Kristaps Dzonsons <kristaps@bsd.lv>
 * Copyright (c) 2010,2011 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <err.h>
#include <fcntl.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <imsg.h>

#include "mdns.h"

/*
 * A named host entry reported by the mdns server.
 * This is unique over "name" entries.
 */
struct	hostent {
	char		*name; /* unique name */
	struct in_addr	 addr; 
	char		*target;
	size_t		 refs;
};

struct	hostdb {
	struct hostent	*hosts;
	size_t		 hostsz;
};

static	int	writer;

/*
 * Look up entry named "name" in our database of entries.
 * TODO: use ohash or another hash based lookup.
 * Returns the entry or NULL if it doesn't exist.
 */
static struct hostent *
db_lookup(struct hostdb *db, const char *name)
{
	size_t	 i;

	for (i = 0; i < db->hostsz; i++)
		if (0 == strcmp(name, db->hosts[i].name))
			return(&db->hosts[i]);

	return(NULL);
}

/*
 * Decrement a reference counter, if active.
 */
static void
db_unref(struct hostent *ent)
{

	if (ent->refs) 
		warnx("writer: entry down: %s (%zu refs)", 
			ent->name, --ent->refs);
	else
		warnx("writer: entry down: %s (already down)", 
			ent->name);
}

/*
 * Increase the reference count of a name.
 * This always frees the "target" pointer.
 * Also check whether our IP address and/or target is changing.
 */
static void
db_ref(struct hostent *ent, char *target, const struct in_addr *addr)
{
	char	 buf[64];
	char	*cp;

	if (ent->refs) {
		warnx("writer: known entity being referenced: "
			"%s (%zu refs)", ent->name, ent->refs + 1);
		cp = inet_ntoa(*addr);
		strlcpy(buf, cp, sizeof(buf));
		if (memcmp(&ent->addr, addr, sizeof(ent->addr))) {
			warnx("address changed: is %s, was %s: %s", 
				buf, inet_ntoa(ent->addr), ent->name);
			memcpy(&ent->addr, addr, sizeof(ent->addr));
		}
		if (strcmp(ent->target, target)) {
			warnx("target changed: is %s, was %s: %s", 
				ent->target, target, ent->name);
			free(ent->target);
			ent->target = target;
			target = NULL;
		} 
	} else {
		warnx("writer: known entity "
			"coming online: %s", ent->name);
		memcpy(&ent->addr, addr, sizeof(ent->addr));
		free(ent->target);
		ent->target = target;
		target = NULL;
	}

	ent->refs++;
	free(target);
}

/*
 * Add an entry to the database.
 * IT MUST NOT ALREADY EXIST.
 * Initialises the entry with the given attributes.
 */
static void
db_add(struct hostdb *db, char *name, 
	char *target, struct in_addr *addr)
{

	db->hosts = reallocarray(db->hosts, 
		db->hostsz + 1, sizeof(struct hostent));
	if (NULL == db->hosts)
		err(EXIT_FAILURE, NULL);

	db->hosts[db->hostsz].refs = 1;
	db->hosts[db->hostsz].target = target;
	db->hosts[db->hostsz].name = name;
	memcpy(&db->hosts[db->hostsz].addr, 
		addr, sizeof(struct in_addr));
	db->hostsz++;
	warnx("writer: unknown entity coming online: %s "
		"(%s -> %s)", name, inet_ntoa(*addr), target);
}

/*
 * Write binary buffer "buf" of size "sz" to the descriptor.
 * Return zero on failure, non-zero on success.
 */
static int
write_buf(int fd, const char *name, const void *buf, size_t sz)
{
	ssize_t	 ssz;

	ssz = write(fd, buf, sz);
	if (ssz < 0) {
		warn("write: %s", name);
		return(-1);
	} else if (sz != (size_t)ssz) {
		warnx("short write: %s", name);
		return(-1);
	}

	return(1);
}

/*
 * Write nil-terminated string "buf" to the descriptor.
 * Return zero on failure, non-zero on success.
 */
static int
write_str(int fd, const char *name, const char *buf)
{
	size_t	 sz;

	sz = strlen(buf) + 1;
	if (write_buf(fd, name, &sz, sizeof(size_t)) < 0)
		return(0);
	return(write_buf(fd, name, buf, sz));
}

/*
 * Write an integral token to the descriptor.
 * Return zero on failure, non-zero on success.
 */
static int
write_token(int fd, const char *name, int token)
{

	return(write_buf(fd, name, &token, sizeof(int)));
}

/*
 * Read a buffer "buf" of known size "sz".
 * Returns zero on failure, non-zero on success.
 */
static int
read_buf(int fd, const char *name, void *buf, size_t sz)
{
	ssize_t	 ssz;

	if ((ssz = read(fd, buf, sz)) < 0) {
		warn("read: %s", name);
		return(0);
	} else if (sz != (size_t)ssz) {
		warnx("short read: %s", name);
		return(0);
	}

	return(1);
}

/* 
 * Read a string into "buf".
 * Returns zero on failure, non-zero on success.
 */
static int
read_str(int fd, const char *name, char **buf)
{
	ssize_t	 ssz;
	size_t	 sz;

	ssz = read(fd, &sz, sizeof(size_t));
	if (ssz < 0) {
		warn("read: %s", name);
		return(0);
	} else if (sizeof(size_t) != (size_t)ssz) {
		warnx("short read: %s", name);
		return(0);
	}

	if (NULL == (*buf = malloc(sz)))
		err(EXIT_FAILURE, NULL);

	ssz = read(fd, *buf, sz);
	if (ssz < 0) {
		warn("read: %s", name);
		return(0);
	} else if (sz != (size_t)ssz) {
		warnx("short read: %s", name);
		return(0);
	}

	return(1);
}

/*
 * Read an integral token into "tok", if non-NULL.
 * Returns <0 on failure, 0 on disconnect, >0 on success.
 */
static int
read_token(int fd, const char *name, int *tok)
{
	ssize_t	 ssz;
	int	 code = 1;

	if (NULL == tok)
		tok = &code;

	ssz = read(fd, tok, sizeof(int));
	if (ssz < 0) {
		warn("read: %s", name);
		return(-1);
	} else if (0 == ssz) {
		return(0);
	} else if (sizeof(int) != (size_t)ssz) {
		warnx("short read: %s", name);
		return(-1);
	}

	return(1);
}

/*
 * A browsing event has occurred: entity down or up.
 * If down, pass it to the writer.
 * If up, resolve address and pass to hosts_resolv_hook().
 */
static void
hosts_browse_hook(struct mdns *m, int ev, 
	const char *name, const char *app, const char *proto)
{

	switch (ev) {
	case MDNS_SERVICE_UP:
		break;
	case MDNS_SERVICE_DOWN:
		if (name == NULL)
			return;
		if ( ! write_token(writer, "service down", 1))
			errx(EXIT_FAILURE, "write_token");
		if ( ! write_str(writer, "name", name))
			errx(EXIT_FAILURE, "write_str");
		return;
	default:
		errx(EXIT_FAILURE, "unhandled browse event");
		/* NOTREACHED */
	}

	if (name == NULL) {
		if (mdns_browse_add(m, app, proto) == -1)
			errx(EXIT_FAILURE, "mdns_browse_add");
	} else {
		if (mdns_resolve(m, name, app, proto) == -1)
			errx(EXIT_FAILURE, "mdns_resolve");
	}
}

/*
 * Address has been resolved.
 * Pass to the writer (entity up).
 */
static void
hosts_resolv_hook(struct mdns *m, int ev, struct mdns_service *ms)
{

	switch (ev) {
	case MDNS_RESOLVE_FAILURE:
		warnx("can't resolve: %s", ms->name);
		return;
	case MDNS_RESOLVE_SUCCESS:
		break;
	default:
		errx(EXIT_FAILURE, "unhandled resolve event");
		/* NOTREACHED */
	}

	if ( ! write_token(writer, "service up", 2))
		errx(EXIT_FAILURE, "write_token");
	if ( ! write_str(writer, "name", ms->name))
		errx(EXIT_FAILURE, "write_str");
	if ( ! write_buf(writer, "addr", &ms->addr, sizeof(ms->addr)))
		errx(EXIT_FAILURE, "write_buf");
	if ( ! write_str(writer, "target", ms->target))
		errx(EXIT_FAILURE, "write_str");
}

static int
proc_writer(int wfd, int rfd)
{
	int	 	 c, rc = 0, tok, change;
	struct hostdb	 db;
	size_t		 i;
	FILE		*f;
	char		*name = NULL, *target = NULL;
	struct hostent	*ent;
	struct in_addr	 addr;

	memset(&db, 0, sizeof(struct hostdb));

	/* Make us safe: trap us in /etc/mdns. */

	if (-1 == chroot("/etc/mdns")) {
		warn("chroot");
		return(0);
	} else if (-1 == chdir("/")) {
		warnx("chdir");
		return(0);
	} else if (-1 == pledge("stdio cpath wpath fattr rpath", NULL)) {
		warn("pledge");
		return(0);
	}

	/* Wait until the renamer has started up. */

	if (0 == (c = read_token(wfd, "renamer up", NULL))) {
		warnx("process down: renamer");
		return(0);
	} else if (-1 == c)
		return(0);

	/*
	 * Main loop: wait until we receive an update on our hosts, then
	 * flush any changes to the file hosts.
	 * Re-create this every time.
	 */

	for (;;) {
		if (0 == (c = read_token(rfd, "update", &tok))) {
			warnx("writer: updater has exited");
			rc = 1;
			break;
		} else if (c < 0)
			break;

		change = 0;

		/* Process addition or deletion. */

		if (1 == tok) {
			if ( ! read_str(rfd, "name", &name))
				break;

			if (NULL != (ent = db_lookup(&db, name))) {
				change = 1 == ent->refs;
				db_unref(ent);
			} else
				warnx("unknown service: %s", name);

			free(name);
			name = NULL;
		} else if (2 == tok) {
			if ( ! read_str(rfd, "name", &name))
				break;
			if ( ! read_buf(rfd, "addr", &addr, sizeof(addr)))
				break;
			if ( ! read_str(rfd, "target", &target))
				break;

			if (NULL != (ent = db_lookup(&db, name))) {
				free(name);
				change = 0 == ent->refs;
				db_ref(ent, target, &addr);
			} else {
				change = 1;
				db_add(&db, name, target, &addr);
			}
			name = target = NULL;
		} else 
			err(EXIT_FAILURE, "unknown token");

		if ( ! change)
			continue;

		if (NULL == (f = fopen("hosts", "a"))) {
			warn("/etc/mdns/hosts");
			break;
		}

		fprintf(f, "127.0.0.1 localhost\n");
		fprintf(f, "::1 localhost\n");
		for (i = 0; i < db.hostsz; i++) {
			fprintf(f, "%s %s\n", 
				inet_ntoa(db.hosts[i].addr), 
				db.hosts[i].target);
		}
		fclose(f);

		if (-1 == chmod("hosts", 0644)) {
			warn("/etc/mdns/hosts");
			break;
		}

		warnx("writer: created /etc/mdns/hosts");
		if ( ! write_token(wfd, "writer req", 1))
			break;
		if ( ! read_token(wfd, "writer resp", NULL))
			break;
		warnx("writer: changes flushed");
	}

	free(target);
	free(name);

	for (i = 0; i < db.hostsz; i++) {
		free(db.hosts[i].name);
		free(db.hosts[i].target);
	}

	free(db.hosts);
	return(rc);
}

static int
proc_renamer(int fd)
{
	int	 c, rc = 0;

	warnx("renamer: start");

	/* 
	 * Make us safe: chroot in /etc and pledge.
	 * We need to use rename(2) (and thus cpath) in this because
	 * /etc/hosts needs to have sane contents at all times.
	 */

	if (-1 == chroot("/etc")) {
		warn("chroot");
		return(0);
	} else if (-1 == chdir("/")) {
		warnx("chdir");
		return(0);
	} else if (-1 == pledge("stdio rpath cpath", NULL)) {
		warn("pledge");
		return(0);
	}

	warnx("renamer: /etc/hosts <-> /etc/hosts/mdns.save");

	/* Back up our current /etc/hosts. */

	if (-1 == link("hosts", "hosts.mdns.save")) {
		warn("link: /etc/hosts, /etc/hosts.mdns.save");
		return(0);
	}

	warnx("renamer: notifying reader");

	/* Notify the writer that we're ready. */

	if ( ! write_token(fd, "reader up", 1))
		return(0);

	/*
	 * Read loop.
	 * When our writer notifies us, we rename the hard-link.
	 * That's all.
	 */

	warnx("renamer: main loop");

	for (;;) {
		if (0 == (c = read_token(fd, "writer req", NULL))) {
			warnx("renamer: writer has exited");
			rc = 1;
			break;
		} else if (c < 0)
			break;

		warnx("renamer: /etc/mdns/hosts -> /etc/hosts");

		/*
		 * The /etc/mdns/hosts file is created and managed by
		 * another process.
		 * While we're in this section, this other process will
		 * not touch the file.
		 * It will then re-create it when more updates are
		 * necessary, leaving the inode secure.
		 */

		if (-1 == rename("mdns/hosts", "hosts")) {
			warn("rename: /etc/mdns/hosts, /etc/hosts");
			break;
		}

		if ( ! write_token(fd, "writer resp", 1))
			break;
	}

	/* Recovery: replace our /etc/hosts with the original. */

	warnx("renamer: /etc/hosts.mdns.save -> /etc/hosts");

	if (-1 == rename("hosts.mdns.save", "hosts")) {
		warn("rename: /etc/hosts.mdns.save, /etc/hosts");
		return(0);
	}

	warnx("renamer: /etc/hosts/mdns.save -> (remove)");
	remove("hosts.mdns.save");
	return(rc);
}

static	volatile sig_atomic_t doexit = 0;

static void
dosig(int code)
{

	doexit = 1;
}

int
main(int argc, char *argv[])
{
	int		 c, sockfd;
	int		 hsock[2], wsock[2];
	struct mdns	 mdns;
	ssize_t		 n;
	pid_t		 hpid, wpid;

	/*
	 * Create the renamer, which just sits there til it's woken, at
	 * which point it renames /etc/mdns/hosts as /etc/hosts.
	 */

	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, dosig);

	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, hsock))
		err(EXIT_FAILURE, "socketpair");
	if (-1 == socketpair(AF_UNIX, SOCK_STREAM, 0, wsock))
		err(EXIT_FAILURE, "socketpair");

	warnx("starting renamer");

	if (-1 == (hpid = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == hpid) {
		close(hsock[0]);
		close(wsock[0]);
		close(wsock[1]);
		c = proc_renamer(hsock[1]);
		close(hsock[1]);
		_exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(hsock[1]);

	warnx("starting writer");

	/*
	 * Create the writer.
	 * This keeps track of which hosts are up and down, and
	 * serialies these changes to a file.
	 * When it updates the file, it notifies the renamer.
	 */

	if (-1 == (wpid = fork()))
		err(EXIT_FAILURE, "fork");

	if (0 == wpid) {
		close(wsock[0]);
		c = proc_writer(hsock[0], wsock[1]);
		close(wsock[1]);
		close(hsock[1]);
		_exit(c ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	close(hsock[0]);
	close(wsock[1]);

	writer = wsock[0];

	warnx("updater: starting");

	signal(SIGINT, dosig);

	/*
	 * Now we just have a communicator to the writer in wsock[0].
	 * That's all we need.
	 * We'll use it to pass host updates.
	 */

	if (-1 == pledge("stdio unix", NULL))
		err(EXIT_FAILURE, NULL);

	if (-1 == (sockfd = mdns_open(&mdns)))
		err(EXIT_FAILURE, "mdns_open");

	if (-1 == pledge("stdio", NULL))
		err(EXIT_FAILURE, NULL);

	mdns_set_browse_hook(&mdns, hosts_browse_hook);
	mdns_set_resolve_hook(&mdns, hosts_resolv_hook);

	if (-1 == mdns_browse_add(&mdns, NULL, NULL))
		err(EXIT_FAILURE, "mdns_browse_add");

	warnx("updater: browse loop");

	while ( ! doexit) 
		if (-1 == (n = mdns_read(&mdns)))
			errx(EXIT_FAILURE, "mdns_read");
		else if (n == 0)
			errx(EXIT_FAILURE, "server closed socket");

	warnx("updater: exiting");

	mdns_close(&mdns);

	close(writer);
	close(sockfd);

	return(EXIT_SUCCESS);
}
