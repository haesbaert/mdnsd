/*	$OpenBSD: log.c,v 1.6 2009/11/02 20:20:54 claudio Exp $ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "mdnsd.h"

int	debug;
int	verbose;

void	logit(int, const char *, ...);

#ifndef S
#define S(a) #a
#endif

#define LOG_DEBUG_STRUCT(x, field, how)		\
	log_debug("%s = " S(how), S(field), x->field)

void
log_init(int n_debug)
{
	extern char	*__progname;

	debug = n_debug;
	verbose = n_debug;

	if (!debug)
		openlog(__progname, LOG_NDELAY, LOG_DAEMON);

	tzset();
}

void
log_verbose(int v)
{
	verbose = v;
}

void
logit(int pri, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vlog(pri, fmt, ap);
	va_end(ap);
}

void
vlog(int pri, const char *fmt, va_list ap)
{
	char	*nfmt;

	if (debug) {
		/* best effort in out of mem situations */
		if (asprintf(&nfmt, "%s\n", fmt) == -1) {
			vfprintf(stderr, fmt, ap);
			fprintf(stderr, "\n");
		} else {
			vfprintf(stderr, nfmt, ap);
			free(nfmt);
		}
		fflush(stderr);
	} else
		vsyslog(pri, fmt, ap);
}

void
log_warn(const char *emsg, ...)
{
	char	*nfmt;
	va_list	 ap;

	/* best effort to even work in out of memory situations */
	if (emsg == NULL)
		logit(LOG_CRIT, "%s", strerror(errno));
	else {
		va_start(ap, emsg);

		if (asprintf(&nfmt, "%s: %s", emsg, strerror(errno)) == -1) {
			/* we tried it... */
			vlog(LOG_CRIT, emsg, ap);
			logit(LOG_CRIT, "%s", strerror(errno));
		} else {
			vlog(LOG_CRIT, nfmt, ap);
			free(nfmt);
		}
		va_end(ap);
	}
}

void
log_warnx(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_CRIT, emsg, ap);
	va_end(ap);
}

void
log_info(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_INFO, emsg, ap);
	va_end(ap);
}

void
log_debug(const char *emsg, ...)
{
	va_list	 ap;

	if (verbose) {
		va_start(ap, emsg);
		vlog(LOG_DEBUG, emsg, ap);
		va_end(ap);
	}
}

void
fatal(const char *emsg)
{
	if (emsg == NULL)
		logit(LOG_CRIT, "fatal: %s", strerror(errno));
	else
		if (errno)
			logit(LOG_CRIT, "fatal: %s: %s",
			    emsg, strerror(errno));
		else
			logit(LOG_CRIT, "fatal: %s", emsg);

	exit(1);
}

void
fatalx(const char *emsg)
{
	errno = 0;
	fatal(emsg);
}

const char *
if_state_name(int state)
{
	switch (state) {
	case IF_STA_DOWN:
		return ("DOWN");
	case IF_STA_ACTIVE:
		return ("ACTIVE");
	default:
		return ("UNKNOWN");
	}
}

const char *
rr_type_name(uint16_t type)
{
	switch(type) {
	case T_ANY:
		return "ANY";	/* NOTREACHED */
		break;
	case T_A:
		return "A";
		break;		/* NOTREACHED */
	case T_AAAA:
		return "AAAA";
		break;		/* NOTREACHED */
	case T_HINFO:
		return "HINFO";
		break;		/* NOTREACHED */
	case T_CNAME:
		return "CNAME";
		break;		/* NOTREACHED */
	case T_PTR:
		return "PTR";
		break;		/* NOTREACHED */
	case T_SRV:
		return "SRV";
		break;		/* NOTREACHED */
	case T_TXT:
		return "TXT";
		break;		/* NOTREACHED */
	case T_NS:
		return "NS";
		break;		/* NOTREACHED */
	default:
		log_debug("Unknown %d", type);
		break;		/* NOTREACHED */
	}

	return "Unknown";
}

void
log_debug_rr(struct rr *rr)
{
	log_debug("-->%s (%s)", rr->rrs.dname, rr_type_name(rr->rrs.type));

	switch(rr->rrs.type) {
	case T_A:
		log_debug("\t %s", inet_ntoa(rr->rdata.A));
		break;
	case T_HINFO:
		log_debug("\t cpu: %s", rr->rdata.HINFO.cpu);
		log_debug("\t os: %s",  rr->rdata.HINFO.os);
		break;
	case T_CNAME:
		log_debug("\t %s", rr->rdata.CNAME);
		break;
	case T_PTR:
		log_debug("\t %s", rr->rdata.PTR);
		break;
	case T_SRV:
		log_debug("\t dname: %s", rr->rdata.SRV.dname);
		log_debug("\t priority: %u", rr->rdata.SRV.priority);
		log_debug("\t weight: %u", rr->rdata.SRV.weight);
		log_debug("\t port: %u", rr->rdata.SRV.port);
		break;
	case T_TXT:
		log_debug("\t %s", rr->rdata.TXT);
		break;
	case T_NS:
		log_debug("\t %s", rr->rdata.NS);
		break;
	case T_AAAA:
		log_debug("\t implement me");
		break;
	default:
		log_debug("log_debug_rr: Unknown rr type");
		break;
	}
	log_debug("<--");
}
