/*	$OpenBSD: log.h,v 1.5 2009/11/02 20:20:54 claudio Exp $ */

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

#ifndef _LOG_H_
#define	_LOG_H_

#include <stdarg.h>

#include "mdnsd.h"

void		log_init(int);
void		log_verbose(int);
void		vlog(int, const char *, va_list);
void		log_warn(const char *, ...);
void		log_warnx(const char *, ...);
void		log_info(const char *, ...);
void		log_debug(const char *, ...);
void		log_debug_rr(struct rr *);
void		fatal(const char *) __dead;
void		fatalx(const char *) __dead;
const char *	if_state_name(int);
const char *	if_type_name(enum iface_type);
const char *	if_action_name(int);
const char *	rr_type_name(uint16_t);
char *		rrs_str(struct rrset *);
char *		sa_str(struct sockaddr *);

#endif /* _LOG_H_ */
