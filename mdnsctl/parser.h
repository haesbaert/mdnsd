/*
 * Copyright (c) 2010 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 * Copyright (c) 2006 Michele Marchetto <mydecay@openbeer.it>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
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

#ifndef _PARSER_H_
#define _PARSER_H_

#include <sys/param.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>

/* FLAGS */
#define F_A		1
#define F_HINFO		2
#define F_SRV		4
#define F_TXT		8
#define F_PTR		16

/* BRFLAGS */
#define F_RESOLV	1

enum actions {
	NONE,
	LOOKUP,
	RLOOKUP,
	BROWSE_PROTO,
	PUBLISH
};

struct parse_result {
	struct in_addr	addr;
	int		flags;
	enum actions	action;
	char		hostname[MAXHOSTNAMELEN];
	const char	*proto;
	const char	*app;
	const char	*srvname;
	const char	*txtstring;
};

struct parse_result	*parse(int, char *[]);
const struct token	*match_token(const char *, const struct token *);
void			 show_valid_args(const struct token *);
int			 parse_addr(const char *, struct in_addr *);
int			 parse_hostname(const char *, char [MAXHOSTNAMELEN]);
int			 parse_proto(const char *, char [MAXHOSTNAMELEN]);
int			 parse_flags(const char *, int *);
int			 parse_brflags(const char *, int *);

#endif	/* _PARSER_H_ */
