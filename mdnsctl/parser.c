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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parser.h"

enum token_type {
	NOTOKEN,
	ENDTOKEN,
	KEYWORD,
	ADDRESS,
	FLAGS,
	HOSTNAME,
	PROTO,
	APPPROTO,
	BRFLAGS
};

struct token {
	enum token_type		 type;
	const char		*keyword;
	int			 value;
	const struct token	*next;
};

static const struct token t_main[];
static const struct token t_lkup[];
static const struct token t_browse_proto[];
static const struct token t_browse_app[];


static const struct token t_main[] = {
	{KEYWORD,	"lkup",		NONE,		t_lkup},
	{KEYWORD,	"browse",	NONE,		t_browse_app},
	{ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_lkup[] = {
	{ FLAGS	,	"-",		NONE,		t_lkup},
	{ ADDRESS,	"",		LOOKUP_ADDR,	NULL},
	{ HOSTNAME,     "",             LOOKUP,    	NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_browse_app[] = {
	{ BRFLAGS,	"-",		NONE,		t_browse_app},
	{ KEYWORD,	"all",		BROWSE_PROTO,	NULL},
	{ APPPROTO,	"",		NONE,		t_browse_proto},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static const struct token t_browse_proto[] = {
	{ PROTO,	"tcp",		BROWSE_PROTO,	NULL},
	{ PROTO,	"udp",		BROWSE_PROTO,	NULL},
	{ ENDTOKEN,	"",		NONE,		NULL}
};

static struct parse_result	res;

struct parse_result *
parse(int argc, char *argv[])
{
	const struct token	*table = t_main;
	const struct token	*match;

	bzero(&res, sizeof(res));

	while (argc >= 0) {
		if ((match = match_token(argv[0], table)) == NULL) {
			fprintf(stderr, "valid commands/args:\n");
			show_valid_args(table);
			return (NULL);
		}

		argc--;
		argv++;

		if (match->type == NOTOKEN || match->next == NULL)
			break;

		table = match->next;
	}

	if (argc > 0) {
		fprintf(stderr, "superfluous argument: %s\n", argv[0]);
		return (NULL);
	}

	return (&res);
}

const struct token *
match_token(const char *word, const struct token *table)
{
	u_int			 i, match;
	const struct token	*t = NULL;

	match = 0;

	for (i = 0; table[i].type != ENDTOKEN; i++) {
		switch (table[i].type) {
		case NOTOKEN:
			if (word == NULL || strlen(word) == 0) {
				match++;
				t = &table[i];
			}
			break;
		case BRFLAGS:
			if (parse_brflags(word, &res.flags)) {
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
			break;
		case FLAGS:
			if (parse_flags(word, &res.flags)) {
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
			break;
		case KEYWORD:
			if (word != NULL && strcmp(word, table[i].keyword)
			    == 0) {
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
			break;
		case PROTO:
			if (word != NULL && strcmp(word, table[i].keyword)
			    == 0) {
				res.proto = word;
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
			break;
		case ADDRESS:
			if (parse_addr(word, &res.addr)) {
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
			break;
		case HOSTNAME:
			if (parse_hostname(word, res.hostname)) {
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
			break;
		case APPPROTO:
			if (word && *word != '-' &&
			    (strcmp(word, "all") != 0)) {
				res.app = word;
				match++;
				t = &table[i];
				if (t->value)
					res.action = t->value;
			}
		case ENDTOKEN:
			break;
		}
	}

	if (match != 1) {
		if (word == NULL)
			fprintf(stderr, "missing argument:\n");
		else if (match > 1)
			fprintf(stderr, "ambiguous argument: %s\n", word);
		else if (match < 1)
			fprintf(stderr, "unknown argument: %s\n", word);
		return (NULL);
	}

	return (t);
}

void
show_valid_args(const struct token *table)
{
	int	i;

	for (i = 0; table[i].type != ENDTOKEN; i++) {
		switch (table[i].type) {
		case NOTOKEN:
			fprintf(stderr, "  <cr>\n");
			break;
		case KEYWORD:
			fprintf(stderr, "  %s\n", table[i].keyword);
			break;
		case PROTO:
			fprintf(stderr, "  %s\n", table[i].keyword);
			break;
		case ADDRESS:
			fprintf(stderr, "  <address>\n");
			break;
		case HOSTNAME:
			fprintf(stderr, "  <hostname.local>\n");
			break;
		case APPPROTO:
			fprintf(stderr, "  <application protocol>\n");
			break;
		case FLAGS:
			fprintf(stderr, "  <-ahst>\n");
			break;
		case BRFLAGS:
			fprintf(stderr, "  <-r>\n");
			break;
		case ENDTOKEN:
			break;
		}
	}
}

int
parse_addr(const char *word, struct in_addr *addr)
{
	struct in_addr	ina;
	
	if (word == NULL || !isdigit(*word))
		return (0);

	bzero(addr, sizeof(struct in_addr));
	bzero(&ina, sizeof(ina));
	if (inet_pton(AF_INET, word, &ina)) {
		addr->s_addr = ina.s_addr;
		return (1);
	}

	return (0);
}

int
parse_hostname(const char *word, char hostname[MAXHOSTNAMELEN])
{
	if (word == NULL || !isalpha(*word))
		return (0);
	
	if (strlen(word) < 7 ||	/* shorter host is a.local */
	    strcmp(&word[strlen(word) - 6], ".local") != 0) {
		fprintf(stderr, "Invalid domain, must be .local\n");
		return (0);
	}
	strlcpy(hostname, word, MAXHOSTNAMELEN);
		
	return (1);
}

int
parse_flags(const char *word, int *flags)
{
	int r = 0;
	
	if (word == NULL || *word != '-')
		return (r);
	word++;
	while(*word) {
		switch (*word) {
		case 'a':
			*flags |= F_A;
			r++;
			break;
		case 'h':
			*flags |= F_HINFO;
			r++;
			break;
		case 's':
			*flags |= F_SRV;
			r++;
			break;
		case 't':
			*flags |= F_TXT;
			r++;
			break;
		default:
			errx(1, "unknown flag -%c", *word);
		}
		word++;
	}
	
	return (r);
}

int
parse_brflags(const char *word, int *flags)
{
	int r = 0;
	
	if (word == NULL || *word != '-')
		return (r);
	word++;
	while(*word) {
		switch (*word) {
		case 'r':
			*flags |= F_RESOLV;
			r++;
			break;
		default:
			errx(1, "unknown flag -%c", *word);
		}
		word++;
	}
	
	return (r);
}
