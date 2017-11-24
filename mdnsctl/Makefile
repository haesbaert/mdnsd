PREFIX?=/usr/local
BINDIR=${PREFIX}/bin
MANDIR= ${PREFIX}/man/cat

PROG=	mdnsctl
SRCS=	mdnsctl.c parser.c

CFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mdnsd

.if exists(${.CURDIR}/../libmdns/${__objdir})
LDADD+= -L${.CURDIR}/../libmdns/${__objdir} -lmdns
.else
LDADD+= -L${.CURDIR}/../libmdns -lmdns
.endif
LDADD+= -lutil
DPADD+=  ${LIBUTIL}

MAN=	mdnsctl.8

.include <bsd.prog.mk>
