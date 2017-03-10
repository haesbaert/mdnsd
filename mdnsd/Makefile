PREFIX?=/usr/local
BINDIR=${PREFIX}/bin
MANDIR= ${PREFIX}/man/cat

PROG=	mdnsd
SRCS=	log.c mdnsd.c kiface.c interface.c packet.c \
	control.c mdns.c

MAN=	mdnsd.8

CFLAGS+= -g -Wall -I${.CURDIR} -I${.CURDIR}/../
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare

.if exists(${.CURDIR}/../libmdns/${__objdir})
LDADD+= -L${.CURDIR}/../libmdns/${__objdir} -lmdns
.else
LDADD+= -L${.CURDIR}/../libmdns -lmdns
.endif
LDADD+= -levent -lutil
DPADD+= ${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
.include <bsd.man.mk>
