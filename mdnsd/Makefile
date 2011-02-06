PROG=	mdnsd
SRCS=	log.c mdnsd.c kiface.c interface.c packet.c \
	control.c mdns.c ../mdnsctl/mdnsl.c

MAN=	mdnsd.8
VERSION=pre-alpha (2011-02-05)

CFLAGS+=-DVERSION="\"${VERSION}\""
CFLAGS+= -g -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
LDADD+= -levent -lutil
DPADD+= ${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
.include <bsd.man.mk>
