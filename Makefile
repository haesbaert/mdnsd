PROG=	mdnsd
SRCS=	log.c mdnsd.c kiface.c interface.c packet.c cache.c \
	control.c imsg.c buffer.c mdns_api.c query.c

#MAN=	mdnsd.8

CFLAGS+= -g -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
LDADD+=	-levent
DPADD+= ${LIBEVENT}

.include <bsd.prog.mk>
