PROG=	mdnsd
SRCS=	log.c mdnsd.c mif.c kiface.c mife.c imsg.c buffer.c interface.c

#MAN=	mdnsd.8

CFLAGS+= -g -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
LDADD+=	-levent
DPADD+= ${LIBEVENT}

.include <bsd.prog.mk>
