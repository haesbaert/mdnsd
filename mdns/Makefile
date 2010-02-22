.PATH:		${.CURDIR}/../

PROG=	mdns
SRCS=	buffer.c imsg.c log.c mdns.c parser.c mdns_api.c
CFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../
#MAN=	mdns.8

.include <bsd.prog.mk>
