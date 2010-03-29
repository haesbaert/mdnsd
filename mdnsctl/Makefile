.PATH:	${.CURDIR}/../mdnsd

PROG=	mdnsctl
SRCS=	mdnsctl.c parser.c mdnsl.c buffer.c imsg.c
CFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mdnsd
# LDADD+= -lmdns
# DPADD+= ${LIBMDNS}

#MAN=	mdnsctl.8

.include <bsd.prog.mk>
