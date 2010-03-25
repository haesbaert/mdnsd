PROG=	mdnsctl
SRCS=	mdnsctl.c parser.c
CFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../
# LDADD+= -lmdns
# DPADD+= ${LIBMDNS}

#MAN=	mdns.8

.include <bsd.prog.mk>
