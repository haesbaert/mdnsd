LIB= mdns
SRCS+= mdnsl.c

CFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mdnsd
LDADD+= ${.CURDIR}/../libmdns -lmdns
LDADD+= -lutil
DPADD+=  ${LIBUTIL}

.include <bsd.lib.mk>
