PREFIX?=/usr/local
BINDIR=${PREFIX}/bin

PROG=	mdnshosts
SRCS=	main.c mdnsl.c 

CFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mdnsd
LDADD+= -lutil
DPADD+=  ${LIBUTIL}

MAN=	${PROG}.8

.include <bsd.prog.mk>
