.PATH:	${.CURDIR}/../mdnsd

PROG=	mdnsctl
SRCS=	mdnsctl.c parser.c mdnsl.c 

pCFLAGS+= -g -Wall
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
CFLAGS+= -I${.CURDIR} -I${.CURDIR}/../mdnsd
LDADD+= -lutil
DPADD+=  ${LIBUTIL}

#MAN=	mdnsctl.8

.include <bsd.prog.mk>
