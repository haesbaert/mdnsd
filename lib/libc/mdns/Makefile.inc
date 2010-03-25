#	$OpenBSD: Makefile.inc,v 1.7 2010/02/03 20:49:00 miod Exp $

# yp sources
.PATH: ${LIBCSRCDIR}/mdns

SRCS+= buffer.c imsg.c mdns.c
# MAN+=	ypclnt.3

# MLINKS+=ypclnt.3 yp_all.3 ypclnt.3 yp_bind.3 ypclnt.3 yp_first.3 \
# 	ypclnt.3 yp_get_default_domain.3 ypclnt.3 yp_maplist.3 \
# 	ypclnt.3 yp_master.3 ypclnt.3 yp_match.3 ypclnt.3 yp_next.3 \
# 	ypclnt.3 yp_order.3 ypclnt.3 yp_unbind.3 \
# 	ypclnt.3 yperr_string.3 ypclnt.3 ypprot_err.3
