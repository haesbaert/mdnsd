SUBDIR= libmdns mdnsctl mdnsd

.include <bsd.subdir.mk>

TAG_SUBDIRS+=mdnsd
TAG_SUBDIRS+=mdnsctl
TAG_SUBDIRS+=/usr/include
TAG_SUBDIRS+=/usr/src/lib/libevent

etags:
	find ${TAG_SUBDIRS} -type f -iname "*.[ch]" | \
		etags -o TAGS -
