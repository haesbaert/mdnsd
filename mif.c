/*
 * Copyright (c) 2010 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <string.h>

#include "mdnsd.h"
#include "log.h"

struct mif *
mif_new(struct kif *k)
{
	struct mif	*mif;
	
	if ((mif = calloc(1, sizeof(struct mif))) == NULL)
		fatal("calloc");
	
	strlcpy(mif->ifname, k->ifname, sizeof(mif->ifname));
	mif->ifindex	= k->ifindex;
	mif->flags	= k->flags;
	mif->linkstate	= k->link_state;
	mif->media_type = k->media_type;
	mif->mtu	= k->mtu;
	
	return mif;
}
