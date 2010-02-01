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

extern struct mdnsd_conf *mconf;

const char *	mif_if_event_name(int);
const char *	mif_if_action_name(int);
const char *	mif_if_state_name(int);

struct {
	enum mif_if_state	state;
	enum mif_if_event	event;
	enum mif_if_action	action;
} mif_if_fsm[] = {
	/* current state	event that happened	action to take */
	{MIF_STA_DOWN,		MIF_EVT_UP,		MIF_ACT_START},
	{MIF_STA_DOWN,		MIF_EVT_DOWN,		MIF_ACT_NOTHING},
	{MIF_STA_ACTIVE,	MIF_EVT_DOWN,		MIF_ACT_SHUTDOWN},
	{MIF_STA_ACTIVE,	MIF_EVT_UP,		MIF_ACT_NOTHING},
	{0xFF,			MIF_EVT_NOTHING,	MIF_ACT_NOTHING},
};

static const char * const mif_if_state_names[] = {
	"ACTIVE",
	"DOWN"
};
	
static const char * const mif_if_action_names[] = {
	"NOTHING",
	"START",
	"SHUTDOWN"
};

static const char * const mif_if_event_names[] = {
	"NOTHING",
	"UP",
	"DOWN",
};

struct mif *
mif_new(struct kif *k)
{ 
	struct mif	*mif;
	
	if ((mif = calloc(1, sizeof(struct mif))) == NULL)
		fatal("calloc");
	
	strlcpy(mif->ifname, k->ifname, sizeof(mif->ifname));
	mif->ifindex = k->ifindex;
	mif->state = MIF_STA_DOWN;
/* 	mif->pipe   = -1; */
	
	return mif;
}

/* to be used in parent only */
struct mif *
mif_find_index(u_short ifindex)
{
	struct mif	 *mif;
	
	LIST_FOREACH(mif, &mconf->mif_list, entry) {
		if (mif->ifindex == ifindex)
			return mif;
	}

	return NULL;
}

int
mif_fsm(struct mif *mif, enum mif_if_event event)
{
	int i, ret = 0;
	enum mif_if_state old_state = mif->state;
	struct imsg imsg;
	
	bzero(&imsg, sizeof(struct imsg));
	
	for (i = 0; mif_if_fsm[i].state != 0xFF; i++)
		if (mif->state == mif_if_fsm[i].state)
			break;
	
	if (mif_if_fsm[i].state == 0xFF) {
		log_debug("mif_if_fsm: interface %s, "
		    "event '%s' not expected in state '%s'", mif->ifname,
		    mif_if_event_name(event), mif_if_state_name(mif->state));
		return -1;
	}
	
	switch (mif_if_fsm[i].action) {
	case MIF_ACT_START:
		log_debug("Sending start message to mif %s", mif->ifname);
		main_imsg_compose_mife(mif, IMSG_START, NULL, 0);
		mif->state = MIF_STA_ACTIVE;
		break;
	case MIF_ACT_SHUTDOWN:
		log_debug("Sending shutdown message to mif %s", mif->ifname);
		main_imsg_compose_mife(mif, IMSG_STOP, NULL, 0);
		mif->state = MIF_STA_DOWN;
		break;
	case MIF_ACT_NOTHING:
		/* do nothing */
		break;
	default:
		log_warn("mif_if_fsm: Unknown action");
		return -1;
	}

	log_debug("mif_if_fsm: event '%s' resulted in action '%s' and changing "
	    "state for interface %s from '%s' to '%s'",
	    mif_if_event_name(event), mif_if_action_name(mif_if_fsm[i].action),
	    mif->ifname, mif_if_state_name(old_state), mif_if_state_name(mif->state));

	return 0;
}

const char *
mif_if_event_name(int event)
{
	return (mif_if_event_names[event]);
}

const char *
mif_if_action_name(int action)
{
	return (mif_if_action_names[action]);
}

const char *
mif_if_state_name(int state)
{
	return mif_if_state_names[state];
}
