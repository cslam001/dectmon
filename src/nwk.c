/*
 * dectmon - NWK layer message parsing
 *
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdio.h>

#include <dect/libdect.h>
#include <dect/s_fmt.h>
#include <dectmon.h>
#include <nwk.h>

static LIST_HEAD(dect_pt_list);

static const char * const nwk_msg_types[256] = {
	[DECT_LCE_PAGE_RESPONSE]			= "LCE-PAGE-RESPONSE",
	[DECT_LCE_PAGE_REJECT]				= "LCE-PAGE-REJECT",
	[DECT_CC_ALERTING]				= "CC-ALERTING",
	[DECT_CC_CALL_PROC]				= "CC-CALL-PROC",
	[DECT_CC_SETUP]					= "CC-SETUP",
	[DECT_CC_CONNECT]				= "CC-CONNECT",
	[DECT_CC_SETUP_ACK]				= "CC-SETUP-ACK",
	[DECT_CC_CONNECT_ACK]				= "CC-CONNECT-ACK",
	[DECT_CC_SERVICE_CHANGE]			= "CC-SERVICE-CHANGE",
	[DECT_CC_SERVICE_ACCEPT]			= "CC-SERVICE-ACCEPT",
	[DECT_CC_SERVICE_REJECT]			= "CC-SERVICE-REJECT",
	[DECT_CC_RELEASE]				= "CC-RELEASE",
	[DECT_CC_RELEASE_COM]				= "CC-RELEASE-COM",
	[DECT_CC_IWU_INFO]				= "CC-IWU-INFO",
	[DECT_CC_NOTIFY]				= "CC-NOTIFY",
	[DECT_CC_INFO]					= "CC-INFO",
	[DECT_CISS_FACILITY]				= "CISS-FACILITY",
	[DECT_CISS_REGISTER]				= "CISS-REGISTER",
	[DECT_MM_AUTHENTICATION_REQUEST]		= "MM-AUTHENTICATION-REQUEST",
	[DECT_MM_AUTHENTICATION_REPLY]			= "MM-AUTHENTICATION-REPLY",
	[DECT_MM_KEY_ALLOCATE]				= "MM-KEY-ALLOCATE",
	[DECT_MM_AUTHENTICATION_REJECT]			= "MM-AUTHENTICATION-REJECT",
	[DECT_MM_ACCESS_RIGHTS_REQUEST]			= "MM-ACCESS-RIGHTS-REQUEST",
	[DECT_MM_ACCESS_RIGHTS_ACCEPT]			= "MM-ACCESS-RIGHTS-ACCEPT",
	[DECT_MM_ACCESS_RIGHTS_REJECT]			= "MM-ACCESS-RIGHTS-REJECT",
	[DECT_MM_ACCESS_RIGHTS_TERMINATE_REQUEST]	= "MM-ACCESS-RIGHTS-TERMINATE-REQUEST",
	[DECT_MM_ACCESS_RIGHTS_TERMINATE_ACCEPT]	= "MM-ACCESS-RIGHTS-TERMINATE-ACCEPT",
	[DECT_MM_ACCESS_RIGHTS_TERMINATE_REJECT]	= "MM-ACCESS-RIGHTS-TERMINATE-REJECT",
	[DECT_MM_CIPHER_REQUEST]			= "MM-CIPHER-REQUEST",
	[DECT_MM_CIPHER_SUGGEST]			= "MM-CIPHER-SUGGEST",
	[DECT_MM_CIPHER_REJECT]				= "MM-CIPHER-REJECT",
	[DECT_MM_INFO_REQUEST]				= "MM-INFO-REQUEST",
	[DECT_MM_INFO_ACCEPT]				= "MM-INFO-ACCEPT",
	[DECT_MM_INFO_SUGGEST]				= "MM-INFO-SUGGEST",
	[DECT_MM_INFO_REJECT]				= "MM-INFO-REJECT",
	[DECT_MM_LOCATE_REQUEST]			= "MM-LOCATE-REQUEST",
	[DECT_MM_LOCATE_ACCEPT]				= "MM-LOCATE-ACCEPT",
	[DECT_MM_DETACH]				= "MM-DETACH",
	[DECT_MM_LOCATE_REJECT]				= "MM-LOCATE-REJECT",
	[DECT_MM_IDENTITY_REQUEST]			= "MM-IDENTITY-REQUEST",
	[DECT_MM_IDENTITY_REPLY]			= "MM-IDENTITY-REPLY",
	[DECT_MM_IWU]					= "MM-IWU",
	[DECT_MM_TEMPORARY_IDENTITY_ASSIGN]		= "MM-TEMPORARY-IDENTITY-ASSIGN",
	[DECT_MM_TEMPORARY_IDENTITY_ASSIGN_ACK]		= "MM-TEMPORARY-IDENTITY-ASSIGN-ACK",
	[DECT_MM_TEMPORARY_IDENTITY_ASSIGN_REJ]		= "MM-TEMPORARY-IDENTITY-ASSIGN-REJ",
};

#define dect_ie_release(dh, ie) 		\
	do { 					\
		if (ie != NULL)			\
			dect_ie_put(dh, ie);	\
		ie = NULL;			\
	} while (0)

static struct dect_pt *dect_pt_lookup(struct dect_ie_portable_identity *portable_identity)
{
	struct dect_pt *pt;

	list_for_each_entry(pt, &dect_pt_list, list) {
		if (!dect_ipui_cmp(&pt->portable_identity->ipui,
				   &portable_identity->ipui))
			return pt;
	}
	return NULL;
}

static struct dect_pt *dect_pt_init(struct dect_ie_portable_identity *portable_identity)
{
	struct dect_pt *pt;

	pt = calloc(1, sizeof(*pt));
	if (pt == NULL)
		return NULL;

	pt->portable_identity = dect_ie_hold(portable_identity);
	list_add_tail(&pt->list, &dect_pt_list);

	return pt;
}

static void dect_pt_track_key_allocation(struct dect_pt *pt, uint8_t msgtype,
					 const struct dect_sfmt_ie *ie,
					 struct dect_ie_common *common)
{
	uint8_t k[DECT_AUTH_KEY_LEN], ks[DECT_AUTH_KEY_LEN];
	uint8_t dck[DECT_CIPHER_KEY_LEN];
	uint32_t res1;
	uint8_t ac[4];

	switch (msgtype) {
	case DECT_MM_KEY_ALLOCATE:
		if (pt->procedure != DECT_MM_NONE &&
		    pt->procedure != DECT_MM_KEY_ALLOCATION)
			return;

		if (ie->id == DECT_IE_RS)
			pt->rs =	(void *)__dect_ie_hold(common);
		if (ie->id == DECT_IE_RAND)
			pt->rand_f =	(void *)__dect_ie_hold(common);

		pt->procedure = DECT_MM_KEY_ALLOCATION;
		pt->last_msg  = msgtype;
		return;
	case DECT_MM_AUTHENTICATION_REQUEST:
		if (pt->procedure != DECT_MM_KEY_ALLOCATION ||
		    pt->last_msg != DECT_MM_KEY_ALLOCATE)
			return;

		if (ie->id == DECT_IE_RES)
			pt->res =	(void *)__dect_ie_hold(common);

		pt->last_msg = msgtype;
		break;
	default:
		if (pt->procedure == DECT_MM_KEY_ALLOCATION) {
			printf("unexpected message during key allocation\n");
			goto release;
		}
		return;
	}

	if (pt->rs == NULL || pt->rand_f == NULL ||
	    pt->res == NULL)
		return;

	dect_pin_to_ac("0000", ac, sizeof(ac));
	dect_auth_b1(ac, sizeof(ac), k);

	dect_auth_a11(k, pt->rs->value, ks);
	dect_auth_a12(ks, pt->rand_f->value, dck, &res1);

	if (res1 == pt->res->value) {
		printf("authentication ok\n");

		dect_auth_a21(k, pt->rs->value, ks);

		dect_hexdump("UAK", ks, sizeof(ks));
		memcpy(pt->uak, ks, sizeof(pt->uak));

		dect_hexdump("DCK", dck, sizeof(dck));
		memcpy(pt->dck, dck, sizeof(pt->dck));
	} else
		printf("authentication failed\n");

release:
	dect_ie_release(dh, pt->portable_identity);
	dect_ie_release(dh, pt->rs);
	dect_ie_release(dh, pt->rand_f);
	dect_ie_release(dh, pt->res);
	pt->procedure = DECT_MM_NONE;
}

static void dect_pt_track_auth(struct dect_pt *pt, uint8_t msgtype,
			       const struct dect_sfmt_ie *ie,
			       struct dect_ie_common *common)
{
	uint8_t k[DECT_AUTH_KEY_LEN], ks[DECT_AUTH_KEY_LEN];
	uint8_t dck[DECT_CIPHER_KEY_LEN];
	struct dect_ie_auth_res res1;

	switch (msgtype) {
	case DECT_MM_AUTHENTICATION_REQUEST:
		if (pt->procedure != DECT_MM_NONE &&
		    pt->procedure != DECT_MM_AUTHENTICATION)
			return;

		if (ie->id == DECT_IE_AUTH_TYPE)
			pt->auth_type = (void *)__dect_ie_hold(common);
		if (ie->id == DECT_IE_RS)
			pt->rs =	(void *)__dect_ie_hold(common);
		if (ie->id == DECT_IE_RAND)
			pt->rand_f =	(void *)__dect_ie_hold(common);

		pt->procedure = DECT_MM_AUTHENTICATION;
		pt->last_msg  = msgtype;
		return;
	case DECT_MM_AUTHENTICATION_REPLY:
		if (pt->procedure != DECT_MM_AUTHENTICATION ||
		    pt->last_msg != DECT_MM_AUTHENTICATION_REQUEST)
			return;

		if (ie->id == DECT_IE_RES)
			pt->res		= (void *)__dect_ie_hold(common);
		break;
	default:
		if (pt->procedure == DECT_MM_AUTHENTICATION) {
			printf("unexpected message during authentication\n");
			goto release;
		}
		return;
	}

	if (pt->auth_type == NULL || pt->rs == NULL || pt->rand_f == NULL ||
	    pt->res == NULL)
		return;

	dect_auth_b1(pt->uak, sizeof(pt->uak), k);

	dect_auth_a11(k, pt->rs->value, ks);
	dect_auth_a12(ks, pt->rand_f->value, dck, &res1.value);

	if (res1.value == pt->res->value) {
		printf("authentication successful\n");
		if (pt->auth_type->flags & DECT_AUTH_FLAG_UPC)
			memcpy(pt->dck, dck, sizeof(pt->dck));
	} else
		printf("authentication failed\n");

release:
	dect_ie_release(dh, pt->auth_type);
	dect_ie_release(dh, pt->rs);
	dect_ie_release(dh, pt->rand_f);
	dect_ie_release(dh, pt->res);
	pt->procedure = DECT_MM_NONE;
}

static void dect_pt_track_ciphering(struct dect_pt *pt, uint8_t msgtype,
				    const struct dect_sfmt_ie *ie,
				    struct dect_ie_common *common)
{
	switch (msgtype) {
	case DECT_MM_CIPHER_REQUEST:
		if (pt->procedure != DECT_MM_NONE)
			return;
		pt->tbc->ciphered = true;
		break;
	default:
		return;
	}
}

void dect_dl_data_ind(struct dect_dl *dl, struct dect_msg_buf *mb)
{
	struct dect_pt *pt;
	struct dect_sfmt_ie ie;
	struct dect_ie_common *common;
	uint8_t msgtype;

	if (!(dumpopts & DECTMON_DUMP_NWK))
		return;

	msgtype = mb->data[1];

	printf("\n");
	dect_hexdump("NWK", mb->data, mb->len);
	printf("{%s} message:\n", nwk_msg_types[msgtype]);

	dect_mbuf_pull(mb, 2);
	while (mb->len) {
		if (dect_parse_sfmt_ie_header(&ie, mb) < 0)
			return;
		if (dect_parse_sfmt_ie(dh, ie.id, &common, &ie) < 0)
			return;

		if (ie.id == DECT_IE_PORTABLE_IDENTITY) {
			pt = dect_pt_lookup((void *)common);
			if (pt == NULL)
				pt = dect_pt_init((void *)common);
			dl->pt = pt;
		}

		if (dl->pt != NULL) {
			dect_pt_track_key_allocation(dl->pt, msgtype, &ie, common);
			dect_pt_track_auth(dl->pt, msgtype, &ie, common);
			dect_pt_track_ciphering(dl->pt, msgtype, &ie, common);
		}

		__dect_ie_put(dh, common);
		dect_mbuf_pull(mb, ie.len);
	}
}
