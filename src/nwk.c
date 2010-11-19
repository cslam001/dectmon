/*
 * dectmon - NWK layer message parsing
 *
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include <dect/libdect.h>
#include <dect/s_fmt.h>
#include <dectmon.h>
#include <nwk.h>

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

static FILE *dect_keyfile_open(const char *mode)
{
	char name[PATH_MAX];

	snprintf(name, sizeof(name), "%s/%s", getenv("HOME"), "dectmon.keys");
	return fopen(name, mode);
}

static void dect_pt_write_uak(const struct dect_pt *pt)
{
	char ipei[DECT_IPEI_STRING_LEN];
	unsigned int i;
	FILE *f;

	f = dect_keyfile_open("w");
	if (f == NULL)
		return;
	dect_format_ipei_string(&pt->portable_identity->ipui.pun.n.ipei, ipei);

	fprintf(f, "%s|", ipei);
	for (i = 0; i < DECT_AUTH_KEY_LEN; i++)
		fprintf(f, "%02x", pt->uak[i]);
	fprintf(f, "\n");

	fclose(f);
}

static void dect_pt_read_uak(struct dect_pt *pt)
{
	char ipei[DECT_IPEI_STRING_LEN];
	uint8_t uak[DECT_AUTH_KEY_LEN];
	struct dect_ipui ipui;
	unsigned int i;
	FILE *f;

	f = dect_keyfile_open("r");
	if (f == NULL)
		return;

	if (fscanf(f, "%13s|", ipei) != 1)
		goto err;

	for (i = 0; i < DECT_AUTH_KEY_LEN; i++) {
		if (fscanf(f, "%02hhx", &uak[i]) != 1)
			goto err;
	}

	memset(&ipui, 0, sizeof(ipui));
	ipui.put = DECT_IPUI_N;
	if (!dect_parse_ipei_string(&ipui.pun.n.ipei, ipei))
		goto err;

	if (dect_ipui_cmp(&ipui, &pt->portable_identity->ipui))
		goto err;

	memcpy(pt->uak, uak, sizeof(pt->uak));
err:
	fclose(f);
}

static struct dect_pt *dect_pt_lookup(struct dect_handle *dh,
				      struct dect_ie_portable_identity *portable_identity)
{
	struct dect_handle_priv *priv = dect_handle_priv(dh);
	struct dect_pt *pt;

	list_for_each_entry(pt, &priv->pt_list, list) {
		if (!dect_ipui_cmp(&pt->portable_identity->ipui,
				   &portable_identity->ipui))
			return pt;
	}
	return NULL;
}

static struct dect_pt *dect_pt_init(struct dect_handle *dh,
				    struct dect_ie_portable_identity *portable_identity)
{
	struct dect_handle_priv *priv = dect_handle_priv(dh);
	struct dect_pt *pt;

	pt = calloc(1, sizeof(*pt));
	if (pt == NULL)
		return NULL;

	pt->portable_identity = dect_ie_hold(portable_identity);
	list_add_tail(&pt->list, &priv->pt_list);

	dect_pt_read_uak(pt);
	return pt;
}

static void dect_pt_track_key_allocation(struct dect_handle *dh,
					 struct dect_pt *pt, uint8_t msgtype,
					 const struct dect_sfmt_ie *ie,
					 struct dect_ie_common *common)
{
	uint8_t k[DECT_AUTH_KEY_LEN], ks[DECT_AUTH_KEY_LEN];
	uint8_t dck[DECT_CIPHER_KEY_LEN];
	uint8_t ac[DECT_AUTH_CODE_LEN];
	uint32_t res1;

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
		    (pt->last_msg != DECT_MM_KEY_ALLOCATE &&
		     pt->last_msg != DECT_MM_AUTHENTICATION_REQUEST))
			return;

		if (ie->id == DECT_IE_RES)
			pt->res =	(void *)__dect_ie_hold(common);

		pt->last_msg = msgtype;
		break;
	default:
		if (pt->procedure == DECT_MM_KEY_ALLOCATION) {
			dectmon_log("unexpected message during key allocation\n");
			goto release;
		}
		return;
	}

	if (pt->rs == NULL || pt->rand_f == NULL ||
	    pt->res == NULL)
		return;

	dect_pin_to_ac(auth_pin, ac, sizeof(ac));
	dect_auth_b1(ac, sizeof(ac), k);

	dect_auth_a11(k, pt->rs->value, ks);
	dect_auth_a12(ks, pt->rand_f->value, dck, &res1);

	if (res1 == pt->res->value) {
		dectmon_log("authentication ok\n");

		dect_auth_a21(k, pt->rs->value, ks);

		dect_hexdump("UAK", ks, sizeof(ks));
		memcpy(pt->uak, ks, sizeof(pt->uak));

		dect_hexdump("DCK", dck, sizeof(dck));
		memcpy(pt->dck, dck, sizeof(pt->dck));

		dect_pt_write_uak(pt);
	} else
		dectmon_log("authentication failed\n");

release:
	dect_ie_release(dh, pt->rs);
	dect_ie_release(dh, pt->rand_f);
	dect_ie_release(dh, pt->res);
	pt->procedure = DECT_MM_NONE;
}

static void dect_pt_track_auth(struct dect_handle *dh,
			       struct dect_pt *pt, uint8_t msgtype,
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
			dectmon_log("unexpected message during authentication\n");
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
		dectmon_log("authentication successful\n");
		if (pt->auth_type->flags & DECT_AUTH_FLAG_UPC) {
			dect_hexdump("DCK", dck, sizeof(dck));
			memcpy(pt->dck, dck, sizeof(pt->dck));
		}
	} else
		dectmon_log("authentication failed\n");

release:
	dect_ie_release(dh, pt->auth_type);
	dect_ie_release(dh, pt->rs);
	dect_ie_release(dh, pt->rand_f);
	dect_ie_release(dh, pt->res);
	pt->procedure = DECT_MM_NONE;
}

static void dect_pt_track_ciphering(struct dect_handle *dh,
				    struct dect_pt *pt, uint8_t msgtype,
				    const struct dect_sfmt_ie *ie,
				    struct dect_ie_common *common)
{
	switch (msgtype) {
	case DECT_MM_CIPHER_REQUEST:
		if (pt->procedure != DECT_MM_NONE)
			return;
		pt->dl->tbc->ciphered = true;
		break;
	default:
		return;
	}
}

static void dect_pt_track_audio(struct dect_handle *dh,
				struct dect_pt *pt, uint8_t msgtype,
				const struct dect_sfmt_ie *ie,
				struct dect_ie_common *common)
{
	struct dect_ie_progress_indicator *progress_indicator;

	switch (msgtype) {
	case DECT_CC_SETUP:
	case DECT_CC_SETUP_ACK:
	case DECT_CC_CALL_PROC:
	case DECT_CC_INFO:
	case DECT_CC_ALERTING:
		if (ie->id != DECT_IE_PROGRESS_INDICATOR)
			break;
		progress_indicator = (void *)common;
		if (progress_indicator->progress !=
		    DECT_PROGRESS_INBAND_INFORMATION_NOW_AVAILABLE)
			break;
		/* fall through */
	case DECT_CC_CONNECT:
		if (pt->ah == NULL)
			pt->ah = dect_audio_open();
		break;
	case DECT_CC_RELEASE:
	case DECT_CC_RELEASE_COM:
		if (pt->ah != NULL) {
			dect_audio_close(pt->ah);
			pt->ah = NULL;
		}
		break;
	}
}

void dect_dl_data_ind(struct dect_handle *dh, struct dect_dl *dl,
		      struct dect_msg_buf *mb)
{
	struct dect_pt *pt;
	struct dect_sfmt_ie ie;
	struct dect_ie_common *common;
	uint8_t msgtype;

	if (!(dumpopts & DECTMON_DUMP_NWK))
		return;

	msgtype = mb->data[1];

	dectmon_log("\n");
	dect_hexdump("NWK", mb->data, mb->len);
	dectmon_log("{%s} message:\n", nwk_msg_types[msgtype]);

	dect_mbuf_pull(mb, 2);
	while (mb->len) {
		if (dect_parse_sfmt_ie_header(&ie, mb) < 0)
			return;
		if (dect_parse_sfmt_ie(dh, ie.id, &common, &ie) < 0)
			return;

		if (ie.id == DECT_IE_PORTABLE_IDENTITY) {
			pt = dect_pt_lookup(dh, (void *)common);
			if (pt == NULL)
				pt = dect_pt_init(dh, (void *)common);
			dl->pt = pt;
			pt->dl = dl;
		}

		if (dl->pt != NULL) {
			dect_pt_track_key_allocation(dh, dl->pt, msgtype, &ie, common);
			dect_pt_track_auth(dh, dl->pt, msgtype, &ie, common);
			dect_pt_track_ciphering(dh, dl->pt, msgtype, &ie, common);
			dect_pt_track_audio(dh, dl->pt, msgtype, &ie, common);
		}

		__dect_ie_put(dh, common);
		dect_mbuf_pull(mb, ie.len);
	}
}

void dect_dl_u_data_ind(struct dect_handle *dh, struct dect_dl *dl, bool dir,
			struct dect_msg_buf *mb)
{
	struct dect_pt *pt = dl->pt;
	struct dect_msg_buf *clone;

	if (pt == NULL || pt->ah == NULL)
		return;

	/* Clone message buffer - audio is processed asynchronously, so we can't
	 * use the on-stack buffer
	 */
	clone = dect_mbuf_alloc(dh);
	if (clone == NULL)
		return;

	mb->len = 40;
	memcpy(dect_mbuf_put(clone, mb->len), mb->data, mb->len);
	dect_audio_queue(pt->ah, dir, clone);
}
