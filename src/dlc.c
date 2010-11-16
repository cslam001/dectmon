/*
 * dectmon DLC message reassembly
 *
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <dect/libdect.h>
#include <dectmon.h>
#include <mac.h>
#include <dlc.h>

#define dlc_print(fmt, args...)				\
	do {						\
		if (dumpopts & DECTMON_DUMP_DLC)	\
			printf(fmt, ## args);		\
	} while (0)

#if 1
#define lc_debug(lc, fmt, args...)	dlc_print(fmt, ## args)
#else
#define lc_debug(lc, fmt, args...)
#endif

static void dect_fa_parse_len(struct dect_fa_len *len,
			      const struct dect_msg_buf *mb)
{
	uint8_t l;

	l = mb->data[DECT_FA_LI_OFF];
	len->len  = (l & DECT_FA_LI_LENGTH_MASK) >> DECT_FA_LI_LENGTH_SHIFT;
	len->more = (l & DECT_FA_LI_M_FLAG);
}

static struct dect_lc *dect_lc_init(struct dect_mac_con *mc)
{
	struct dect_lc *lc;

	lc = calloc(1, sizeof(*lc));
	if ((mc->tbc->pmid & 0xf0000) != 0xe0000)
		lc->lsig = mc->tbc->pmid;
	return lc;
}

static bool dect_fa_frame_csum_verify(const struct dect_lc *lc,
				      struct dect_msg_buf *mb)
{
	uint8_t *data = mb->data;
	unsigned int i;
	uint8_t c0 = 0, c1 = 0;
	uint16_t t;

	data[mb->len - 2] ^= lc->lsig >> 8;
	data[mb->len - 1] ^= lc->lsig & 0xff;

	for (i = 0; i < mb->len; i++) {
		t = c0 + data[i];
		c0 = (t & 0xffU) + ((t >> 8) & 0x1U);
		t = c1 + c0;
		c1 = (t & 0xffU) + ((t >> 8) & 0x1U);
	}

	lc_debug(lc, "csum verify: lsig %.4x c0: %.2x c1: %.2x\n",
		 lc->lsig, c0, c1);
	return c0 == (uint8_t)~0 && c1 == (uint8_t)~0;
}

static const uint8_t channel_sdu_size[] = {
        [DECT_MC_C_S]	= DECT_C_S_SDU_SIZE,
        [DECT_MC_C_F]	= DECT_C_F_SDU_SIZE,
};

#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))

static struct dect_msg_buf *dect_lc_reassemble(struct dect_handle *dh,
					       struct dect_lc *lc,
					       enum dect_data_channels chan,
					       struct dect_msg_buf *mb)
{
	struct dect_fa_len fl;
	uint8_t sdu_len, len;

	sdu_len = channel_sdu_size[chan];
	if (lc->rx_buf == NULL) {
		dect_fa_parse_len(&fl, mb);
		len = fl.len;
		len += DECT_FA_HDR_SIZE + DECT_FA_CSUM_SIZE;

		lc->rx_len = roundup(len, sdu_len);
		lc->rx_buf = dect_mbuf_alloc(dh);
		if (lc->rx_buf == NULL)
			goto err;
	}

	memcpy(dect_mbuf_put(lc->rx_buf, sdu_len), mb->data, sdu_len);
	mb = NULL;

	if (lc->rx_buf->len >= lc->rx_len) {
		mb = lc->rx_buf;
		lc->rx_buf = NULL;

		if (mb->len != lc->rx_len)
			goto err;

		if (!dect_fa_frame_csum_verify(lc, mb))
			goto err;

		/* Trim checksum and filling */
		dect_fa_parse_len(&fl, mb);
		mb->len = fl.len + DECT_FA_HDR_SIZE;
		lc_debug(lc, "reassembled SDU len %u\n", mb->len);
	}

	return mb;

err:
	lc_debug(lc, "reassembly failed\n");
	return NULL;
}

void dect_mac_co_data_ind(struct dect_handle *dh, struct dect_mac_con *mc,
			  enum dect_data_channels chan,
			  struct dect_msg_buf *mb)
{
	struct dect_lc *lc;

	//printf("MAC_CO_DATA-ind\n");
	if (mc->lc == NULL) {
		lc = dect_lc_init(mc);
		if (lc == NULL)
			return;
		mc->lc = lc;
	}

	mb = dect_lc_reassemble(dh, mc->lc, chan, mb);
	if (mb != NULL && mb->len > DECT_FA_HDR_SIZE) {
		dect_mbuf_pull(mb, DECT_FA_HDR_SIZE);
		dect_dl_data_ind(dh, &mc->tbc->dl, mb);
	}
}
