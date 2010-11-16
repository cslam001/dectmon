/*
 * dectmon MAC layer message tracing
 *
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <stdio.h>
#include <asm/byteorder.h>

#include <dect/libdect.h>
#include <dectmon.h>
#include <phl.h>
#include <mac.h>

#define BITS_PER_BYTE	8

#define mac_print(fmt, args...)				\
	do {						\
		if (dumpopts & DECTMON_DUMP_MAC)	\
			printf(fmt, ## args);		\
	} while (0)

/*
 * Tail message parsing/construction
 */

static enum dect_tail_identifications dect_parse_tail(const struct dect_msg_buf *mb)
{
	return mb->data[DECT_HDR_TA_OFF] & DECT_HDR_TA_MASK;
}

static uint8_t dect_parse_ari(struct dect_ari *ari, uint64_t a)
{
	ari->arc = (a & DECT_ARI_ARC_MASK) >> DECT_ARI_ARC_SHIFT;
	switch (ari->arc) {
	case DECT_ARC_A:
		ari->emc = (a & DECT_ARI_A_EMC_MASK) >> DECT_ARI_A_EMC_SHIFT;
		ari->fpn = (a & DECT_ARI_A_FPN_MASK) >> DECT_ARI_A_FPN_SHIFT;
		return DECT_ARC_A_LEN;
	case DECT_ARC_B:
		ari->eic = (a & DECT_ARI_B_EIC_MASK) >> DECT_ARI_B_EIC_SHIFT;
		ari->fpn = (a & DECT_ARI_B_FPN_MASK) >> DECT_ARI_B_FPN_SHIFT;
		ari->fps = (a & DECT_ARI_B_FPS_MASK) >> DECT_ARI_B_FPS_SHIFT;
		return DECT_ARC_B_LEN;
	case DECT_ARC_C:
		ari->poc = (a & DECT_ARI_C_POC_MASK) >> DECT_ARI_C_POC_SHIFT;
		ari->fpn = (a & DECT_ARI_C_FPN_MASK) >> DECT_ARI_C_FPN_SHIFT;
		ari->fps = (a & DECT_ARI_C_FPS_MASK) >> DECT_ARI_C_FPS_SHIFT;
		return DECT_ARC_C_LEN;
	case DECT_ARC_D:
		ari->gop = (a & DECT_ARI_D_GOP_MASK) >> DECT_ARI_D_GOP_SHIFT;
		ari->fpn = (a & DECT_ARI_D_FPN_MASK) >> DECT_ARI_D_FPN_SHIFT;
		return DECT_ARC_D_LEN;
	case DECT_ARC_E:
		ari->fil = (a & DECT_ARI_E_FIL_MASK) >> DECT_ARI_E_FIL_SHIFT;
		ari->fpn = (a & DECT_ARI_E_FPN_MASK) >> DECT_ARI_E_FPN_SHIFT;
		return DECT_ARC_E_LEN;
	default:
		return 0;
        }
}

static int dect_parse_identities_information(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_idi *idi = &tm->idi;
	uint8_t ari_len, rpn_len;

	ari_len = dect_parse_ari(&idi->pari, t << DECT_RFPI_ARI_SHIFT);
	if (ari_len == 0)
		return -1;
	rpn_len = BITS_PER_BYTE * DECT_NT_ID_RFPI_LEN - 1 - ari_len;

	idi->e   = (t & DECT_RFPI_E_FLAG);
	idi->rpn = (t >> DECT_RFPI_RPN_SHIFT) & ((1 << rpn_len) - 1);
	tm->type = DECT_TM_TYPE_ID;

	mac_print("identities information: E: %u class: %u EMC: %.4x "
		 "FPN: %.5x RPN: %x\n", idi->e, idi->pari.arc,
		 idi->pari.emc, idi->pari.fpn, idi->rpn);
	return 0;
}

static int dect_parse_static_system_information(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_ssi *ssi = &tm->ssi;

	ssi->nr	    = (t & DECT_QT_SSI_NR_FLAG);
	ssi->sn     = (t & DECT_QT_SSI_SN_MASK) >> DECT_QT_SSI_SN_SHIFT;
	ssi->sp     = (t & DECT_QT_SSI_SP_MASK) >> DECT_QT_SSI_SP_SHIFT;
	ssi->txs    = (t & DECT_QT_SSI_TXS_MASK) >> DECT_QT_SSI_TXS_SHIFT;
	ssi->mc     = (t & DECT_QT_SSI_MC_FLAG);
	ssi->rfcars = (t & DECT_QT_SSI_RFCARS_MASK) >> DECT_QT_SSI_RFCARS_SHIFT;
	ssi->cn     = (t & DECT_QT_SSI_CN_MASK) >> DECT_QT_SSI_CN_SHIFT;
	ssi->pscn   = (t & DECT_QT_SSI_PSCN_MASK) >> DECT_QT_SSI_PSCN_SHIFT;

	if (ssi->sn > 11 || ssi->cn > 9 || ssi->pscn > 9 || ssi->rfcars == 0)
		return -1;
	tm->type = DECT_TM_TYPE_SSI;

	mac_print("static system information: SN: %u CN: %u PSCN: %u NR: %u "
		  "Txs: %u Mc: %u RF-carriers: %x\n",
		  ssi->sn, ssi->cn, ssi->pscn, ssi->nr, ssi->txs, ssi->mc,
		  ssi->rfcars);
	return 0;
}

static int dect_parse_extended_rf_carrier_information(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_erfc *erfc = &tm->erfc;

	erfc->rfcars	 = (t & DECT_QT_ERFC_RFCARS_MASK) >>
			   DECT_QT_ERFC_RFCARS_SHIFT;
	erfc->band	 = (t & DECT_QT_ERFC_RFBAND_MASK) >>
			   DECT_QT_ERFC_RFBAND_SHIFT;
	erfc->num_rfcars = (t & DECT_QT_ERFC_NUM_RFCARS_MASK) >
			   DECT_QT_ERFC_NUM_RFCARS_SHIFT;
	tm->type = DECT_TM_TYPE_ERFC;

	mac_print("extended rf carrier information: RF-carriers: %.6x band: %u num: %u\n",
		  erfc->rfcars, erfc->band, erfc->num_rfcars);
	return 0;
}

static int dect_parse_fixed_part_capabilities(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_fpc *fpc = &tm->fpc;

	fpc->fpc = (t & DECT_QT_FPC_CAPABILITY_MASK) >>
		   DECT_QT_FPC_CAPABILITY_SHIFT;
	fpc->hlc = (t & DECT_QT_FPC_HLC_MASK) >> DECT_QT_FPC_HLC_SHIFT;
	tm->type = DECT_TM_TYPE_FPC;

	mac_print("fixed part capabilities: FPC: %.5x HLC: %.4x\n",
		  fpc->fpc, fpc->hlc);
	return 0;
}

static int dect_parse_extended_fixed_part_capabilities(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_efpc *efpc = &tm->efpc;

	efpc->fpc = (t & DECT_QT_EFPC_EFPC_MASK) >> DECT_QT_EFPC_EFPC_SHIFT;
	efpc->hlc = (t & DECT_QT_EFPC_EHLC_MASK) >> DECT_QT_EFPC_EHLC_SHIFT;
	tm->type  = DECT_TM_TYPE_EFPC;

	mac_print("extended fixed part capabilities: FPC: %.5x HLC: %.6x\n",
		  efpc->fpc, efpc->hlc);
	return 0;
}

static int dect_parse_extended_fixed_part_capabilities2(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_efpc2 *efpc2 = &tm->efpc2;

	efpc2->fpc = (t & DECT_QT_EFPC2_FPC_MASK) >> DECT_QT_EFPC2_FPC_SHIFT;
	efpc2->hlc = (t & DECT_QT_EFPC2_HLC_MASK) >> DECT_QT_EFPC2_HLC_SHIFT;
	tm->type   = DECT_TM_TYPE_EFPC2;

	mac_print("extended fixed part capabilities2: FPC: %x HLC: %x\n",
		  efpc2->fpc, efpc2->hlc);
	return 0;
}

static int dect_parse_sari(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_sari *sari = &tm->sari;

	sari->list_cycle = (((t & DECT_QT_SARI_LIST_CYCLE_MASK) >>
			     DECT_QT_SARI_LIST_CYCLE_SHIFT) + 1) * 2;
	sari->tari  = (t & DECT_QT_SARI_TARI_FLAG);
	sari->black = (t & DECT_QT_SARI_BLACK_FLAG);
	//dect_parse_ari(&sari->ari, t << DECT_QT_SARI_ARI_SHIFT);
	tm->type = DECT_TM_TYPE_SARI;

	mac_print("sari: cycle %u TARI: %u black: %u\n",
		  sari->list_cycle, sari->tari, sari->black);
	return 0;
}

static int dect_parse_multiframe_number(struct dect_tail_msg *tm, uint64_t t)
{
	tm->mfn.num = (t & DECT_QT_MFN_MASK) >> DECT_QT_MFN_SHIFT;
	tm->type = DECT_TM_TYPE_MFN;

	mac_print("multiframe number: %u\n", tm->mfn.num);
	return 0;
}

static int dect_parse_system_information(struct dect_tail_msg *tm, uint64_t t)
{
	/* clear of memcmp */
	memset(((void *)tm) + offsetof(struct dect_tail_msg, ssi), 0,
	       sizeof(*tm) - offsetof(struct dect_tail_msg, ssi));

	switch (t & DECT_QT_H_MASK) {
	case DECT_QT_SI_SSI:
	case DECT_QT_SI_SSI2:
		return dect_parse_static_system_information(tm, t);
	case DECT_QT_SI_ERFC:
		return dect_parse_extended_rf_carrier_information(tm, t);
	case DECT_QT_SI_FPC:
		return dect_parse_fixed_part_capabilities(tm, t);
	case DECT_QT_SI_EFPC:
		return dect_parse_extended_fixed_part_capabilities(tm, t);
	case DECT_QT_SI_EFPC2:
		return dect_parse_extended_fixed_part_capabilities2(tm, t);
	case DECT_QT_SI_SARI:
		return dect_parse_sari(tm, t);
	case DECT_QT_SI_MFN:
		return dect_parse_multiframe_number(tm, t);
	default:
		mac_print("unknown system information type %llx\n",
			  (unsigned long long)t & DECT_QT_H_MASK);
		return -1;
	}
}

static int dect_parse_blind_full_slots(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_bfs *bfs = &tm->bfs;

	bfs->mask = (t & DECT_PT_BFS_MASK) >> DECT_PT_BFS_SHIFT;
	tm->type = DECT_TM_TYPE_BFS;

	mac_print("page: RFPI: %.3x blind full slots: %.3x\n",
		  tm->page.rfpi, bfs->mask);
	return 0;
}

static int dect_parse_bearer_description(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_bearer_desc *bd = &tm->bd;

	bd->bt = (t & DECT_PT_INFO_TYPE_MASK);
	bd->sn = (t & DECT_PT_BEARER_SN_MASK) >> DECT_PT_BEARER_SN_SHIFT;
	bd->sp = (t & DECT_PT_BEARER_SP_MASK) >> DECT_PT_BEARER_SP_SHIFT;
	bd->cn = (t & DECT_PT_BEARER_CN_MASK) >> DECT_PT_BEARER_CN_SHIFT;
	if (bd->sn >= DECT_HALF_FRAME_SIZE)
		return -1;
	tm->type = DECT_TM_TYPE_BD;

	mac_print("page: RFPI: %.3x bearer description: BT: %llx SN: %u SP: %u CN: %u\n",
		  tm->page.rfpi, (unsigned long long)bd->bt, bd->sn, bd->sp, bd->cn);
	return 0;
}

static int dect_parse_rfp_identity(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_rfp_id *id = &tm->rfp_id;

	id->id = (t & DECT_PT_RFP_ID_MASK) >> DECT_PT_RFP_ID_SHIFT;
	tm->type = DECT_TM_TYPE_RFP_ID;

	mac_print("page: RFPI: %.3x RFP identity: %.3x\n",
		  tm->page.rfpi, id->id);
	return 0;
}

static int dect_parse_rfp_status(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_rfp_status *st = &tm->rfp_status;

	st->rfp_busy = t & DECT_PT_RFPS_RFP_BUSY_FLAG;
	st->sys_busy = t & DECT_PT_RFPS_SYS_BUSY_FLAG;
	tm->type = DECT_TM_TYPE_RFP_STATUS;

	mac_print("page: RFPI: %.3x RFP status: rfp_busy: %d sys_busy: %d\n",
		  tm->page.rfpi, st->rfp_busy, st->sys_busy);
	return 0;
}

static int dect_parse_active_carriers(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_active_carriers *ac = &tm->active_carriers;

	ac->active = (t & DECT_PT_ACTIVE_CARRIERS_MASK) >>
		     DECT_PT_ACTIVE_CARRIERS_SHIFT;
	tm->type = DECT_TM_TYPE_ACTIVE_CARRIERS;

	mac_print("page: RFPI: %.3x active carriers: %.3x\n",
		  tm->page.rfpi, ac->active);
	return 0;
}

static int dect_parse_paging_info(struct dect_tail_msg *tm, uint64_t t)
{
	switch (t & DECT_PT_INFO_TYPE_MASK) {
	case DECT_PT_IT_BLIND_FULL_SLOT:
		return dect_parse_blind_full_slots(tm, t);
	case DECT_PT_IT_OTHER_BEARER:
	case DECT_PT_IT_RECOMMENDED_OTHER_BEARER:
	case DECT_PT_IT_GOOD_RFP_BEARER:
	case DECT_PT_IT_DUMMY_OR_CL_BEARER_POSITION:
	case DECT_PT_IT_CL_BEARER_POSITION:
		return dect_parse_bearer_description(tm, t);
	case DECT_PT_IT_RFP_IDENTITY:
		return dect_parse_rfp_identity(tm, t);
	case DECT_PT_IT_DUMMY_OR_CL_BEARER_MARKER:
		mac_print("dummy or connectionless bearer marker\n");
		return 0;
	case DECT_PT_IT_RFP_STATUS:
		return dect_parse_rfp_status(tm, t);
	case DECT_PT_IT_ACTIVE_CARRIERS:
		return dect_parse_active_carriers(tm, t);
	default:
		mac_print("unknown paging info %llx\n",
			  (unsigned long long)t);
		return -1;
	}
}

static int dect_parse_paging_msg(struct dect_tail_msg *tm, uint64_t t)
{
	tm->page.extend = t & DECT_PT_HDR_EXTEND_FLAG;
	tm->page.length = t & DECT_PT_HDR_LENGTH_MASK;

	switch (tm->page.length) {
	case DECT_PT_ZERO_PAGE:
		tm->page.rfpi = (t & DECT_PT_ZP_RFPI_MASK) >>
				DECT_PT_ZP_RFPI_SHIFT;

		return dect_parse_paging_info(tm, t);
	case DECT_PT_SHORT_PAGE:
		tm->page.rfpi = 0;
		return dect_parse_paging_info(tm, t);
	case DECT_PT_FULL_PAGE:
	case DECT_PT_LONG_PAGE:
	case DECT_PT_LONG_PAGE_FIRST:
	case DECT_PT_LONG_PAGE_LAST:
	case DECT_PT_LONG_PAGE_ALL:
		tm->type = DECT_TM_TYPE_PAGE;
		mac_print("full/long page: extend: %u length: %llx\n",
			  tm->page.extend, (unsigned long long)tm->page.length);
		return 0;
	default:
		mac_print("invalid page length %llx\n",
			  (unsigned long long)tm->page.length);
		return -1;
	}
}

static int dect_parse_cctrl_common(struct dect_cctrl *cctl, uint64_t t)
{
	cctl->fmid = (t & DECT_CCTRL_FMID_MASK) >> DECT_CCTRL_FMID_SHIFT;
	cctl->pmid = (t & DECT_CCTRL_PMID_MASK) >> DECT_CCTRL_PMID_SHIFT;

	mac_print("cctrl: command: %llx FMID: %.3x PMID: %.5x\n",
		  (unsigned long long)cctl->cmd, cctl->fmid, cctl->pmid);
	return 0;
}

static int dect_parse_cctrl_attr(struct dect_cctrl *cctl, uint64_t t)
{
	cctl->ecn        = (t & DECT_CCTRL_ATTR_ECN_MASK) >> DECT_CCTRL_ATTR_ECN_SHIFT;
	cctl->lbn        = (t & DECT_CCTRL_ATTR_LBN_MASK) >> DECT_CCTRL_ATTR_LBN_SHIFT;
	cctl->type       = (t & DECT_CCTRL_ATTR_TYPE_MASK) >> DECT_CCTRL_ATTR_TYPE_SHIFT;
	cctl->service    = (t & DECT_CCTRL_ATTR_SERVICE_MASK) >> DECT_CCTRL_ATTR_SERVICE_SHIFT;
	cctl->slot       = (t & DECT_CCTRL_ATTR_SLOT_MASK) >> DECT_CCTRL_ATTR_SLOT_SHIFT;
	cctl->cf         = (t & DECT_CCTRL_ATTR_CF_FLAG);
	cctl->a_mod      = (t & DECT_CCTRL_ATTR_A_MOD_MASK) >> DECT_CCTRL_ATTR_A_MOD_SHIFT;
	cctl->bz_mod     = (t & DECT_CCTRL_ATTR_BZ_MOD_MASK) >> DECT_CCTRL_ATTR_BZ_MOD_SHIFT;
	cctl->bz_ext_mod = (t & DECT_CCTRL_ATTR_BZ_EXT_MOD_MASK) >> DECT_CCTRL_ATTR_BZ_EXT_MOD_SHIFT;
	cctl->acr        = (t & DECT_CCTRL_ATTR_ACR_MASK) >> DECT_CCTRL_ATTR_ACR_SHIFT;

	mac_print("cctrl: command: %llx ECN: %x LBN: %x type: %x "
		  "service: %x slot type: %x CF: %d A-modulation: %x "
		  "B/Z-modulation: %x B/Z extended modulation: %x ACR: %x\n",
		  (unsigned long long)cctl->cmd, cctl->ecn, cctl->lbn,
		  cctl->type, cctl->service, cctl->slot, cctl->cf,
		  cctl->a_mod, cctl->bz_mod, cctl->bz_ext_mod, cctl->acr);

	return 0;
}

static int dect_parse_cctrl_release(struct dect_cctrl *cctl, uint64_t t)
{
	cctl->lbn    = (t & DECT_CCTRL_RELEASE_LBN_MASK) >>
		       DECT_CCTRL_RELEASE_LBN_SHIFT;
	cctl->reason = (t & DECT_CCTRL_RELEASE_REASON_MASK) >>
		       DECT_CCTRL_RELEASE_REASON_SHIFT;
	cctl->pmid   = (t & DECT_CCTRL_RELEASE_PMID_MASK) >>
		       DECT_CCTRL_RELEASE_PMID_SHIFT;

	mac_print("cctrl: release: PMID: %.5x LBN: %x reason: %x\n",
		  cctl->pmid, cctl->lbn, cctl->reason);
	return 0;
}

static int dect_parse_basic_cctrl(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_cctrl *cctl = &tm->cctl;

	cctl->cmd = t & DECT_MT_CMD_MASK;
	switch (cctl->cmd) {
	case DECT_CCTRL_ACCESS_REQ:
	case DECT_CCTRL_BEARER_HANDOVER_REQ:
	case DECT_CCTRL_CONNECTION_HANDOVER_REQ:
	case DECT_CCTRL_UNCONFIRMED_ACCESS_REQ:
	case DECT_CCTRL_BEARER_CONFIRM:
	case DECT_CCTRL_WAIT:
		return dect_parse_cctrl_common(cctl, t);
	case DECT_CCTRL_ATTRIBUTES_T_REQUEST:
	case DECT_CCTRL_ATTRIBUTES_T_CONFIRM:
		return dect_parse_cctrl_attr(cctl, t);
	case DECT_CCTRL_RELEASE:
		return dect_parse_cctrl_release(cctl, t);
	default:
		mac_print("unknown basic cctrl command: %llx\n",
			  (unsigned long long)cctl->cmd);
		return -1;
	}
}

static int dect_parse_advanced_cctrl(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_cctrl *cctl = &tm->cctl;

	cctl->cmd = t & DECT_MT_CMD_MASK;
	switch (cctl->cmd) {
	case DECT_CCTRL_ACCESS_REQ:
	case DECT_CCTRL_BEARER_HANDOVER_REQ:
	case DECT_CCTRL_CONNECTION_HANDOVER_REQ:
	case DECT_CCTRL_UNCONFIRMED_ACCESS_REQ:
	case DECT_CCTRL_BEARER_CONFIRM:
	case DECT_CCTRL_WAIT:
	case DECT_CCTRL_UNCONFIRMED_DUMMY:
	case DECT_CCTRL_UNCONFIRMED_HANDOVER:
		return dect_parse_cctrl_common(cctl, t);
	case DECT_CCTRL_ATTRIBUTES_T_REQUEST:
	case DECT_CCTRL_ATTRIBUTES_T_CONFIRM:
		return dect_parse_cctrl_attr(cctl, t);
	case DECT_CCTRL_BANDWIDTH_T_REQUEST:
	case DECT_CCTRL_BANDWIDTH_T_CONFIRM:
		return -1;
	case DECT_CCTRL_RELEASE:
		return dect_parse_cctrl_release(cctl, t);
	default:
		mac_print("unknown advanced cctrl command: %llx\n",
			  (unsigned long long)cctl->cmd);
		return -1;
	}
}

static int dect_parse_encryption_ctrl(struct dect_tail_msg *tm, uint64_t t)
{
	struct dect_encctrl *ectl = &tm->encctl;

	ectl->cmd  = (t & DECT_ENCCTRL_CMD_MASK) >> DECT_ENCCTRL_CMD_SHIFT;
	ectl->fmid = (t & DECT_ENCCTRL_FMID_MASK) >> DECT_ENCCTRL_FMID_SHIFT;
	ectl->pmid = (t & DECT_ENCCTRL_PMID_MASK) >> DECT_ENCCTRL_PMID_SHIFT;
	mac_print("encctrl: command: %x FMID: %.4x PMID: %.5x\n",
		  ectl->cmd, ectl->fmid, ectl->pmid);
	return 0;
}

static int dect_parse_mac_ctrl(struct dect_tail_msg *tm, uint64_t t)
{
	switch (t & DECT_MT_HDR_MASK) {
	case DECT_MT_BASIC_CCTRL:
		if (dect_parse_basic_cctrl(tm, t) < 0)
			return -1;
		tm->type = DECT_TM_TYPE_BCCTRL;
		return 0;
	case DECT_MT_ADV_CCTRL:
		if (dect_parse_advanced_cctrl(tm, t) < 0)
			return -1;
		tm->type = DECT_TM_TYPE_ACCTRL;
		return 0;
	case DECT_MT_ENC_CTRL:
		if (dect_parse_encryption_ctrl(tm, t) < 0)
			return -1;
		tm->type = DECT_TM_TYPE_ENCCTRL;
		return 0;
	default:
		mac_print("Unknown MAC control %llx\n",
			  (unsigned long long)t & DECT_MT_HDR_MASK);
		return -1;
	}
}

static int dect_parse_ct_data(struct dect_tail_msg *tm, uint64_t t, uint8_t seq)
{
	struct dect_ct_data *ctd = &tm->ctd;

	ctd->seq = seq;
	tm->type = DECT_TM_TYPE_CT;
	mac_print("CS tail: sequence number: %u\n", seq);
	return 0;
}

static int dect_parse_tail_msg(struct dect_tail_msg *tm,
			       const struct dect_msg_buf *mb)
{
	uint64_t t;

	tm->type = DECT_TM_TYPE_INVALID;
	t = __be64_to_cpu(*(uint64_t *)&mb->data[DECT_T_FIELD_OFF]);

	switch (dect_parse_tail(mb)) {
	case DECT_TI_CT_PKT_0:
		return dect_parse_ct_data(tm, t, 0);
	case DECT_TI_CT_PKT_1:
		return dect_parse_ct_data(tm, t, 1);
	case DECT_TI_NT_CL:
		mac_print("connectionless: ");
	case DECT_TI_NT:
		return dect_parse_identities_information(tm, t);
	case DECT_TI_QT:
		return dect_parse_system_information(tm, t);
	case DECT_TI_PT:
		/* Paging tail in direction FP->PP, MAC control otherwise */
		if (mb->slot < 12)
			return dect_parse_paging_msg(tm, t);
	case DECT_TI_MT:
		return dect_parse_mac_ctrl(tm, t);
	default:
		mac_print("unknown tail %x\n", dect_parse_tail(mb));
		return -1;
	}
}

/*
 * TBC
 */

#define tbc_log(tbc, fmt, args...) \
	printf("TBC: PMID: %.5x FMID: %.3x: " fmt, \
	       (tbc)->pmid, (tbc)->fmid, ## args)

static void dect_tbc_release(struct dect_handle *dh, struct dect_tbc *tbc)
{
	struct dect_handle_priv *priv = dect_handle_priv(dh);

	tbc_log(tbc, "release\n");
	if (dect_timer_running(tbc->timer))
		dect_timer_stop(dh, tbc->timer);
	priv->slots[tbc->slot1] = NULL;
	priv->slots[tbc->slot2] = NULL;
	free(tbc);
}

static void dect_tbc_timeout(struct dect_handle *dh, struct dect_timer *timer)
{
	struct dect_tbc *tbc = dect_timer_data(timer);

	tbc_log(tbc, "timeout\n");
	dect_tbc_release(dh, tbc);
}

static struct dect_tbc *dect_tbc_init(struct dect_handle *dh,
				      const struct dect_tail_msg *tm,
				      uint8_t slot)
{
	struct dect_handle_priv *priv = dect_handle_priv(dh);
	uint8_t slot2 = dect_tdd_slot(slot);
	struct dect_tbc *tbc;

	tbc = calloc(1, sizeof(*tbc));
	if (tbc == NULL)
		goto err1;

	tbc->slot1 = slot;
	tbc->slot2 = slot2;
	tbc->fmid  = tm->cctl.fmid;
	tbc->pmid  = tm->cctl.pmid;

	tbc->timer = dect_timer_alloc(dh);
	if (tbc->timer == NULL)
		goto err2;
	dect_timer_setup(tbc->timer, dect_tbc_timeout, tbc);
	dect_timer_start(dh, tbc->timer, 5);

	tbc->mbc[DECT_MODE_FP].cs_seq  = 1;
	tbc->mbc[DECT_MODE_FP].cf_seq  = 1;
	tbc->mbc[DECT_MODE_FP].mc.tbc  = tbc;

	tbc->mbc[DECT_MODE_PP].cs_seq  = 1;
	tbc->mbc[DECT_MODE_PP].cf_seq  = 1;
	tbc->mbc[DECT_MODE_PP].mc.tbc  = tbc;

	tbc->dl.tbc		       = tbc;

	priv->slots[slot]  = tbc;
	priv->slots[slot2] = tbc;
	tbc_log(tbc, "establish: slot %u/%u\n", slot, slot2);

	return tbc;

err2:
	free(tbc);
err1:
	return NULL;
}

static void dect_dsc_cipher(struct dect_tbc *tbc, struct dect_msg_buf *mb)
{
	unsigned int i;
	uint8_t *ks;

	if (mb->slot < DECT_HALF_FRAME_SIZE)
		ks = tbc->ks;
	else
		ks = tbc->ks + 45;

	switch (mb->data[0] & DECT_HDR_TA_MASK) {
	case DECT_TI_CT_PKT_0:
	case DECT_TI_CT_PKT_1:
		for (i = 0; i < 5; i++)
			mb->data[i + 1] ^= ks[i];
	default:
		break;
	}

	for (i = 0; i < DECT_B_FIELD_SIZE; i++)
		mb->data[i + 8] ^= ks[i + 5];
}

static void dect_tbc_rcv(struct dect_handle *dh, struct dect_tbc *tbc,
			 struct dect_msg_buf *mb, struct dect_tail_msg *tm)
{
	enum dect_b_identifications b_id;
	struct dect_mbc *mbc;
	unsigned int i;
	uint8_t slot = mb->slot;
	bool cf;

	if (tbc->ciphered) {
		if (slot < DECT_HALF_FRAME_SIZE)
			dect_dsc_keystream(dect_dsc_iv(mb->mfn, mb->frame),
					   tbc->dl.pt->dck,
					   tbc->ks, sizeof(tbc->ks));
		dect_dsc_cipher(tbc, mb);
	}

	if (tm->type == DECT_TM_TYPE_ID) {
		dect_timer_stop(dh, tbc->timer);
		dect_timer_start(dh, tbc->timer, 5);
	}

	mbc = &tbc->mbc[slot < DECT_HALF_FRAME_SIZE ? DECT_MODE_FP : DECT_MODE_PP];
	b_id = (mb->data[0] & DECT_HDR_BA_MASK);

	if (tm->type == DECT_TM_TYPE_CT) {
		if (tm->ctd.seq != mbc->cs_seq) {
			tbc_log(tbc, "CS: incorrect seq: %u\n", tm->ctd.seq);
			return;
		}
		mbc->cs_seq = !mbc->cs_seq;

		dect_mbuf_pull(mb, 1);
		dect_mac_co_data_ind(dh, &mbc->mc, DECT_MC_C_S, mb);
		dect_mbuf_pull(mb, 7);
	} else
		dect_mbuf_pull(mb, 8);

	cf = true;
	switch (b_id) {
	case DECT_BI_ETYPE_NOT_ALL_CF_0:
	case DECT_BI_ETYPE_NOT_ALL_CF_1:
		mac_print("Not all CF\n");
		cf = false;
	case DECT_BI_ETYPE_CF_0:
	case DECT_BI_ETYPE_CF_1:
		if (((b_id >> DECT_HDR_BA_SHIFT) & 0x1) != mbc->cf_seq) {
			tbc_log(tbc, "CF: incorrect seq: %u\n", b_id & 0x1);
			return;
		}
		mbc->cf_seq = !mbc->cf_seq;

		for (i = 0; i < mb->len / 10; i++) {
			if (cf) {
				tbc_log(tbc, "CF: seq: %u\n", i);
				dect_mac_co_data_ind(dh, &mbc->mc, DECT_MC_C_F, mb);
			} else if (!(mb->data[0] & 0x80))
				cf = true;

			dect_mbuf_pull(mb, 10);
		}
		break;
	default:
		break;
	}

	switch (tm->type) {
	case DECT_TM_TYPE_BCCTRL:
	case DECT_TM_TYPE_ACCTRL:
		if (tm->cctl.cmd == DECT_CCTRL_RELEASE)
			dect_tbc_release(dh, tbc);
		break;
	case DECT_TM_TYPE_ENCCTRL:
		switch (tm->encctl.cmd) {
		case DECT_ENCCTRL_START_REQUEST:
			printf("\n");
			break;
		case DECT_ENCCTRL_START_CONFIRM:
		case DECT_ENCCTRL_START_GRANT:
			tbc_log(tbc, "ciphering enabled: %s\n",
			        slot < 12 ? "FP->PP" : "PP->FP");
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}

void dect_mac_rcv(struct dect_handle *dh, struct dect_msg_buf *mb)
{
	struct dect_handle_priv *priv = dect_handle_priv(dh);
	struct dect_tbc *tbc = priv->slots[mb->slot];
	enum dect_tail_identifications a_id;
	enum dect_b_identifications b_id;
	struct dect_tail_msg tm;

	a_id = (mb->data[0] & DECT_HDR_TA_MASK) >> DECT_HDR_TA_SHIFT;
	b_id = (mb->data[0] & DECT_HDR_BA_MASK) >> DECT_HDR_BA_SHIFT;
	mac_print("slot: %02u A: %x B: %x ", mb->slot, a_id, b_id);

	dect_parse_tail_msg(&tm, mb);
	//dect_hexdump("MAC RCV", mb->data, mb->len);

	if (tbc != NULL)
		return dect_tbc_rcv(dh, tbc, mb, &tm);

	switch (tm.type) {
	case DECT_TM_TYPE_BCCTRL:
	case DECT_TM_TYPE_ACCTRL:
		switch (tm.cctl.cmd) {
		case DECT_CCTRL_ACCESS_REQ:
		case DECT_CCTRL_BEARER_HANDOVER_REQ:
		case DECT_CCTRL_CONNECTION_HANDOVER_REQ:
			dect_tbc_init(dh, &tm, mb->slot);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}
