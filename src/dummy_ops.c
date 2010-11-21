/*
 * Copyright (c) 2010 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */


#include <dect/libdect.h>
#include <dectmon.h>
#include <ops.h>

/*
 * LLME Ops
 */

static void llme_mac_me_info_ind(struct dect_handle *dh,
				 const struct dect_ari *pari,
				 const struct dect_fp_capabilities *fpc)
{
}

static struct dect_llme_ops_ dummy_llme_ops;

/*
 * LCE Ops
 */

static bool lce_page_response(struct dect_handle *dh,
			      struct dect_lce_page_param *param)
{
	return false;
}

static void lce_group_ring_ind(struct dect_handle *dh,
			       enum dect_alerting_patterns pattern)
{
}

static struct dect_lce_ops dummy_lce_ops;

/*
 * CC Ops
 */

static void mncc_setup_ind(struct dect_handle *dh, struct dect_call *call,
			   struct dect_mncc_setup_param *param)
{
}

static void mncc_setup_ack_ind(struct dect_handle *dh, struct dect_call *call,
			       struct dect_mncc_setup_ack_param *param)
{
}

static void mncc_reject_ind(struct dect_handle *dh, struct dect_call *call,
			    enum dect_causes cause,
			    struct dect_mncc_release_param *param)
{
}

static void mncc_call_proc_ind(struct dect_handle *dh, struct dect_call *call,
			       struct dect_mncc_call_proc_param *param)
{
}

static void mncc_alert_ind(struct dect_handle *dh, struct dect_call *call,
			   struct dect_mncc_alert_param *param)
{
}

static void mncc_connect_ind(struct dect_handle *dh, struct dect_call *call,
			     struct dect_mncc_connect_param *param)
{
}

static void mncc_connect_cfm(struct dect_handle *dh, struct dect_call *call,
			     struct dect_mncc_connect_param *param)
{
}

static void mncc_release_ind(struct dect_handle *dh, struct dect_call *call,
			     struct dect_mncc_release_param *param)
{
}

static void mncc_release_cfm(struct dect_handle *dh, struct dect_call *call,
			     enum dect_causes cause,
			     struct dect_mncc_release_param *param)
{
}

static void mncc_facility_ind(struct dect_handle *dh, struct dect_call *call,
			      struct dect_mncc_facility_param *param)
{
}

static void mncc_info_ind(struct dect_handle *dh, struct dect_call *call,
			  struct dect_mncc_info_param *param)
{
}

static void mncc_modify_ind(struct dect_handle *dh, struct dect_call *call,
			    struct dect_mncc_modify_param *param)
{
}

static void mncc_modify_cfm(struct dect_handle *dh, struct dect_call *call,
			    bool success,
			    struct dect_mncc_modify_param *param)
{
}

static void mncc_hold_ind(struct dect_handle *dh, struct dect_call *call,
			  struct dect_mncc_hold_param *param)
{
}

static void mncc_hold_cfm(struct dect_handle *dh, struct dect_call *call,
			  struct dect_mncc_hold_param *param)
{
}

static void mncc_retrieve_ind(struct dect_handle *dh, struct dect_call *call,
			      struct dect_mncc_hold_param *param)
{
}

static void mncc_retrieve_cfm(struct dect_handle *dh, struct dect_call *call,
			      struct dect_mncc_hold_param *param)
{
}

static void mncc_iwu_info_ind(struct dect_handle *dh, struct dect_call *call,
			      struct dect_mncc_iwu_info_param *param)
{
}

static void dl_u_data_ind(struct dect_handle *dh, struct dect_call *call,
			  struct dect_msg_buf *mb)
{
}

static struct dect_cc_ops dummy_cc_ops;

/*
 * MM Ops
 */

static void mm_access_rights_ind(struct dect_handle *dh,
				 struct dect_mm_endpoint *mme,
				 struct dect_mm_access_rights_param *param)
{
	struct dect_mm_access_rights_param reply = {};

	dect_mm_access_rights_res(dh, mme, false, &reply);
}

static void mm_access_rights_cfm(struct dect_handle *dh,
				 struct dect_mm_endpoint *mme, bool accept,
				 struct dect_mm_access_rights_param *param)
{
}

static void mm_access_rights_terminate_ind(struct dect_handle *dh,
					   struct dect_mm_endpoint *mme,
					   struct dect_mm_access_rights_terminate_param *param)
{
	struct dect_mm_access_rights_terminate_param reply = {};

	dect_mm_access_rights_terminate_res(dh, mme, false, &reply);
}

static void mm_access_rights_terminate_cfm(struct dect_handle *dh,
					   struct dect_mm_endpoint *mme, bool accept,
					   struct dect_mm_access_rights_terminate_param *param)
{
}

static void mm_key_allocate_ind(struct dect_handle *dh,
				struct dect_mm_endpoint *mme,
				struct dect_mm_key_allocate_param *param)
{
}

static void mm_authenticate_ind(struct dect_handle *dh,
				struct dect_mm_endpoint *mme,
				struct dect_mm_authenticate_param *param)
{
	struct dect_mm_authenticate_param reply = {};

	dect_mm_authenticate_res(dh, mme, false, &reply);
}

static void mm_authenticate_cfm(struct dect_handle *dh,
				struct dect_mm_endpoint *mme, bool accept,
				struct dect_mm_authenticate_param *param)
{
}

static void mm_cipher_ind(struct dect_handle *dh,
			  struct dect_mm_endpoint *mme,
			  struct dect_mm_cipher_param *param)
{
	struct dect_mm_cipher_param reply = {};

	dect_mm_cipher_res(dh, mme, false, &reply, NULL);
}

static void mm_cipher_cfm(struct dect_handle *dh,
			  struct dect_mm_endpoint *mme, bool accept,
			  struct dect_mm_cipher_param *param)
{
}

static void mm_locate_ind(struct dect_handle *dh,
			  struct dect_mm_endpoint *mme,
			  struct dect_mm_locate_param *param)
{
	struct dect_mm_locate_param reply = {};

	dect_mm_locate_res(dh, mme, false, &reply);
}

static void mm_locate_cfm(struct dect_handle *dh,
			  struct dect_mm_endpoint *mme, bool accept,
			  struct dect_mm_locate_param *param)
{
}

static void mm_detach_ind(struct dect_handle *dh,
			  struct dect_mm_endpoint *mme,
			  struct dect_mm_detach_param *param)
{
}

static void mm_identity_ind(struct dect_handle *dh,
			    struct dect_mm_endpoint *mme,
			    struct dect_mm_identity_param *param)
{
}

static void mm_identity_cfm(struct dect_handle *dh,
			    struct dect_mm_endpoint *mme,
			    struct dect_mm_identity_param *param)
{
}

static void mm_identity_assign_ind(struct dect_handle *dh,
				   struct dect_mm_endpoint *mme,
				   struct dect_mm_identity_assign_param *param)
{
	struct dect_mm_identity_assign_param reply = {};

	dect_mm_identity_assign_res(dh, mme, false, &reply);
}

static void mm_identity_assign_cfm(struct dect_handle *dh,
				   struct dect_mm_endpoint *mme, bool accept,
				   struct dect_mm_identity_assign_param *param)
{
}

static void mm_info_ind(struct dect_handle *dh,
			struct dect_mm_endpoint *mme,
			struct dect_mm_info_param *param)
{
	struct dect_mm_info_param reply = {};

	dect_mm_info_res(dh, mme, false, &reply);
}

static void mm_info_cfm(struct dect_handle *dh,
			struct dect_mm_endpoint *mme, bool accept,
			struct dect_mm_info_param *param)
{
}

static void mm_iwu_ind(struct dect_handle *dh,
		       struct dect_mm_endpoint *mme,
		       struct dect_mm_iwu_param *param)
{
}

static struct dect_mm_ops dummy_mm_ops;

/*
 * SS Ops
 */

static void mnss_setup_ind(struct dect_handle *dh, struct dect_ss_endpoint *sse,
			   struct dect_mnss_param *param)
{

}

static void mnss_facility_ind(struct dect_handle *dh, struct dect_ss_endpoint *sse,
			      struct dect_mnss_param *param)
{

}

static void mnss_release_ind(struct dect_handle *dh, struct dect_ss_endpoint *sse,
			     struct dect_mnss_param *param)

{

}

static struct dect_ss_ops dummy_ss_ops;

/*
 * CLMS Ops
 */

static void mncl_unitdata_ind(struct dect_handle *dh,
			      enum dect_clms_message_types type,
			      struct dect_mncl_unitdata_param *param,
			      struct dect_msg_buf *mb)
{
}

static struct dect_clms_ops dummy_clms_ops;

void dect_dummy_ops_init(struct dect_ops *ops)
{
	struct dect_llme_ops_ *llme_ops;
	struct dect_lce_ops *lce_ops;
	struct dect_cc_ops *cc_ops;
	struct dect_mm_ops *mm_ops;
	struct dect_ss_ops *ss_ops;
	struct dect_clms_ops *clms_ops;

	if (!ops->llme_ops)
		ops->llme_ops = &dummy_llme_ops;
	llme_ops = (void *)ops->llme_ops;

	if (!llme_ops->mac_me_info_ind)
		llme_ops->mac_me_info_ind = llme_mac_me_info_ind;

	if (!ops->lce_ops)
		ops->lce_ops = &dummy_lce_ops;
	lce_ops = (void *)ops->lce_ops;

	if (!lce_ops->lce_page_response)
		lce_ops->lce_page_response = lce_page_response;
	if (!lce_ops->lce_group_ring_ind)
		lce_ops->lce_group_ring_ind = lce_group_ring_ind;

	if (!ops->cc_ops)
		ops->cc_ops = &dummy_cc_ops;
	cc_ops = (void *)ops->cc_ops;

	if (!cc_ops->mncc_setup_ind)
		cc_ops->mncc_setup_ind = mncc_setup_ind;
	if (!cc_ops->mncc_setup_ack_ind)
		cc_ops->mncc_setup_ack_ind = mncc_setup_ack_ind;
	if (!cc_ops->mncc_reject_ind)
		cc_ops->mncc_reject_ind = mncc_reject_ind;
	if (!cc_ops->mncc_call_proc_ind)
		cc_ops->mncc_call_proc_ind = mncc_call_proc_ind;
	if (!cc_ops->mncc_alert_ind)
		cc_ops->mncc_alert_ind = mncc_alert_ind;
	if (!cc_ops->mncc_connect_ind)
		cc_ops->mncc_connect_ind = mncc_connect_ind;
	if (!cc_ops->mncc_connect_cfm)
		cc_ops->mncc_connect_cfm = mncc_connect_cfm;
	if (!cc_ops->mncc_release_ind)
		cc_ops->mncc_release_ind = mncc_release_ind;
	if (!cc_ops->mncc_release_cfm)
		cc_ops->mncc_release_cfm = mncc_release_cfm;
	if (!cc_ops->mncc_facility_ind)
		cc_ops->mncc_facility_ind = mncc_facility_ind;
	if (!cc_ops->mncc_info_ind)
		cc_ops->mncc_info_ind = mncc_info_ind;
	if (!cc_ops->mncc_modify_ind)
		cc_ops->mncc_modify_ind = mncc_modify_ind;
	if (!cc_ops->mncc_modify_cfm)
		cc_ops->mncc_modify_cfm = mncc_modify_cfm;
	if (!cc_ops->mncc_hold_ind)
		cc_ops->mncc_hold_ind = mncc_hold_ind;
	if (!cc_ops->mncc_hold_cfm)
		cc_ops->mncc_hold_cfm = mncc_hold_cfm;
	if (!cc_ops->mncc_retrieve_ind)
		cc_ops->mncc_retrieve_ind = mncc_retrieve_ind;
	if (!cc_ops->mncc_retrieve_cfm)
		cc_ops->mncc_retrieve_cfm = mncc_retrieve_cfm;
	if (!cc_ops->mncc_iwu_info_ind)
		cc_ops->mncc_iwu_info_ind = mncc_iwu_info_ind;
	if (!cc_ops->dl_u_data_ind)
		cc_ops->dl_u_data_ind = dl_u_data_ind;

	if (!ops->mm_ops)
		ops->mm_ops = &dummy_mm_ops;
	mm_ops = (void *)ops->mm_ops;

	if (!mm_ops->mm_access_rights_ind)
		mm_ops->mm_access_rights_ind = mm_access_rights_ind;
	if (!mm_ops->mm_access_rights_cfm)
		mm_ops->mm_access_rights_cfm = mm_access_rights_cfm;
	if (!mm_ops->mm_access_rights_terminate_ind)
		mm_ops->mm_access_rights_terminate_ind = mm_access_rights_terminate_ind;
	if (!mm_ops->mm_access_rights_terminate_cfm)
		mm_ops->mm_access_rights_terminate_cfm = mm_access_rights_terminate_cfm;
	if (!mm_ops->mm_key_allocate_ind)
		mm_ops->mm_key_allocate_ind = mm_key_allocate_ind;
	if (!mm_ops->mm_authenticate_ind)
		mm_ops->mm_authenticate_ind = mm_authenticate_ind;
	if (!mm_ops->mm_authenticate_cfm)
		mm_ops->mm_authenticate_cfm = mm_authenticate_cfm;
	if (!mm_ops->mm_cipher_ind)
		mm_ops->mm_cipher_ind = mm_cipher_ind;
	if (!mm_ops->mm_cipher_cfm)
		mm_ops->mm_cipher_cfm = mm_cipher_cfm;
	if (!mm_ops->mm_locate_ind)
		mm_ops->mm_locate_ind = mm_locate_ind;
	if (!mm_ops->mm_locate_cfm)
		mm_ops->mm_locate_cfm = mm_locate_cfm;
	if (!mm_ops->mm_authenticate_ind)
		mm_ops->mm_detach_ind = mm_detach_ind;
	if (!mm_ops->mm_identity_ind)
		mm_ops->mm_identity_ind = mm_identity_ind;
	if (!mm_ops->mm_identity_cfm)
		mm_ops->mm_identity_cfm = mm_identity_cfm;
	if (!mm_ops->mm_identity_assign_ind)
		mm_ops->mm_identity_assign_ind = mm_identity_assign_ind;
	if (!mm_ops->mm_identity_assign_cfm)
		mm_ops->mm_identity_assign_cfm = mm_identity_assign_cfm;
	if (!mm_ops->mm_info_ind)
		mm_ops->mm_info_ind = mm_info_ind;
	if (!mm_ops->mm_info_cfm)
		mm_ops->mm_info_cfm = mm_info_cfm;
	if (!mm_ops->mm_iwu_ind)
		mm_ops->mm_iwu_ind = mm_iwu_ind;

	if (!ops->ss_ops)
		ops->ss_ops = &dummy_ss_ops;
	ss_ops = (void *)ops->ss_ops;

	if (!ss_ops->mnss_setup_ind)
		ss_ops->mnss_setup_ind = mnss_setup_ind;
	if (!ss_ops->mnss_facility_ind)
		ss_ops->mnss_facility_ind = mnss_facility_ind;
	if (!ss_ops->mnss_release_ind)
		ss_ops->mnss_release_ind = mnss_release_ind;

	if (!ops->clms_ops)
		ops->clms_ops = &dummy_clms_ops;
	clms_ops = (void *)ops->clms_ops;

	if (!clms_ops->mncl_unitdata_ind)
		clms_ops->mncl_unitdata_ind = mncl_unitdata_ind;
}
