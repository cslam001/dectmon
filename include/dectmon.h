#ifndef _DECTMON_H
#define _DECTMON_H

#include <stdbool.h>
#include <list.h>
#include <dect/auth.h>

extern struct dect_handle *dh;

enum {
	DECTMON_DUMP_MAC	= 0x1,
	DECTMON_DUMP_DLC	= 0x2,
	DECTMON_DUMP_NWK	= 0x4,
};

extern uint32_t dumpopts;

struct dect_ops;
extern int dect_event_ops_init(struct dect_ops *ops);
extern void dect_event_loop_stop(void);
extern void dect_event_loop(void);
extern void dect_event_ops_cleanup(void);
extern void dect_dummy_ops_init(struct dect_ops *ops);

extern void dect_hexdump(const char *prefix, const uint8_t *buf, size_t size);

enum dect_mm_procedures {
	DECT_MM_NONE,
	DECT_MM_KEY_ALLOCATION,
	DECT_MM_AUTHENTICATION,
	DECT_MM_CIPHERING,
};


struct dect_pt {
	struct list_head			list;
	struct dect_ie_portable_identity	*portable_identity;
	struct dect_tbc				*tbc;

	uint8_t					uak[DECT_AUTH_KEY_LEN];
	uint8_t					dck[DECT_CIPHER_KEY_LEN];

	enum dect_mm_procedures			procedure;
	uint8_t					last_msg;

	struct dect_ie_auth_type		*auth_type;
	struct dect_ie_auth_value		*rand_f;
	struct dect_ie_auth_value		*rs;
	struct dect_ie_auth_res			*res;
};

/* DLC */

struct dect_dl {
	struct dect_pt				*pt;
	struct dect_tbc				*tbc;
};

struct dect_msg_buf;
extern void dect_dl_data_ind(struct dect_dl *dl, struct dect_msg_buf *mb);

struct dect_lc {
	uint16_t				lsig;
	struct dect_msg_buf			*rx_buf;
	uint8_t					rx_len;
};

struct dect_mac_con {
	struct dect_lc				*lc;
	uint32_t				pmid;
	struct dect_tbc				*tbc;
};

enum dect_data_channels;
extern void dect_mac_co_data_ind(struct dect_mac_con *mc,
				 enum dect_data_channels chan,
				 struct dect_msg_buf *mb);

/* MAC */

struct dect_mbc {
	bool					cs_seq;
	bool					cf_seq;
	struct dect_mac_con			mc;
};

struct dect_tbc {
	struct dect_mbc				mbc[2];
	struct dect_dl				dl;
	bool					ciphered;
};

extern void dect_mac_rcv(struct dect_msg_buf *mb, uint8_t slot);

/* DSC */

extern void dect_dsc_keystream(uint64_t iv, const uint8_t *key,
			       uint8_t *output, unsigned int len);
extern uint64_t dect_dsc_iv(uint32_t mfn, uint8_t framenum);

#endif /* _DECTMON_H */
