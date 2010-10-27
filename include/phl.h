/*
 * DECT Transceiver Layer
 *
 * Copyright (c) 2009 Patrick McHardy <kaber@trash.net>
 */

#include <linux/dect_netlink.h>

#ifndef _NET_DECT_TRANSCEIVER_H
#define _NET_DECT_TRANSCEIVER_H

#define DECT_FRAME_SIZE			24
#define DECT_HALF_FRAME_SIZE		(DECT_FRAME_SIZE / 2)
#define DECT_FRAMES_PER_SECOND		100

#define DECT_SCAN_SLOT			0
#define DECT_SLOT_MASK			0x00ffffff

static inline uint8_t dect_next_slotnum(uint8_t slot)
{
	if (++slot == DECT_FRAME_SIZE)
		slot = 0;
	return slot;
}

static inline uint8_t dect_slot_add(uint8_t s1, uint8_t s2)
{
	return (s1 + s2) % DECT_FRAME_SIZE;
}

static inline uint8_t dect_slot_distance(uint8_t s1, uint8_t s2)
{
	return s2 >= s1 ? s2 - s1 : DECT_FRAME_SIZE + s2 - s1;
}

#define dect_foreach_slot(slot) \
	for ((slot) = 0; (slot) < DECT_FRAME_SIZE; (slot)++)

static inline uint8_t dect_normal_transmit_base(enum dect_cluster_modes mode)
{
	return mode == DECT_MODE_FP ? 0 : DECT_HALF_FRAME_SIZE;
}

static inline uint8_t dect_normal_receive_base(enum dect_cluster_modes mode)
{
	return mode == DECT_MODE_FP ? DECT_HALF_FRAME_SIZE : 0;
}

static inline uint8_t dect_normal_receive_end(enum dect_cluster_modes mode)
{
	return mode == DECT_MODE_FP ? DECT_FRAME_SIZE - 1 :
				      DECT_HALF_FRAME_SIZE - 1;
}

static inline uint8_t dect_tdd_slot(uint8_t slot)
{
	return slot < DECT_HALF_FRAME_SIZE ? slot + DECT_HALF_FRAME_SIZE :
					     slot - DECT_HALF_FRAME_SIZE;
}

#endif /* _NET_DECT_TRANSCEIVER_H */
