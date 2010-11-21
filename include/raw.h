#ifndef _DECTMON_RAW_H
#define _DECTMON_RAW_H

struct dect_raw_frame_hdr {
	uint8_t		len;
	uint8_t		slot;
	uint8_t		frame;
	uint8_t		pad;
	uint32_t	mfn;
};

#endif /* _DECTMON_RAW_H */
