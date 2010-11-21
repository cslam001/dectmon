#ifndef _DECTMON_AUDIO_H
#define _DECTMON_AUDIO_H

#include "../src/ccitt-adpcm/g72x.h"

struct dect_audio_handle {
	struct g72x_state	codec[2];
	struct dect_msg_buf	*queue[2];
};

extern int dect_audio_init(void);
extern struct dect_audio_handle *dect_audio_open(void);
extern void dect_audio_close(struct dect_audio_handle *ah);
extern void dect_audio_queue(struct dect_audio_handle *ah, unsigned int queue,
			     struct dect_msg_buf *mb);

#endif /* _DECTMON_AUDIO_H */
