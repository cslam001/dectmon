#include <SDL/SDL.h>
#include <SDL/SDL_audio.h>

#include <dectmon.h>
#include <utils.h>

void dect_audio_queue(struct dect_audio_handle *ah, unsigned int queue,
		      struct dect_msg_buf *mb)
{
	SDL_LockAudio();
	ptrlist_add_tail(mb, &ah->queue[queue]);
	SDL_UnlockAudio();
}

static void dect_decode_g721(struct g72x_state *codec,
			     int16_t *dst, const uint8_t *src,
			     unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len * 2; i += 2) {
		dst[i + 0] = g721_decoder(src[i / 2] >> 4,
					  AUDIO_ENCODING_LINEAR, codec);
		dst[i + 1] = g721_decoder(src[i / 2] & 0x0f,
					  AUDIO_ENCODING_LINEAR, codec);
	}
}

static void dect_audio_dequeue(void *data, uint8_t *stream, int len)
{
	struct dect_audio_handle *ah = data;
	struct dect_msg_buf *mb;
	int16_t buf[len], *dptr;
	unsigned int i, copy, n;

	len /= 4;
	for (i = 0; i < array_size(ah->queue); i++) {
		dptr = buf;
		n = len;

		while (1) {
			if (ah->queue[i] == NULL) {
				dectmon_log("audio underrun queue %u, missing %u bytes\n",
					    i, n * 4);
				memset(dptr, 0, n * 4);
				break;
			}

			mb = ah->queue[i];
			copy = mb->len;
			if (copy > n)
				copy = n;

			dect_decode_g721(&ah->codec[i], dptr, mb->data, copy);
			dect_mbuf_pull(mb, copy);
			if (mb->len == 0) {
				ah->queue[i] = mb->next;
				free(mb);
			}

			n -= copy;
			if (n == 0)
				break;
			dptr += 2 * copy;
		}
		SDL_MixAudio(stream, (uint8_t *)buf, 4 * len, SDL_MIX_MAXVOLUME);
	}
}

struct dect_audio_handle *dect_audio_open(void)
{
	struct dect_audio_handle *ah;
	SDL_AudioSpec spec = {
		.freq		= 8000,
		.format		= AUDIO_S16SYS,
		.channels	= 1,
		.samples	= 512,
		.callback	= dect_audio_dequeue,
	};

	ah = malloc(sizeof(*ah));
	if (ah == NULL)
		goto err1;

	ptrlist_init(&ah->queue[0]);
	g72x_init_state(&ah->codec[0]);

	ptrlist_init(&ah->queue[1]);
	g72x_init_state(&ah->codec[1]);

	spec.userdata = ah;
	if (SDL_OpenAudio(&spec, NULL) < 0)
		goto err2;
	SDL_PauseAudio(0);

	return ah;

err2:
	free(ah);
err1:
	return NULL;
}

void dect_audio_close(struct dect_audio_handle *ah)
{
	struct dect_msg_buf *mb;
	unsigned int i;

	SDL_CloseAudio();
	for (i = 0; i < array_size(ah->queue); i++) {
		while ((mb = ptrlist_dequeue_head(&ah->queue[i])) != NULL)
			free(mb);
	}
	free(ah);
}

int dect_audio_init(void)
{
	return SDL_Init(SDL_INIT_AUDIO);
}
