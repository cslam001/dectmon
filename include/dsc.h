#ifndef _DECTMON_DSC_H
#define _DECTMON_DSC_H

extern void dect_dsc_keystream(uint64_t iv, const uint8_t *key,
			       uint8_t *output, unsigned int len);
extern uint64_t dect_dsc_iv(uint32_t mfn, uint8_t framenum);

#endif /* _DECTMON_DSC_H */
