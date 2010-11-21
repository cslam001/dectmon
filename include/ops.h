#ifndef _DECTMON_OPS_H
#define _DECTMON_OPS_H

struct dect_ops;
extern int dect_event_ops_init(struct dect_ops *ops);
extern void dect_event_loop_stop(void);
extern void dect_event_loop(void);
extern void dect_event_ops_cleanup(void);
extern void dect_dummy_ops_init(struct dect_ops *ops);

#endif /* _DECTMON_OPS_H */
