#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>

#include <dect/libdect.h>
#include <dectmon.h>

static void event_io_callback(int fd, short mask, void *data)
{
	struct dect_fd *dfd = data;
	uint32_t events;

	events = 0;
	if (mask & EV_READ)
		events |= DECT_FD_READ;
	if (mask & EV_WRITE)
		events |= DECT_FD_WRITE;

	dect_fd_process(dh, dfd, events);
}

static int register_fd(const struct dect_handle *dh, struct dect_fd *dfd,
		       uint32_t events)
{
	struct event *ev = dect_fd_priv(dfd);
	unsigned short mask;

	mask = EV_PERSIST;
	if (events & DECT_FD_READ)
		mask |= EV_READ;
	if (events & DECT_FD_WRITE)
		mask |= EV_WRITE;

	event_set(ev, dect_fd_num(dfd), mask, event_io_callback, dfd);
	event_add(ev, NULL);
	return 0;
}

static void unregister_fd(const struct dect_handle *dh, struct dect_fd *dfd)
{
	struct event *ev = dect_fd_priv(dfd);

	event_del(ev);
}

static void event_timer_callback(int fd, short mask, void *data)
{
	dect_timer_run(dh, data);
}

static void start_timer(const struct dect_handle *dh,
			struct dect_timer *timer,
			const struct timeval *tv)
{
	struct event *ev = dect_timer_priv(timer);

	evtimer_set(ev, event_timer_callback, timer);
	evtimer_add(ev, (struct timeval *)tv);
}

static void stop_timer(const struct dect_handle *dh, struct dect_timer *timer)
{
	struct event *ev = dect_timer_priv(timer);

	evtimer_del(ev);
}

static const struct dect_event_ops dect_event_ops = {
	.fd_priv_size		= sizeof(struct event),
	.register_fd		= register_fd,
	.unregister_fd		= unregister_fd,
	.timer_priv_size	= sizeof(struct event),
	.start_timer		= start_timer,
	.stop_timer		= stop_timer
};

static struct event_base *ev_base;
static struct event sig_event;
static bool sigint;
static bool endloop;

static void sig_callback(int fd, short event, void *data)
{
	sigint = true;
}

int dect_event_ops_init(struct dect_ops *ops)
{

	ev_base = event_init();
	if (ev_base == NULL)
		return -1;
	ops->event_ops = &dect_event_ops;

	signal_set(&sig_event, SIGINT, sig_callback, NULL);
	signal_add(&sig_event, NULL);
	return 0;
}

void dect_event_loop_stop(void)
{
	endloop = true;
}

void dect_event_loop(void)
{
	endloop = false;

	while (!sigint && !endloop)
		event_loop(EVLOOP_ONCE);
}

void dect_event_ops_cleanup(void)
{
	signal_del(&sig_event);
	event_base_free(ev_base);
}
