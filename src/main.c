#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>

#include <dect/libdect.h>
#include <dect/raw.h>
#include <dectmon.h>

struct dect_handle *dh;

static void pexit(const char *str)
{
	perror(str);
	exit(1);
}

static void dect_raw_rcv(struct dect_handle *dh, struct dect_fd *dfd,
			 struct dect_msg_buf *mb)
{
	dect_mac_rcv(mb, mb->slot);
}

static struct dect_raw_ops raw_ops = {
	.raw_rcv	= dect_raw_rcv,
};

static struct dect_ops ops = {
	.raw_ops	= &raw_ops,
};

#define OPTSTRING "c:m:d:n:p:h"

enum {
	OPT_CLUSTER	= 'c',
	OPT_DUMP_MAC	= 'm',
	OPT_DUMP_DLC	= 'd',
	OPT_DUMP_NWK	= 'n',
	OPT_AUTH_PIN	= 'p',
	OPT_HELP	= 'h',
};

static const struct option dectmon_opts[] = {
	{ .name = "cluster",  .has_arg = true,	.flag = 0, .val = OPT_CLUSTER, },
	{ .name = "dump-mac", .has_arg = true,  .flag = 0, .val = OPT_DUMP_MAC, },
	{ .name = "dump-dlc", .has_arg = true,  .flag = 0, .val = OPT_DUMP_DLC, },
	{ .name = "dump-nwk", .has_arg = true,  .flag = 0, .val = OPT_DUMP_NWK, },
	{ .name = "auth-pin", .has_arg = true,  .flag = 0, .val = OPT_AUTH_PIN, },
	{ .name = "help",     .has_arg = false, .flag = 0, .val = OPT_HELP, },
	{ },
};

static uint32_t opt_yesno(const char *arg, uint32_t opts, uint32_t flag)
{
	if (!strcmp(arg, "yes"))
		opts |= flag;
	else if (!strcmp(arg, "no"))
		opts &= ~flag;
	else
		pexit("invalid argument\n");

	return opts;
}

const char *auth_pin = "0000";
uint32_t dumpopts = DECTMON_DUMP_NWK;

int main(int argc, char **argv)
{
	const char *cluster = NULL;
	struct dect_fd *dfd;
	int optidx = 0, c;

	for (;;) {
		c = getopt_long(argc, argv, OPTSTRING, dectmon_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case OPT_CLUSTER:
			cluster = optarg;
			break;
		case OPT_DUMP_MAC:
			dumpopts = opt_yesno(optarg, dumpopts, DECTMON_DUMP_MAC);
			break;
		case OPT_DUMP_DLC:
			dumpopts = opt_yesno(optarg, dumpopts, DECTMON_DUMP_DLC);
			break;
		case OPT_DUMP_NWK:
			dumpopts = opt_yesno(optarg, dumpopts, DECTMON_DUMP_NWK);
			break;
		case OPT_AUTH_PIN:
			auth_pin = optarg;
			break;
		case OPT_HELP:
			printf("%s [ options ]\n"
			       "\n"
			       "Options:\n"
			       "  -m/--dump-mac=yes/no\n"
			       "  -d/--dump-dlc=yes/no\n"
			       "  -n/--dump-nwk=yes/no\n"
			       "  -p/--auth-pin=PIN\n"
			       "  -h/--help\n",
			       argv[0]);

			exit(0);
		case '?':
			exit(1);
		}
	}

	dect_event_ops_init(&ops);
	dect_dummy_ops_init(&ops);

	dh = dect_open_handle(&ops, cluster);
	if (dh == NULL)
		pexit("dect_init_handle");

	dfd = dect_raw_socket(dh);
	if (dfd == NULL)
		pexit("dect_raw_socket");

	dect_event_loop();
	return 0;
}
