#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <dectmon.h>
#include <cli.h>

#define DECTMON_HISTFILE	".dectmon_history"

static struct event cli_event;
static char histfile[PATH_MAX];
static struct parser_state state;
static void *scanner;

void cli_display(const char *fmt, va_list ap)
{
	int point, end;

	point = rl_point;
	end   = rl_end;
	rl_point = rl_end = 0;
	rl_save_prompt();
	rl_clear_message();

	vfprintf(rl_outstream, fmt, ap);

	rl_restore_prompt();
	rl_point = point;
	rl_end   = end;
	rl_forced_update_display();
}

static void cli_read_callback(int fd, short mask, void *data)
{
	rl_callback_read_char();
}

static void cli_complete(char *line)
{
	HIST_ENTRY *hist;
	char *c;

	if (line == NULL)
		return;

	/* avoid empty lines in history */
	for (c = line; c != '\0'; c++) {
		if (!isspace(*c))
			break;
	}
	if (*c == '\0')
		return;

	/* avoid duplicate lines in history */
	hist = history_get(where_history());
	if (hist == NULL ||
	    ((where_history() != history_length - 1) ||
	     strcmp(hist->line, line)))
		add_history(line);

	rl_replace_line("", 1);
	scanner_push_buffer(scanner, line);
	yyparse(scanner, &state);
	rl_crlf();
	free(line);
}

static const char *keywords[] = {
	"debug",
	"cluster",
	"portable",
	"tbc",
	"show",
	"set",
	"on",
	"off",
	"lce",
	"cc",
	"ss",
	"mm",
	"clms",
	"llme",
	"MNCC_SETUP-req",
	"MNCC_INFO-req",
	"MNSS_FACILITY-req",
	"portable-identity",
	"sending-complete",
	"keypad",
	"basic-service",
	"escape-to-proprietary",
	"IPEI",
	"info",
	"service",
	"class",
	"LIA",
	"message",
	"dect/isdn",
	"normal",
	"internal",
	"emergency",
	"external-handover",
	"QA&M",
	"basic-speech",
	"GSM",
	"UMTS",
	"LRMS",
	"GSM-SMS",
	"wideband-speech",
	"SUOTA-class-4",
	"SUOTA-class-3",
	"other",
	"emc",
	"content",
	NULL
};

static char *cli_command_generator(const char *text, int state)
{
	static unsigned int idx, len;
	const char *name;

	if (state == 0) {
		idx = 0;
		len = strlen(text);
	}

	while ((name = keywords[idx]) != NULL) {
		idx++;
		if (!strncasecmp(name, text, len))
			return strdup(name);
	}
	return NULL;
}

static char **cli_completion(const char *text, int start, int end)
{
	return rl_completion_matches(text, cli_command_generator);
}

int cli_init(FILE *file)
{
	const char *prompt = NULL;
	const char *home;
	int fd;

	parser_init(&state);
	scanner = scanner_init(&state);

	rl_instream = file;
	fd = fileno(rl_instream);
	rl_readline_name = "dectmon";
	if (isatty(fd))
		prompt = "dectmon > ";

	rl_outstream = stdout;

	rl_callback_handler_install(prompt, cli_complete);
	rl_attempted_completion_function = cli_completion;

	home = getenv("HOME");
	if (home == NULL)
		home = ".";
	snprintf(histfile, sizeof(histfile), "%s/%s", home, DECTMON_HISTFILE);
	read_history(histfile);
	history_set_pos(history_length);

	event_set(&cli_event, fd, EV_READ | EV_PERSIST, cli_read_callback, NULL);
	event_add(&cli_event, NULL);

	return 0;
}

void cli_exit(void)
{
	rl_callback_handler_remove();
	rl_deprep_terminal();
	write_history(histfile);
}
