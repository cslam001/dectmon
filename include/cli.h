#ifndef DECTMON_CLI_H
#define DECTMON_CLI_H

#define YYLTYPE			struct location
#define YYLTYPE_IS_TRIVIAL	0
#define YYENABLE_NLS		0

struct location {
	off_t		token_offset;
	off_t		line_offset;

	unsigned int	first_line;
	unsigned int	last_line;
	unsigned int	first_column;
	unsigned int	last_column;
};

struct parser_state {
	void		*buffer_state;
	unsigned int	lineno;
	unsigned int	column;
	off_t		token_offset;
	off_t		line_offset;
};

extern void parser_init(struct parser_state *state);
extern int yyparse(void *, struct parser_state *state);

extern void *scanner_init(struct parser_state *state);
extern void scanner_destroy(struct parser_state *state);

extern void scanner_push_buffer(void *scanner, const char *buffer);

extern void cli_display(const char *fmt, va_list ap);
extern int cli_init(FILE *file);
extern void cli_exit(void);

#endif /* DECTMON_CLI_H */
