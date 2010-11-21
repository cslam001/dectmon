%{

#include <stdint.h>
#include <cli.h>
#include "cmd-parser.h"

static void init_pos(struct parser_state *state)
{
	state->lineno		= 1;
	state->column		= 1;
	state->token_offset	= 0;
	state->line_offset	= 0;
}

static void update_pos(struct parser_state *state, struct location *loc,
		       int len)
{
	loc->first_line		= state->lineno;
	loc->first_column	= state->column;
	loc->last_column	= state->column + len - 1;
	state->column		+= len;
}

static void update_offset(struct parser_state *state, struct location *loc,
			  unsigned int len)
{
	state->token_offset	+= len;
	loc->token_offset	= state->token_offset;
	loc->line_offset	= state->line_offset;
}

static void reset_pos(struct parser_state *state, struct location *loc)
{
	state->line_offset	= state->token_offset;
	state->lineno		+= 1;
	state->column		= 1;
	loc->line_offset	= state->line_offset;
}

#define YY_USER_ACTION {					\
	update_pos(yyget_extra(yyscanner), yylloc, yyleng);	\
	update_offset(yyget_extra(yyscanner), yylloc, yyleng);	\
}

/* avoid warnings with -Wmissing-prototypes */
extern int	yyget_column(yyscan_t);
extern void	yyset_column(int, yyscan_t);

%}

%option reentrant
%option noyywrap
%option nounput
%option bison-bridge
%option bison-locations
%option debug
%option yylineno
%option nodefault
%option warn
%option case-insensitive

space		[ ]
tab		\t
newline		\n
digit		[0-9]
hexdigit	[0-9a-fA-F]
decstring	{digit}+
hexstring	0[xX]{hexdigit}+
range		({decstring}?:{decstring}?)
letter		[a-zA-Z]
string		({letter})({letter}|{digit}|[/\-_\.])*
quotedstring	\"[^"]*\"
comment		#.*$
slash		\/
%%

"("			{ return '('; }
")"			{ return ')'; }
"="			{ return '='; }
","			{ return ','; }

"debug"			{ return TOK_DEBUG; }
"cluster"		{ return CLUSTER; }
"portable"		{ return PORTABLE; }
"tbc"			{ return TBC; }

"show"			{ return SHOW; }
"set"			{ return SET; }

"on"			{ return ON; }
"off"			{ return OFF; }

"lce"			{ return LCE; }
"cc"			{ return CC; }
"ss"			{ return SS; }
"clms"			{ return CLMS; }
"mm"			{ return MM; }
"llme"			{ return LLME; }

"MNCC_SETUP-req"	{ return MNCC_SETUP_REQ; }
"MNCC_INFO-req"		{ return MNCC_INFO_REQ; }

"MNSS_FACILITY-req"	{ return MNSS_FACILITY_REQ; }

"portable-identity"	{ return PORTABLE_IDENTITY; }
"sending-complete"	{ return SENDING_COMPLETE; }
"keypad"		{ return KEYPAD; }
"basic-service"		{ return BASIC_SERVICE; }
"escape-to-proprietary"	{ return ESCAPE_TO_PROPRIETARY; }

"IPEI"			{ return IPEI; }

"info"			{ return INFO; }
"service"		{ return SERVICE; }
"class"			{ return CLASS; }

"LIA"			{ return LIA; }
"message"		{ return MESSAGE; }
"dect/isdn"		{ return DECT_ISDN; }
"normal"		{ return NORMAL; }
"internal"		{ return INTERNAL; }
"emergency"		{ return EMERGENCY; }
"external-handover"	{ return EXTERNAL_HO; }
"QA&M"			{ return QA_M; }

"basic-speech"		{ return BASIC_SPEECH; }
"GSM"			{ return GSM; }
"UMTS"			{ return UMTS; }
"LRMS"			{ return LRMS; }
"GSM-SMS"		{ return GSM_SMS; }
"wideband-speech"	{ return WIDEBAND_SPEECH; }
"SUOTA-class-4"		{ return SUOTA_CLASS_4; }
"SUOTA-class-3"		{ return SUOTA_CLASS_3; }
"other"			{ return OTHER; }

"EMC"			{ return EMC; }
"content"		{ return CONTENT; }

{string}		{
				yylval->string = strdup(yytext);
				return STRING;
			}

{quotedstring}		{
				yylval->string = strndup(yytext + 1, yyleng - 2);
				return STRING;
			}

{decstring}		{
				yylval->val = strtoul(yytext, NULL, 0);
				return NUMBER;
			}

\\{newline}		{
				reset_pos(yyget_extra(yyscanner), yylloc);
			}

{newline}		{
				reset_pos(yyget_extra(yyscanner), yylloc);
				return NEWLINE;
			}

{space}+

.			{ return JUNK; }

%%

void scanner_push_buffer(void *scanner, const char *buffer)
{
	struct parser_state *state = yyget_extra(scanner);
	YY_BUFFER_STATE b;

	b = yy_scan_string(buffer, scanner);
	init_pos(state);
}

void *scanner_init(struct parser_state *state)
{
	yyscan_t scanner;

	yylex_init(&scanner);
	yyset_extra(state, scanner);
	yyset_out(NULL, scanner);

	return scanner;
}

void scanner_destroy(struct parser_state *scanner)
{
	yylex_destroy(scanner);
}
