%{

#include <stdint.h>
#include <dect/libdect.h>
#include <dectmon.h>
#include <cli.h>

#include "cmd-parser.h"
#include "cmd-scanner.h"

static void yyerror(struct location *loc, void *scanner,
		    struct parser_state *state, const char *s)
{
	unsigned int plen = strlen("dectmon > ");
	unsigned int i;
	char buf[256];

	memset(buf, ' ', sizeof(buf));
	for (i = loc->first_column - 1 + plen; i < loc->last_column + plen; i++)
		buf[i] = '^';
	buf[i] = '\0';
	dectmon_log("%s\n", buf);
	dectmon_log("%s\n", s);
}

static struct dect_handle *parser_get_handle(void)
{
	struct dect_handle_priv *priv;

	priv = list_first_entry(&dect_handles, struct dect_handle_priv, list);
	return priv->dh;
}

void parser_init(struct parser_state *state)
{
	memset(state, 0, sizeof(*state));
}

static void location_init(void *scanner, struct parser_state *state,
			  struct location *loc)
{
	memset(loc, 0, sizeof(*loc));
}

static void location_update(struct location *loc, struct location *rhs, int n)
{
	if (n) {
		loc->token_offset	= rhs[1].token_offset;
		loc->line_offset	= rhs[1].line_offset;
		loc->first_line		= rhs[1].first_line;
		loc->first_column	= rhs[1].first_column;
		loc->last_line		= rhs[n].last_line;
		loc->last_column	= rhs[n].last_column;
	} else {
		loc->token_offset	= rhs[0].token_offset;
		loc->line_offset	= rhs[0].line_offset;
		loc->first_line		= rhs[0].last_line;
		loc->last_line		= rhs[0].last_line;
		loc->first_column	= rhs[0].last_column;
		loc->last_column	= rhs[0].last_column;
	}
}

#define YYLLOC_DEFAULT(Current, Rhs, N)	location_update(&Current, Rhs, N)

%}

/* Declarations */

%pure-parser
%error-verbose
%parse-param		{ void *scanner }
%parse-param		{ struct parser_state *state }
%lex-param		{ scanner }
%locations

%initial-action {
	location_init(scanner, state, &yylloc);
}

%union {
	uint64_t			val;
	const char			*string;
	struct dect_ie_common		*ie;
	struct dect_mncc_setup_param	*mncc_setup_param;
	struct dect_mncc_info_param	*mncc_info_param;
}

%token TOKEN_EOF 0		"end of file"
%token JUNK			"junk"
%token NEWLINE			"newline"

%token <string> STRING		"string"
%token <val> NUMBER		"number"

%token TOK_DEBUG		"debug"
%token CLUSTER			"cluster"
%token PORTABLE			"portable"
%token TBC			"tbc"

%token SHOW			"show"
%token SET			"set"

%token ON			"on"
%token OFF			"off"

%token LCE			"lce"
%token CC			"cc"
%token SS			"ss"
%token CLMS			"clms"
%token MM			"mm"
%token LLME			"llme"

%token MNCC_SETUP_REQ		"MNCC_SETUP-req"
%token MNCC_INFO_REQ		"MNCC_INFO-req"

%token SENDING_COMPLETE		"sending-complete"
%token KEYPAD			"keypad"
%token BASIC_SERVICE		"basic-service"
%token ESCAPE_TO_PROPRIETARY	"escape-to-proprietary"

%token INFO			"info"
%token SERVICE			"service"
%token CLASS			"class"

%token LIA			"LIA"
%token MESSAGE			"message"
%token DECT_ISDN		"dect/isdn"
%token NORMAL			"normal"
%token INTERNAL			"internal"
%token EMERGENCY		"emergency"
%token EXTERNAL_HO		"external-handover"
%token QA_M			"QA&M"

%token BASIC_SPEECH		"basic-speech"
%token GSM			"GSM"
%token UMTS			"UMTS"
%token LRMS			"LRMS"
%token GSM_SMS			"GSM-SMS"
%token WIDEBAND_SPEECH		"wideband-speech"
%token SUOTA_CLASS_4		"SUOTA-class-4"
%token SUOTA_CLASS_3		"SUOTA-class-3"
%token OTHER			"other"

%token EMC			"EMC"
%token CONTENT			"content"

%type <val>			debug_subsys on_off

%type <mncc_setup_param>	mncc_setup_param_alloc
%type <mncc_setup_param>	mncc_setup_params mncc_setup_param

%type <mncc_info_param>		mncc_info_param_alloc
%type <mncc_info_param>		mncc_info_params mncc_info_param

%type <ie>			keypad_ie keypad_ie_alloc

%type <ie>			sending_complete_ie

%type <ie>			basic_service_ie basic_service_ie_alloc
%type <ie>			basic_service_ie_params basic_service_ie_param
%type <val>			basic_service_ie_class basic_service_ie_service

%type <ie>			etp_ie etp_ie_alloc
%type <ie>			etp_ie_params etp_ie_param

%%

input			:	/* empty */
			|	input		line
			;

line			:	cluster_stmt
			|	portable_stmt
			|	tbc_stmt
			|	debug_stmt
			|	cc_primitive
			;

cluster_stmt		:	CLUSTER		SHOW
			{
				struct dect_handle_priv *priv;

				dectmon_log("Cluster\t\tLocked\t\tPARI\n");
				list_for_each_entry(priv, &dect_handles, list) {
					dectmon_log("%s\t%s\t\tEMC: %.4x FPN: %.5x\n",
						    priv->cluster, priv->locked ? "Yes" : "No",
						    priv->pari.emc, priv->pari.fpn);
				}
			}
			;

portable_stmt		:	PORTABLE	SHOW
			{
				char ipei[DECT_IPEI_STRING_LEN];
				struct dect_handle_priv *priv;
				struct dect_pt *pt;

				dectmon_log("Cluster\t\tIPEI\n");
				list_for_each_entry(priv, &dect_handles, list) {
					list_for_each_entry(pt, &priv->pt_list, list) {
						dect_format_ipei_string(&pt->portable_identity->ipui.pun.n.ipei,
									ipei);
						dectmon_log("%s\t%s\n", priv->cluster, ipei);
					}
				}
			}
			;

tbc_stmt		:	TBC		SHOW
			{
				struct dect_handle_priv *priv;
				struct dect_tbc *tbc;
				unsigned int i;

				dectmon_log("Cluster\t\tPMID\tFMID\tSlots\tCiphered\n");
				list_for_each_entry(priv, &dect_handles, list) {
					for (i = 0; i < DECT_HALF_FRAME_SIZE; i++) {
						tbc = priv->slots[i];
						if (tbc == NULL)
							continue;
						dectmon_log("%s\t%.5x\t%.3x\t%u/%u\t%s\n",
							    priv->cluster,
							    tbc->pmid, tbc->fmid,
							    tbc->slot1, tbc->slot2,
							    tbc->ciphered ? "Yes" : "No");
					}
				}
			}
			;

debug_stmt		:	TOK_DEBUG	SET	debug_subsys	on_off
			{
				if ($4)
					debug_mask |= (1 << $3);
				else
					debug_mask &= ~(1 << $3);
			}
			;

debug_subsys		:	LCE	{ $$ = DECT_DEBUG_LCE; }
			|	CC	{ $$ = DECT_DEBUG_CC; }
			|	SS	{ $$ = DECT_DEBUG_SS; }
			|	CLMS	{ $$ = DECT_DEBUG_CLMS; }
			|	MM	{ $$ = DECT_DEBUG_MM; }
			|	LLME	{ $$ = DECT_DEBUG_NL; }
			;

on_off			:	ON	{ $$ = true; }
			|	OFF	{ $$ = false; }
			;

cc_primitive		:	mncc_setup_req
			|	mncc_info_req
			;

/*
 * MNCC_SETUP-req
 */

mncc_setup_req		:	MNCC_SETUP_REQ	mncc_setup_param_alloc '(' mncc_setup_params ')'
			{
				struct dect_handle *dh = parser_get_handle();
				struct dect_ipui ipui = {};
				struct dect_call *call;

				call = dect_call_alloc(dh);
				dect_mncc_setup_req(dh, call, &ipui, $2);
			}

mncc_setup_param_alloc	:
			{
				$$ = dect_ie_collection_alloc(parser_get_handle(),
							      sizeof(struct dect_mncc_setup_param));
			}
			;

mncc_setup_params	:	mncc_setup_param
			{
				$$ = $<mncc_setup_param>-1;
			}
			|	mncc_setup_params ',' mncc_setup_param
			;

mncc_setup_param	:	keypad_ie
			{
				$<mncc_setup_param>-1->keypad = (struct dect_ie_keypad *)$1;
			}
			|	sending_complete_ie
			{
				$<mncc_setup_param>-1->sending_complete = (struct dect_ie_sending_complete *)$1;
			}
			|	basic_service_ie
			{
				$<mncc_setup_param>-1->basic_service = (struct dect_ie_basic_service *)$1;
			}
			|	etp_ie
			{
				$<mncc_setup_param>-1->escape_to_proprietary = (struct dect_ie_escape_to_proprietary *)$1;
			}
			;

/*
 * MNCC_INFO-req
 */

mncc_info_req		:	MNCC_INFO_REQ	mncc_info_param_alloc '(' mncc_info_params ')'
			{
			}
			;

mncc_info_param_alloc	:
			{
				$$ = dect_ie_collection_alloc(parser_get_handle(),
							      sizeof(struct dect_mncc_info_param));
			}
			;

mncc_info_params	:	mncc_info_param
			{
				$$ = $<mncc_info_param>-1;
			}
			|	mncc_info_params ',' mncc_info_param
			;

mncc_info_param		:	keypad_ie
			{
				$<mncc_info_param>-1->keypad = (struct dect_ie_keypad *)$1;
			}
			|	sending_complete_ie
			{
				$<mncc_info_param>-1->sending_complete = (struct dect_ie_sending_complete *)$1;
			}
			|	etp_ie
			{
				$<mncc_info_param>-1->escape_to_proprietary = (struct dect_ie_escape_to_proprietary *)$1;
			}
			;

/*
 * Keypad IE
 */

keypad_ie		:	KEYPAD	keypad_ie_alloc '(' keypad_ie_param ')'
			{
				$$ = $2;
			}
			;

keypad_ie_alloc		:
			{
				$$ = dect_ie_alloc(parser_get_handle(), sizeof(struct dect_ie_keypad));
			}

keypad_ie_param		:	INFO	'='	STRING
			{
				struct dect_ie_keypad *ie = dect_ie_container(ie, $<ie>-1);

				ie->len = strlen($3);
				memcpy(ie->info, $3, ie->len);
			}
			;

/*
 * Sending complete IE
 */

sending_complete_ie	:	SENDING_COMPLETE
			{
				$$ = dect_ie_alloc(parser_get_handle(), sizeof(struct dect_ie_sending_complete));
			}
			;

/*
 * Basic Service IE
 */

basic_service_ie	:	BASIC_SERVICE	basic_service_ie_alloc '(' basic_service_ie_params ')'
			{
				$$ = $2;
			}
			;

basic_service_ie_alloc	:
			{
				$$ = dect_ie_alloc(parser_get_handle(), sizeof(struct dect_ie_basic_service));
			}
			;

basic_service_ie_params	:	basic_service_ie_param
			{
				$$ = $<ie>-1;
			}
			|	basic_service_ie_params	',' basic_service_ie_param
			;

basic_service_ie_param	:	CLASS	'='	basic_service_ie_class
			{
				struct dect_ie_basic_service *ie = dect_ie_container(ie, $<ie>-1);

				ie->class = $3;
			}
			|	SERVICE	'='	basic_service_ie_service
			{
				struct dect_ie_basic_service *ie = dect_ie_container(ie, $<ie>-1);

				ie->service = $3;
			}
			;

basic_service_ie_class	:	LIA		{ $$ = DECT_CALL_CLASS_LIA_SERVICE_SETUP; }
			|	MESSAGE		{ $$ = DECT_CALL_CLASS_MESSAGE; }
			|	DECT_ISDN	{ $$ = DECT_CALL_CLASS_DECT_ISDN; }
			|	NORMAL		{ $$ = DECT_CALL_CLASS_NORMAL; }
			|	INTERNAL	{ $$ = DECT_CALL_CLASS_INTERNAL; }
			|	EMERGENCY	{ $$ = DECT_CALL_CLASS_EMERGENCY; }
			|	SERVICE		{ $$ = DECT_CALL_CLASS_SERVICE; }
			|	EXTERNAL_HO	{ $$ = DECT_CALL_CLASS_EXTERNAL_HO; }
			|	SS		{ $$ = DECT_CALL_CLASS_SUPPLEMENTARY_SERVICE; }
			|	QA_M		{ $$ = DECT_CALL_CLASS_QA_M; }
			;

basic_service_ie_service:	BASIC_SPEECH	{ $$ = DECT_SERVICE_BASIC_SPEECH_DEFAULT; }
			|	GSM		{ $$ = DECT_SERVICE_DECT_GSM_IWP; }
			|	UMTS		{ $$ = DECT_SERVICE_UMTS_IWP; }
			|	LRMS		{ $$ = DECT_SERVICE_LRMS; }
			|	GSM_SMS		{ $$ = DECT_SERVICE_GSM_IWP_SMS; }
			|	WIDEBAND_SPEECH	{ $$ = DECT_SERVICE_WIDEBAND_SPEECH; }
			|	SUOTA_CLASS_4	{ $$ = DECT_SERVICE_SUOTA_CLASS_4_DPRS_MANAGEMENT; }
			|	SUOTA_CLASS_3	{ $$ = DECT_SERVICE_SUOTA_CLASS_3_DPRS_MANAGEMENT; }
			|	OTHER		{ $$ = DECT_SERVICE_OTHER; }
			;

/*
 * Escape-to-proprietary IE
 */

etp_ie			:	ESCAPE_TO_PROPRIETARY	etp_ie_alloc '(' etp_ie_params ')'
			{
				$$ = $2;
			}
			;

etp_ie_alloc		:
			{
				$$ = dect_ie_alloc(parser_get_handle(), sizeof(struct dect_ie_escape_to_proprietary));
			}
			;

etp_ie_params		:	etp_ie_param
			{
				$$ = $<ie>-1;
			}
			|	etp_ie_params ',' etp_ie_param
			;

etp_ie_param		:	EMC	'='	NUMBER
			{
				struct dect_ie_escape_to_proprietary *ie = dect_ie_container(ie, $<ie>-1);

				ie->emc = $3;
			}
			|	CONTENT	'='	STRING
			{
				struct dect_ie_escape_to_proprietary *ie = dect_ie_container(ie, $<ie>-1);

				ie->len = strlen($3);
				memcpy(ie->content, $3, ie->len);
			}
			;

%%
