/*
 * Copyright (c) 1999-2008 NOVELL (All rights reserved)
 * Copyright (c) 2010, Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2.1 of the GNU Lesser General
 * Public License published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


%{

/* set the following to non-zero to get bison to emit debugging
 * information about tokens given and rules matched. */
#define YYDEBUG 0
#include <string.h>
#include "aalogparse.h"
#include "parser.h"
#include "grammar.h"
#include "scanner.h"

aa_log_record *ret_record;

/* Since we're a library, on any errors we don't want to print out any
 * error messages. We should probably add a debug interface that does
 * emit messages when asked for. */
void aalogparse_error(void *scanner, char const *s)
{
        //printf("ERROR: %s\n", s);
	ret_record->event = AA_RECORD_INVALID;
}

struct aa_type_table {
	unsigned int audit_type;
	aa_record_event_type event;
};

static struct aa_type_table aa_type_table[] = {
	{AUDIT_APPARMOR_AUDIT,   AA_RECORD_AUDIT},
	{AUDIT_APPARMOR_ALLOWED, AA_RECORD_ALLOWED},
	{AUDIT_APPARMOR_DENIED,  AA_RECORD_DENIED},
	{AUDIT_APPARMOR_HINT,    AA_RECORD_HINT},
	{AUDIT_APPARMOR_STATUS,  AA_RECORD_STATUS},
	{AUDIT_APPARMOR_ERROR,   AA_RECORD_ERROR},
	{0,                      AA_RECORD_INVALID},
};

aa_record_event_type lookup_aa_event(unsigned int type)
{
	int i;

	for (i = 0; aa_type_table[i].audit_type != 0; i++)
		if (type == aa_type_table[i].audit_type)
			break;

	return aa_type_table[i].event;
}


%}

%defines
%pure_parser
%lex-param{void *scanner}
%parse-param{void *scanner}

%union
{
	char	*t_str;
	long	t_long;
}

%type <t_str> safe_string protocol
%token <t_long> TOK_DIGITS TOK_TYPE_UNKNOWN
%token <t_str> TOK_QUOTED_STRING TOK_ID TOK_MODE TOK_DMESG_STAMP
%token <t_str> TOK_AUDIT_DIGITS TOK_DATE_MONTH TOK_DATE TOK_TIME
%token <t_str> TOK_HEXSTRING TOK_TYPE_OTHER TOK_MSG_REST
%token <t_str> TOK_IP_ADDR

%token TOK_EQUALS
%token TOK_COLON
%token TOK_MINUS
%token TOK_OPEN_PAREN
%token TOK_CLOSE_PAREN
%token TOK_PERIOD

%token TOK_TYPE_REJECT
%token TOK_TYPE_AUDIT
%token TOK_TYPE_COMPLAIN
%token TOK_TYPE_HINT
%token TOK_TYPE_STATUS
%token TOK_TYPE_ERROR
%token TOK_TYPE_AA_REJECT
%token TOK_TYPE_AA_AUDIT
%token TOK_TYPE_AA_COMPLAIN
%token TOK_TYPE_AA_HINT
%token TOK_TYPE_AA_STATUS
%token TOK_TYPE_AA_ERROR
%token TOK_TYPE_LSM_AVC

%token TOK_KEY_APPARMOR
%token TOK_KEY_TYPE
%token TOK_KEY_MSG
%token TOK_KEY_OPERATION
%token TOK_KEY_NAME
%token TOK_KEY_NAME2
%token TOK_KEY_DENIED_MASK
%token TOK_KEY_REQUESTED_MASK
%token TOK_KEY_ATTRIBUTE
%token TOK_KEY_TASK
%token TOK_KEY_PARENT
%token TOK_KEY_MAGIC_TOKEN
%token TOK_KEY_INFO
%token TOK_KEY_PID
%token TOK_KEY_PROFILE
%token TOK_AUDIT
%token TOK_KEY_FAMILY
%token TOK_KEY_SOCK_TYPE
%token TOK_KEY_PROTOCOL
%token TOK_KEY_NAMESPACE
%token TOK_KEY_ERROR
%token TOK_KEY_FSUID
%token TOK_KEY_OUID
%token TOK_KEY_COMM
%token TOK_KEY_CAPABILITY
%token TOK_KEY_CAPNAME
%token TOK_KEY_OFFSET
%token TOK_KEY_TARGET
%token TOK_KEY_LADDR
%token TOK_KEY_FADDR
%token TOK_KEY_LPORT
%token TOK_KEY_FPORT

%token TOK_SYSLOG_KERNEL

%%

log_message: audit_type
	| syslog_type
	| audit_dispatch
	;

audit_type: TOK_KEY_TYPE TOK_EQUALS type_syntax ;

type_syntax: new_syntax { ret_record->version = AA_RECORD_SYNTAX_V2; }
	| other_audit
	;

new_syntax:
	  TOK_TYPE_AA_REJECT audit_msg key_list { ret_record->event = AA_RECORD_DENIED; }
	| TOK_TYPE_AA_AUDIT audit_msg key_list { ret_record->event = AA_RECORD_AUDIT; }
	| TOK_TYPE_AA_COMPLAIN audit_msg key_list { ret_record->event = AA_RECORD_ALLOWED; }
	| TOK_TYPE_AA_HINT audit_msg key_list { ret_record->event = AA_RECORD_HINT; }
	| TOK_TYPE_AA_STATUS audit_msg key_list { ret_record->event = AA_RECORD_STATUS; }
	| TOK_TYPE_AA_ERROR audit_msg key_list { ret_record->event = AA_RECORD_ERROR; }
	| TOK_TYPE_UNKNOWN audit_msg key_list { ret_record->event = lookup_aa_event($1); }
	| TOK_TYPE_LSM_AVC audit_msg key_list
	;

other_audit: TOK_TYPE_OTHER audit_msg TOK_MSG_REST
	{
		ret_record->operation = $1;
		ret_record->event = AA_RECORD_INVALID;
		ret_record->info = $3;
	}
	;

syslog_type:
	  syslog_date TOK_ID TOK_SYSLOG_KERNEL audit_id key_list
	  { ret_record->version = AA_RECORD_SYNTAX_V2; }
	| syslog_date TOK_ID TOK_SYSLOG_KERNEL key_type audit_id key_list
	  { ret_record->version = AA_RECORD_SYNTAX_V2; }
	| syslog_date TOK_ID TOK_SYSLOG_KERNEL TOK_DMESG_STAMP audit_id key_list
	  { ret_record->version = AA_RECORD_SYNTAX_V2; }
	| syslog_date TOK_ID TOK_SYSLOG_KERNEL TOK_DMESG_STAMP key_type audit_id key_list
	  { ret_record->version = AA_RECORD_SYNTAX_V2; }
	;

/* when audit dispatches a message it doesn't prepend the audit type string */
audit_dispatch:
	audit_msg key_list { ret_record->version = AA_RECORD_SYNTAX_V2; }
	;

audit_msg: TOK_KEY_MSG TOK_EQUALS audit_id
	;

audit_id: TOK_AUDIT TOK_OPEN_PAREN TOK_AUDIT_DIGITS TOK_PERIOD TOK_AUDIT_DIGITS TOK_COLON TOK_AUDIT_DIGITS TOK_CLOSE_PAREN TOK_COLON
	{
		if (!asprintf(&ret_record->audit_id, "%s.%s:%s", $3, $5, $7))
			yyerror(scanner, YY_("Out of memory"));
		ret_record->epoch = atol($3);
		ret_record->audit_sub_id = atoi($7);
		free($3);
		free($5);
		free($7);
	} ;

syslog_date: TOK_DATE_MONTH TOK_DIGITS TOK_TIME { /* do nothing? */ }
	| TOK_DATE TOK_TIME { /* do nothing */ }
	;

key_list: key
	| key_list key
	;

key: TOK_KEY_OPERATION TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->operation = $3;}
	| TOK_KEY_NAME TOK_EQUALS safe_string
	{ ret_record->name = $3;}
	| TOK_KEY_NAMESPACE TOK_EQUALS safe_string
	{ ret_record->namespace = $3;}
	| TOK_KEY_NAME2 TOK_EQUALS safe_string
	{ ret_record->name2 = $3;}
	| TOK_KEY_DENIED_MASK TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->denied_mask = $3;}
	| TOK_KEY_REQUESTED_MASK TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->requested_mask = $3;}
	| TOK_KEY_ATTRIBUTE TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->attribute = $3;}
	| TOK_KEY_TASK TOK_EQUALS TOK_DIGITS
	{ ret_record->task = $3;}
	| TOK_KEY_PARENT TOK_EQUALS TOK_DIGITS
	{ ret_record->parent = $3;}
	| TOK_KEY_MAGIC_TOKEN TOK_EQUALS TOK_DIGITS
	{ ret_record->magic_token = $3;}
	| TOK_KEY_INFO TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->info = $3;}
	| key_pid
	| TOK_KEY_PROFILE TOK_EQUALS safe_string
	{ ret_record->profile = $3;}
	| TOK_KEY_FAMILY TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->net_family = $3;}
	| TOK_KEY_SOCK_TYPE TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->net_sock_type = $3;}
	| TOK_KEY_PROTOCOL TOK_EQUALS protocol
	{ ret_record->net_protocol = $3;}
	| TOK_KEY_TYPE TOK_EQUALS TOK_DIGITS
	{ ret_record->event = lookup_aa_event($3);}
	| TOK_KEY_ERROR TOK_EQUALS TOK_DIGITS
	{ ret_record->error_code = $3;}
	| TOK_KEY_ERROR TOK_EQUALS TOK_MINUS TOK_DIGITS
	{ ret_record->error_code = $4;}
	| TOK_KEY_FSUID TOK_EQUALS TOK_DIGITS
	{ ret_record->fsuid = $3;}
	| TOK_KEY_OUID TOK_EQUALS TOK_DIGITS
	{ ret_record->ouid = $3;}
	| TOK_KEY_COMM TOK_EQUALS safe_string
	{ ret_record->comm = $3;}
	| TOK_KEY_APPARMOR TOK_EQUALS apparmor_event
	| TOK_KEY_CAPABILITY TOK_EQUALS TOK_DIGITS
	{ /* need to reverse map number to string, need to figure out
	   * how to get auto generation of reverse mapping table into
	   * autotools Makefile.  For now just drop assumming capname is
	   * present which it should be with current kernels */
	}
	| TOK_KEY_CAPNAME TOK_EQUALS TOK_QUOTED_STRING
	{ /* capname used to be reported in name */
	  ret_record->name = $3;
	}
	| TOK_KEY_OFFSET TOK_EQUALS TOK_DIGITS
	{ /* offset is used for reporting where an error occured unpacking
	   * loaded policy.  We can just drop this currently
	   */
	}
	| TOK_KEY_TARGET TOK_EQUALS safe_string
	{ /* target was always name2 in the past */
	  ret_record->name2 = $3;
	}
	| TOK_KEY_LADDR TOK_EQUALS TOK_IP_ADDR
	{ ret_record->net_local_addr = $3;}
	| TOK_KEY_FADDR TOK_EQUALS TOK_IP_ADDR
	{ ret_record->net_foreign_addr = $3;}
	| TOK_KEY_LPORT TOK_EQUALS TOK_DIGITS
	{ ret_record->net_local_port = $3;}
	| TOK_KEY_FPORT TOK_EQUALS TOK_DIGITS
	{ ret_record->net_foreign_port = $3;}
	| TOK_MSG_REST
	{
		ret_record->event = AA_RECORD_INVALID;
		ret_record->info = $1;
	}
	;

apparmor_event:
	  TOK_TYPE_REJECT	{ ret_record->event = AA_RECORD_DENIED; }
	| TOK_TYPE_AUDIT	{ ret_record->event = AA_RECORD_AUDIT; }
	| TOK_TYPE_COMPLAIN	{ ret_record->event = AA_RECORD_ALLOWED; }
	| TOK_TYPE_HINT		{ ret_record->event = AA_RECORD_HINT; }
	| TOK_TYPE_STATUS	{ ret_record->event = AA_RECORD_STATUS; }
	| TOK_TYPE_ERROR	{ ret_record->event = AA_RECORD_ERROR; }
	;

key_pid: TOK_KEY_PID TOK_EQUALS TOK_DIGITS { ret_record->pid = $3; }
	;

key_type: TOK_KEY_TYPE TOK_EQUALS TOK_DIGITS { ret_record->event = lookup_aa_event($3); }
	;

safe_string: TOK_QUOTED_STRING
	| TOK_HEXSTRING
	;

protocol: TOK_QUOTED_STRING
	| TOK_DIGITS
	{ /* FIXME: this should probably convert back to a string proto name */
	  $$ = ipproto_to_string($1);
	}
	;
%%

aa_log_record *
_parse_yacc(char *str)
{
	/* yydebug = 1;  */
	YY_BUFFER_STATE lex_buf;
	yyscan_t scanner;
	int parser_return;

	ret_record = NULL;
	ret_record = (aa_log_record *) malloc(sizeof(aa_log_record));

	_init_log_record(ret_record);

	if (ret_record == NULL)
		return NULL;

#if (YYDEBUG != 0)
	yydebug = 1;
#endif

	aalogparse_lex_init(&scanner);
	lex_buf = aalogparse__scan_string(str, scanner);
	parser_return = aalogparse_parse(scanner);
	aalogparse__delete_buffer(lex_buf, scanner);
	aalogparse_lex_destroy(scanner);
	return ret_record;
}
