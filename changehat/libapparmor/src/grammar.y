/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, contact Novell, Inc.
 */


%{

#define YYDEBUG 0
#include <string.h>
#include "aalogparse.h"
#include "parser.h"
#include "grammar.h"
#include "scanner.h"

aa_log_record *ret_record;
void aalogparse_error(void *scanner, char const *s)
{
	printf("Error: %s\n", s);
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

%type <t_str> old_profile;
%token <t_long> TOK_DIGITS
%token <t_str> TOK_QUOTED_STRING TOK_PATH TOK_ID TOK_NULL_COMPLAIN TOK_MODE TOK_SINGLE_QUOTED_STRING TOK_AUDIT_DIGITS

%token TOK_EQUALS
%token TOK_COLON
%token TOK_OPEN_PAREN
%token TOK_CLOSE_PAREN
%token TOK_PERIOD

%token TOK_TYPE_REJECT
%token TOK_TYPE_AUDIT
%token TOK_TYPE_COMPLAIN
%token TOK_TYPE_HINT
%token TOK_TYPE_STATUS
%token TOK_TYPE_ERROR
%token TOK_OLD_TYPE_APPARMOR
%token TOK_OLD_APPARMOR_REJECT
%token TOK_OLD_APPARMOR_PERMIT
%token TOK_OLD_APPARMOR_LOGPROF_HINT
%token TOK_OLD_UNKNOWN_HAT
%token TOK_OLD_ACTIVE
%token TOK_OLD_UNKNOWN_PROFILE
%token TOK_OLD_MISSING_PROFILE
%token TOK_OLD_ACCESS
%token TOK_OLD_TO
%token TOK_OLD_PIPE
%token TOK_OLD_EXTENDED
%token TOK_OLD_ATTRIBUTE
%token TOK_OLD_ON
%token TOK_OLD_MKDIR
%token TOK_OLD_RMDIR
%token TOK_OLD_XATTR
%token TOK_OLD_CHANGE
%token TOK_OLD_CAPABILITY
%token TOK_OLD_FORK
%token TOK_OLD_CHILD

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
%token TOK_KEY_IMAGE

%%

type: TOK_KEY_TYPE TOK_EQUALS type_syntax ;

type_syntax: old_syntax { ret_record->version = AA_RECORD_SYNTAX_V1; }
	 | new_syntax { ret_record->version = AA_RECORD_SYNTAX_V2; }
	;

old_syntax: TOK_OLD_TYPE_APPARMOR audit_msg old_msg ;

new_syntax: 
	  TOK_TYPE_REJECT audit_msg key { ret_record->event = AA_RECORD_DENIED; }
	| TOK_TYPE_AUDIT audit_msg key { ret_record->event = AA_RECORD_AUDIT; }
	| TOK_TYPE_COMPLAIN audit_msg key { ret_record->event = AA_RECORD_ALLOWED; }
	| TOK_TYPE_HINT audit_msg key { ret_record->event = AA_RECORD_HINT; }
	| TOK_TYPE_STATUS audit_msg key { ret_record->event = AA_RECORD_STATUS; }
	| TOK_TYPE_ERROR audit_msg key { ret_record->event = AA_RECORD_ERROR; }
	;

old_msg:
	  old_permit_reject_syntax old_permit_reject_syntax2
	| TOK_OLD_APPARMOR_LOGPROF_HINT old_logprof_syntax { ret_record->event = AA_RECORD_HINT; }
	;

old_permit_reject_syntax:
	  TOK_OLD_APPARMOR_REJECT { ret_record->event = AA_RECORD_DENIED; }
	| TOK_OLD_APPARMOR_PERMIT { ret_record->event = AA_RECORD_ALLOWED; }
	;

old_permit_reject_syntax2:
	  TOK_MODE TOK_OLD_ACCESS old_permit_reject_path_pipe_extended
		TOK_OPEN_PAREN TOK_ID TOK_OPEN_PAREN TOK_ID TOK_CLOSE_PAREN
		TOK_KEY_PROFILE old_profile TOK_OLD_ACTIVE old_profile TOK_CLOSE_PAREN
	{
		ret_record->requested_mask = strdup($1);
		free($1);
		ret_record->info = strdup($5);
		free($5);
		ret_record->pid = atol($7);
		free($7);
		ret_record->profile = strdup($10);
		free($10);
		ret_record->active_hat = strdup($12);
		free($12);
		ret_record->operation = strdup("access");
	}
	| mkdir_or_rmdir TOK_OLD_ON TOK_PATH
		TOK_OPEN_PAREN TOK_ID TOK_OPEN_PAREN TOK_ID TOK_CLOSE_PAREN
		TOK_KEY_PROFILE old_profile TOK_OLD_ACTIVE old_profile TOK_CLOSE_PAREN
	{
		ret_record->name = strdup($3);
		free($3);
		ret_record->info = strdup($5);
		free($5);
		ret_record->pid = atol($7);
		free($7);
		ret_record->profile = strdup($10);
		free($10);
		ret_record->active_hat = strdup($12);
		free($12);
	}
	| TOK_OLD_XATTR TOK_ID TOK_OLD_ON TOK_PATH
		TOK_OPEN_PAREN TOK_ID TOK_OPEN_PAREN TOK_ID TOK_CLOSE_PAREN
		TOK_KEY_PROFILE old_profile TOK_OLD_ACTIVE old_profile TOK_CLOSE_PAREN
	{
		ret_record->operation = strdup("xattr");
		ret_record->attribute = strdup($2);
		free($2);
		ret_record->name = strdup($4);
		free($4);
		ret_record->info = strdup($6);
		free($6);
		ret_record->pid = atol($8);
		free($8);
		ret_record->profile = strdup($11);
		free($11);
		ret_record->active_hat = strdup($13);
		free($13);
	}
	| TOK_KEY_ATTRIBUTE TOK_OPEN_PAREN TOK_ID TOK_CLOSE_PAREN
		TOK_OLD_CHANGE TOK_OLD_TO TOK_PATH
		TOK_OPEN_PAREN TOK_ID TOK_OPEN_PAREN TOK_ID TOK_CLOSE_PAREN
		TOK_KEY_PROFILE old_profile TOK_OLD_ACTIVE old_profile TOK_CLOSE_PAREN
	{
		ret_record->operation = strdup("setattr");
		ret_record->attribute = strdup($3);
		free($3);
		ret_record->name = strdup($7);
		free($7);
		ret_record->info = strdup($9);
		free($9);
		ret_record->pid = atol($11);
		free($11);
		ret_record->profile = strdup($14);
		free($14);
		ret_record->active_hat = strdup($16);
		free($16);
	}
	| TOK_OLD_ACCESS TOK_OLD_TO TOK_OLD_CAPABILITY TOK_SINGLE_QUOTED_STRING
		TOK_OPEN_PAREN TOK_ID TOK_OPEN_PAREN TOK_ID TOK_CLOSE_PAREN
		TOK_KEY_PROFILE old_profile TOK_OLD_ACTIVE old_profile TOK_CLOSE_PAREN
	{
		ret_record->operation = strdup("capability");
		ret_record->name = strdup($4);
		free($4);
		ret_record->info = strdup($6);
		free($6);
		ret_record->pid = atol($8);
		free($8);
		ret_record->profile = strdup($11);
		free($11);
		ret_record->active_hat = strdup($13);
		free($13);
	}
	;

mkdir_or_rmdir:
	  TOK_OLD_MKDIR { ret_record->operation = strdup("mkdir"); }
	| TOK_OLD_RMDIR { ret_record->operation = strdup("rmdir"); }
	;

old_permit_reject_path_pipe_extended:
	  TOK_OLD_TO TOK_PATH
		{
			ret_record->name = strdup($2);
			free($2);
		}
	| TOK_OLD_TO TOK_OLD_PIPE /* Frankly, I don't think this is used */
		{
			ret_record->info = strdup("pipe");
		}
	| TOK_OLD_EXTENDED TOK_KEY_ATTRIBUTE /* Nor this */
		{
			ret_record->info = strdup("extended attribute");
		}
	;
old_logprof_syntax:
		  old_logprof_syntax2 TOK_KEY_PID TOK_EQUALS TOK_DIGITS 
			TOK_KEY_PROFILE TOK_EQUALS old_profile TOK_OLD_ACTIVE TOK_EQUALS old_profile
			{
				ret_record->pid = $4;
				ret_record->profile = strdup($7);
				free($7);
				ret_record->active_hat = strdup($10);
				free($10);
			}
		| old_logprof_fork_syntax
		;

old_logprof_syntax2:
	  TOK_OLD_UNKNOWN_PROFILE TOK_KEY_IMAGE TOK_EQUALS TOK_ID
		{
			ret_record->operation = strdup("profile_set");
			ret_record->info = strdup("unknown profile");
			ret_record->name = strdup($4);
			free($4);
		}
	| TOK_OLD_MISSING_PROFILE TOK_KEY_IMAGE TOK_EQUALS TOK_ID 
		{
			ret_record->operation = strdup("exec");
			ret_record->info = strdup("mandatory profile missing");
			ret_record->name = strdup($4);
			free($4);
		}
	| TOK_OLD_UNKNOWN_HAT TOK_ID
		{
			ret_record->operation = strdup("change_hat");
			ret_record->name = strdup($2); 
			free($2);
			ret_record->info = strdup("unknown_hat");
		}
	;

/* TODO: Clean this up */
old_logprof_fork_syntax:
	  TOK_OLD_FORK TOK_KEY_PID TOK_EQUALS TOK_DIGITS
		TOK_OLD_CHILD TOK_EQUALS TOK_DIGITS old_logprof_fork_addition
	{
		ret_record->operation = strdup("clone");
		ret_record->task = $7;
		ret_record->pid = $4;
	}
	;

old_logprof_fork_addition:
	/* Nothin */
	| TOK_KEY_PROFILE TOK_EQUALS old_profile TOK_OLD_ACTIVE TOK_EQUALS old_profile
	{
		ret_record->profile = strdup($3);
		free($3);
		ret_record->active_hat = strdup($6);
		free($6);
	}
	;

old_profile:
	  TOK_PATH
		{
			$$ = strdup($1);
			free($1);
		}
	| TOK_NULL_COMPLAIN
		{
			$$ = strdup("null-complain-profile");
		}
	;

audit_msg: TOK_KEY_MSG TOK_EQUALS TOK_AUDIT TOK_OPEN_PAREN TOK_AUDIT_DIGITS TOK_PERIOD TOK_AUDIT_DIGITS TOK_COLON TOK_AUDIT_DIGITS TOK_CLOSE_PAREN TOK_COLON
	{
		asprintf(&ret_record->audit_id, "%s.%s:%s", $5, $7, $9);
		free($5);
		free($7);
		free($9);
	} ;

key:
	  key_list
	| key key_list
	;

key_list: TOK_KEY_OPERATION TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->operation = strdup($3); free($3); }
	| TOK_KEY_NAME TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->name = strdup($3); free($3); }
	| TOK_KEY_NAME2 TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->name2 = strdup($3); free($3); }
	| TOK_KEY_DENIED_MASK TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->denied_mask = strdup($3); free($3);}
	| TOK_KEY_REQUESTED_MASK TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->requested_mask = strdup($3); free($3);}
	| TOK_KEY_ATTRIBUTE TOK_EQUALS TOK_QUOTED_STRING 
	{ ret_record->attribute = strdup($3); free($3);}
	| TOK_KEY_TASK TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->task = atol($3); free($3);}
	| TOK_KEY_PARENT TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->parent = strdup($3); free($3);}
	| TOK_KEY_MAGIC_TOKEN TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->magic_token = strdup($3); free($3);}
	| TOK_KEY_INFO TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->info = strdup($3); free($3);}
	| TOK_KEY_PID TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->pid = atol($3); free($3);}
	| TOK_KEY_PROFILE TOK_EQUALS TOK_QUOTED_STRING
	{ ret_record->profile = strdup($3); free($3);}
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

	aalogparse_lex_init(&scanner);
	lex_buf = aalogparse__scan_string(str, scanner);
	parser_return = aalogparse_parse(scanner);
	aalogparse__delete_buffer(lex_buf, scanner);
	aalogparse_lex_destroy(scanner);
	return ret_record;
}
