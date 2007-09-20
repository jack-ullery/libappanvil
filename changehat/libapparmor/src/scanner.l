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

%option noyywrap
%option reentrant
%option prefix="aalogparse_"
%option bison-bridge
%option header-file="scanner.h"
%option outfile="scanner.c" 
%option stack
%{

#include "grammar.h"
#include "aalogparse.h"
#include "parser.h"
%}

ws		[ \t\r\n]

equals		"="
digits		[0-9]+
hex		[A-F0-9]
colon		":"
open_paren	"("
close_paren	")"
ID		[^ \t\n\(\)="'!]
path		"/"{ID}*
hexstring	({hex}{hex})+
period		"\."
modes           [RrWwXxIiLlUuPpMm]

/* New message types */

reject_type		"APPARMOR_DENIED"
audit_type		"APPARMOR_AUDIT"
complain_type		"APPARMOR_ALLOWED"
hint_type		"APPARMOR_HINT"
status_type		"APPARMOR_STATUS"
error_type		"APPARMOR_ERROR"
unknown_type		UNKNOWN\[{digits}+\]
other_audit_type	[[:alnum:]\[\]_-]+

/* Old message tokens */

old_apparmor_type	"APPARMOR"
old_apparmor_reject	"REJECTING"
old_apparmor_permit	"PERMITTING"
old_apparmor_audit	"AUDITING"
old_apparmor_logprof	"LOGPROF-HINT"
old_unknown_hat		"unknown_hat"
old_unknown_profile	"unknown_profile"
old_missing_profile	"missing_mandatory_profile"
old_changing_profile	"changing_profile"
old_active		"active"
old_access		"access"
old_from		"from"
old_to			"to"
old_pipe		"pipe"
old_extended		"extended"
old_rmdir		"rmdir"
old_mkdir		"mkdir"
old_on			"on"
old_xattr		"xattr"
old_change		"change"
old_capability		"capability"
old_syscall		"syscall"
old_link		"link"
old_fork		"fork"
old_child		"child"

null_complain		"null-complain-profile"

/* Key tokens */

key_type		"type"
key_msg			"msg"
key_operation		"operation"
key_name		"name"
key_name2		"name2"
key_denied_mask		"denied_mask"
key_requested_mask	"requested_mask"
key_attribute		"attribute"
key_task		"task"
key_parent		"parent"
key_magic_token		"magic_token"
key_info		"info"
key_pid			"pid"
key_profile		"profile"
key_image		"image"
key_family		"family"
key_sock_type		"sock_type"
key_protocol		"protocol"
audit			"audit"

/* syslog tokens */
syslog_kernel		kernel{colon}
syslog_month 		Jan(uary)?|Feb(ruary)?|Mar(ch)?|Apr(il)?|May|Jun(e)?|Jul(y)?|Aug(ust)?|Sep(tember)?|Oct(ober)?|Nov(ember)?|Dec(ember)?
syslog_time 		{digits}{digits}{colon}{digits}{digits}{colon}{digits}{digits}
syslog_hostname		[[:alnum:]_-]+
dmesg_timestamp		\[[[:digit:] ]{5,}\.[[:digit:]]{6,}\]

%x quoted_string
%x sub_id
%x audit_id
%x single_quoted_string
%x hostname
%x dmesg_timestamp
%x safe_string
%x audit_types
%x other_audit
%x unknown_message

%%
%{
char string_buf[512];
char *string_buf_ptr = string_buf; /* assignment to quiet gcc warning */

/* yy_flex_debug = 1;  */
%}

{ws}+			{ /* Skip whitespace */ }

<audit_id>{
	{digits}		{ yylval->t_str = strdup(yytext); return(TOK_AUDIT_DIGITS);}
	{colon}			{ return(TOK_COLON); }
	{period}		{ return(TOK_PERIOD); }
	{open_paren}		{ return(TOK_OPEN_PAREN); }
	{close_paren}		{ yy_pop_state(yyscanner); return(TOK_CLOSE_PAREN); }
}

<sub_id>{
	{open_paren}		{ return(TOK_OPEN_PAREN); }
	{close_paren}		{ BEGIN(INITIAL); return(TOK_CLOSE_PAREN); }
	"'"			{ string_buf_ptr = string_buf; BEGIN(single_quoted_string); }
	{ws}		{ }
	\"			{ string_buf_ptr = string_buf; BEGIN(quoted_string); }
	{ID}+	{
			yylval->t_str = strdup(yytext);
			BEGIN(INITIAL);
			return(TOK_ID);
		}
	{equals}		{ return(TOK_EQUALS); }
	}


"'"			{ string_buf_ptr = string_buf; BEGIN(single_quoted_string); }
<single_quoted_string>"'" { /* End of the quoted string */
				BEGIN(INITIAL);
				*string_buf_ptr = '\0';
				yylval->t_str = strdup(string_buf);
				return(TOK_SINGLE_QUOTED_STRING);
			}


<single_quoted_string>\\(.|\n) { *string_buf_ptr++ = yytext[1]; }

<single_quoted_string>[^\\\n\'\"]+ {
				char *yptr = yytext;
				while (*yptr)
				{
					*string_buf_ptr++ = *yptr++;
				}

			}

\"			{ string_buf_ptr = string_buf; BEGIN(quoted_string); }
<quoted_string>\"	{ /* End of the quoted string */
				BEGIN(INITIAL);
				*string_buf_ptr = '\0';
				yylval->t_str = strdup(string_buf);
				return(TOK_QUOTED_STRING);
			}


<quoted_string>\\(.|\n) { *string_buf_ptr++ = yytext[1]; }

<quoted_string>[^\\\n\"]+ {
			char *yptr = yytext;
				while (*yptr)
				{
					*string_buf_ptr++ = *yptr++;
				}
			}

<safe_string>{
	"'"		{ string_buf_ptr = string_buf; BEGIN(single_quoted_string); }
	\"		{ string_buf_ptr = string_buf; BEGIN(quoted_string); }
	{hexstring}	{ yylval->t_str = hex_to_string(yytext); BEGIN(INITIAL); return(TOK_HEXSTRING);}
	{equals}	{ return(TOK_EQUALS); }
	.		{ /* eek, error! try another state */ BEGIN(INITIAL); yyless(0); }
	}

<audit_types>{
	{equals}	{ return(TOK_EQUALS); }
	{digits}	{ yylval->t_long = atol(yytext); BEGIN(INITIAL); return(TOK_DIGITS); }
	{reject_type}	{ BEGIN(INITIAL); return(TOK_TYPE_REJECT); }
	{audit_type}	{ BEGIN(INITIAL); return(TOK_TYPE_AUDIT); }
	{complain_type}	{ BEGIN(INITIAL); return(TOK_TYPE_COMPLAIN); }
	{hint_type}	{ BEGIN(INITIAL); return(TOK_TYPE_HINT); }
	{status_type}	{ BEGIN(INITIAL); return(TOK_TYPE_STATUS); }
	{error_type}	{ BEGIN(INITIAL); return(TOK_TYPE_ERROR); }
	{unknown_type}	{ char *yptr = yytext;
			  while (*yptr && *yptr != '[')
			  	yptr++;
			  if (*yptr)
			  	yylval->t_long = atol(yptr + 1); /* skip '[' */
			  BEGIN(INITIAL);
			  return(TOK_TYPE_UNKNOWN);
			}
	{old_apparmor_type} { BEGIN(INITIAL); return(TOK_OLD_TYPE_APPARMOR); }
	{other_audit_type}  { yylval->t_str = strdup(yytext);
			      BEGIN(other_audit);
			      return(TOK_TYPE_OTHER);
			}
	}

{equals}		{ return(TOK_EQUALS); }
{digits}		{ yylval->t_long = atol(yytext); return(TOK_DIGITS); }
{colon}			{ return(TOK_COLON); }
{open_paren}		{
			BEGIN(sub_id);
			return(TOK_OPEN_PAREN); 
			}
{close_paren}		{ return(TOK_CLOSE_PAREN); }
{path}			{ yylval->t_str = strdup(yytext); return(TOK_PATH); }
{period}		{ return(TOK_PERIOD); }

{old_apparmor_reject}	{ return(TOK_OLD_APPARMOR_REJECT); }
{old_apparmor_permit}	{ return(TOK_OLD_APPARMOR_PERMIT); }
{old_apparmor_audit}	{ return(TOK_OLD_APPARMOR_AUDIT); }
{old_apparmor_logprof}	{ return(TOK_OLD_APPARMOR_LOGPROF_HINT); }
{old_unknown_hat}	{ BEGIN(sub_id); return(TOK_OLD_UNKNOWN_HAT); }
{old_unknown_profile}	{ return(TOK_OLD_UNKNOWN_PROFILE); }
{old_missing_profile}	{ return(TOK_OLD_MISSING_PROFILE); }
{old_changing_profile}	{ return(TOK_OLD_CHANGING_PROFILE); }
{old_active}		{ BEGIN(sub_id); return(TOK_OLD_ACTIVE); }
{old_access}		{ return(TOK_OLD_ACCESS); }
{old_to}		{ return(TOK_OLD_TO); }
{old_from}		{ return(TOK_OLD_FROM); }
{old_pipe}		{ return(TOK_OLD_PIPE); }
{old_extended}		{ return(TOK_OLD_EXTENDED); }
{old_mkdir}		{ return(TOK_OLD_MKDIR); }
{old_rmdir}		{ return(TOK_OLD_RMDIR); }
{old_on}		{ return(TOK_OLD_ON); }
{old_xattr}		{ BEGIN(sub_id); return(TOK_OLD_XATTR); }
{old_change}		{ return(TOK_OLD_CHANGE); }
{old_capability}	{ BEGIN(sub_id); return(TOK_OLD_CAPABILITY); }
{old_syscall}		{ return(TOK_OLD_SYSCALL); }
{old_link}		{ return(TOK_OLD_LINK); }
{old_fork}		{ return(TOK_OLD_FORK); }
{old_child}		{ return(TOK_OLD_CHILD); }
{modes}+		{ yylval->t_str = strdup(yytext); return(TOK_MODE); }

{key_type}		{ BEGIN(audit_types); return(TOK_KEY_TYPE); }
{key_msg}		{ return(TOK_KEY_MSG); }
{key_operation}		{ return(TOK_KEY_OPERATION); }
{key_name}		{ BEGIN(safe_string); return(TOK_KEY_NAME); }
{key_name2}		{ BEGIN(safe_string); return(TOK_KEY_NAME2); }
{key_denied_mask}	{ return(TOK_KEY_DENIED_MASK); }
{key_requested_mask}	{ return(TOK_KEY_REQUESTED_MASK); }
{key_attribute}		{ BEGIN(sub_id); return(TOK_KEY_ATTRIBUTE); }
{key_task}		{ return(TOK_KEY_TASK); }
{key_parent}		{ return(TOK_KEY_PARENT); }
{key_magic_token}	{ return(TOK_KEY_MAGIC_TOKEN); }
{key_info}		{ return(TOK_KEY_INFO); }
{key_pid}		{ return(TOK_KEY_PID); }
{key_profile}		{ BEGIN(safe_string); return(TOK_KEY_PROFILE); }
{key_family}		{ return(TOK_KEY_FAMILY); }
{key_sock_type}		{ return(TOK_KEY_SOCK_TYPE); }
{key_protocol}		{ return(TOK_KEY_PROTOCOL); }

{syslog_kernel}		{ BEGIN(dmesg_timestamp); return(TOK_SYSLOG_KERNEL); }
{syslog_month}		{ yylval->t_str = strdup(yytext); return(TOK_DATE_MONTH); }
{syslog_time}		{ yylval->t_str = strdup(yytext); BEGIN(hostname); return(TOK_DATE_TIME); }

{audit}			{ yy_push_state(audit_id, yyscanner); return(TOK_AUDIT); }
{null_complain}		{ return(TOK_NULL_COMPLAIN); }
{key_image}		{ BEGIN(sub_id); return(TOK_KEY_IMAGE); }

<hostname>{
	{ws}+		{ /* eat whitespace */ }
	{syslog_hostname} { yylval->t_str = strdup(yytext); BEGIN(INITIAL); return(TOK_ID); }
}

<dmesg_timestamp>{
	{ws}+		{ /* eat whitespace */ }
	{dmesg_timestamp} { yylval->t_str = strdup(yytext); BEGIN(INITIAL); return(TOK_DMESG_STAMP); }
	.		{ /* no timestamp in this message */ BEGIN(INITIAL); yyless(0); }
}

<other_audit>{
	{ws}+		{ /* eat whitespace */ }
	{audit}		{ yy_push_state(audit_id, yyscanner); return(TOK_AUDIT); }
	{key_msg}	{ return(TOK_KEY_MSG); }
	{equals}	{ return(TOK_EQUALS); }
	{colon}		{ return(TOK_COLON); }
	.		{ BEGIN(unknown_message); yyless(0); /* dump the rest */ }
}

<unknown_message>{
	.*		{ yylval->t_str = strdup(yytext); return(TOK_MSG_REST); }
	\n		{ /* not sure why needed here and not elsewhere */ }
	}

%%
