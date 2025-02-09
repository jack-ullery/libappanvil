/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *   Copyright (c) 2010 - 2013
 *   Canonical Ltd. (All rights reserved)
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
 *   along with this program; if not, contact Canonical, Ltd.
 */

/* Definitions section */
/* %option main */
%option c++
%option interactive
%option noyylineno

/* options set to noXXX eliminates need to link with libfl */
%option noyywrap
%option noyy_top_state
%option nounput
%option stack
%option nodefault

%option yyclass="Lexer"

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <unordered_map>
#include <string>

#include "common.hh"
#include "driver.hh"
#include "parser.h"
#include "lexer.hh"
#include "lib.h"

#define YY_USER_ACTION 								\
  driver.yylloc.first_pos = driver.yylloc.last_pos;	\
  driver.yylloc.last_pos  = yyin.tellg();

#define DUMP_PREPROCESS do { /*ECHO;*/ } while (0)

#define DUMP_AND_DEBUG(X...) \
do { \
	DUMP_PREPROCESS; \
} while (0)

#define EAT_TOKEN(X...) DUMP_AND_DEBUG(X)

#define POP() \
do { \
	DUMP_AND_DEBUG(" (pop_to(%s)): Matched: %s\n", state_names[yy_top_state()].c_str(), yytext); \
	yy_pop_state(); \
} while (0)

#define POP_NODUMP() \
do { \
	yy_pop_state(); \
} while (0)

#define PUSH(X) \
do { \
	DUMP_AND_DEBUG(" (push(%s)): Matched: %s\n", state_names[(X)].c_str(), yytext); \
	yy_push_state(X); \
} while (0)

#define YY_NO_INPUT

#define STATE_TABLE_ENT(X) {X, #X }
extern std::unordered_map<int, std::string> state_names;

static char *lsntrim(char *s, int l)
{
	const char *end = s + l;

	while (s <= end && isspace(*s))
		s++;
	return s;
}

static int rsntrim(const char *s, int l)
{
	const char *r = s + l;

	while (r > s && isspace(*--r))
		l--;
	return l;
}

%}

CARET		"^"
OPEN_BRACE 	\{
CLOSE_BRACE \}
SLASH		\/
COLON		:
AMPERSAND	&
END_OF_RULE	[,]
RANGE		-
MODE_CHARS 	([RrWwaLlMmkXx])|(([Pp]|[Cc])[Xx])|(([Pp]|[Cc])?([IiUu])[Xx])
MODES		{MODE_CHARS}+
WS		[[:blank:]]
NUMBER		[[:digit:]]+

ID_CHARS	[^ \t\r\n"!,]
ID 		{ID_CHARS}|(,{ID_CHARS}|\\[ ]|\\\t|\\\"|\\!|\\,)
IDS		{ID}+
INC_ID 		[^ \t\r\n"!,<>]|(,[^ \t\r\n"!,<>]|\\[ ]|\\\t|\\\"|\\!|\\,)
INC_IDS		{INC_ID}+
POST_VAR_ID_CHARS	[^ \t\n"!,]{-}[=\+]
POST_VAR_ID 	{POST_VAR_ID_CHARS}|(,{POST_VAR_ID_CHARS}|\\[ ]|\\\t|\\\"|\\!|\\,|\\\(|\\\))
LIST_VALUE_ID_CHARS	([^ \t\n"!,]{-}[()]|\\[ ]|\\\t|\\\"|\\!|\\,|\\\(|\\\))
LIST_VALUE_QUOTED_ID_CHARS [^\0"]|\\\"
LIST_VALUE_ID	{LIST_VALUE_ID_CHARS}+
QUOTED_LIST_VALUE_ID	\"{LIST_VALUE_QUOTED_ID_CHARS}+\"
ID_CHARS_NOEQ	[^ \t\n"!,]{-}[=)]
LEADING_ID_CHARS_NOEQ [^ \t\n"!,]{-}[=()+&]
ID_NOEQ		{ID_CHARS_NOEQ}|(,{ID_CHARS_NOEQ})
IDS_NOEQ	{LEADING_ID_CHARS_NOEQ}{ID_NOEQ}*
ALLOWED_QUOTED_ID 	[^\0"]|\\\"
QUOTED_ID	\"{ALLOWED_QUOTED_ID}*\"

IP		{NUMBER}\.{NUMBER}\.{NUMBER}\.{NUMBER}

HAT		hat{WS}*
PROFILE		profile{WS}*
KEYWORD         [[:alpha:]_]+
VARIABLE_NAME	[[:alpha:]][[:alnum:]_]*
SET_VAR_PREFIX  @
SET_VARIABLE	{SET_VAR_PREFIX}(\{{VARIABLE_NAME}\}|{VARIABLE_NAME})
BOOL_VARIABLE	$(\{{VARIABLE_NAME}\}|{VARIABLE_NAME})

LABEL		(\/|{SET_VARIABLE}{POST_VAR_ID}|{COLON}|{AMPERSAND}){ID}*
QUOTED_LABEL	\"(\/|{SET_VAR_PREFIX}|{COLON}|{AMPERSAND})([^\0"]|\\\")*\"

OPEN_PAREN 	\(
CLOSE_PAREN	\)
COMMA		\,
EQUALS		=
ADD_ASSIGN	\+=
ARROW		->
LT_EQUAL	<=
LT		<
GT		>

/* IF adding new state please update state_names table and default rule (just
 * above the state_names table) at the eof.
 *
 * The nodefault option is set so missing adding to the default rule isn't
 * fatal but can't take advantage of additional debug the default rule might
 * have.
 *
 * If a state is not added to the default rule it can result in the message
 * "flex scanner jammed"
 */
%x SUB_ID
%x SUB_ID_WS
%x SUB_VALUE
%x EXTCOND_MODE
%x EXTCONDLIST_MODE
%x NETWORK_MODE
%x LIST_VAL_MODE
%x LIST_COND_MODE
%x LIST_COND_VAL
%x LIST_COND_PAREN_VAL
%x ASSIGN_MODE
%x RLIMIT_MODE
%x MOUNT_MODE
%x DBUS_MODE
%x SIGNAL_MODE
%x PTRACE_MODE
%x UNIX_MODE
%x CHANGE_PROFILE_MODE
%x INCLUDE
%x INCLUDE_EXISTS
%x ABI_MODE
%x USERNS_MODE

%%

%{
%}

<INITIAL,SUB_ID_WS,INCLUDE,INCLUDE_EXISTS,LIST_VAL_MODE,EXTCOND_MODE,LIST_COND_VAL,LIST_COND_PAREN_VAL,LIST_COND_MODE,EXTCONDLIST_MODE,ASSIGN_MODE,NETWORK_MODE,CHANGE_PROFILE_MODE,RLIMIT_MODE,MOUNT_MODE,DBUS_MODE,SIGNAL_MODE,PTRACE_MODE,UNIX_MODE,ABI_MODE,USERNS_MODE>{
	{WS}+	{  DUMP_PREPROCESS; /* Ignoring whitespace */ }
}

<INCLUDE,INCLUDE_EXISTS,ABI_MODE>{
	(\<((([^"\>\t\r\n])+)|{QUOTED_ID})\>|{QUOTED_ID}|({INC_IDS}))	{ /* <filename> | <"filename"> | "filename" | filename */
		int lt = *yytext == '<'  ? 1 : 0;
		int len = yyleng - lt*2;
		char *s = yytext + lt;
		char * filename = lsntrim(s, yyleng);
		// yylval.id = filename;

		filename = processid(filename, rsntrim(filename, len - (filename - s)));
		if (!filename) {
			yyerror(_("Failed to process filename\n"));
		}

		if (YYSTATE == ABI_MODE) {
			if (lt)
				return yy::parser::make_TOK_ID(filename, driver.yylloc);
			else
				return yy::parser::make_TOK_VALUE(filename, driver.yylloc);
		}

		POP();
		if (lt) {
			return yy::parser::make_TOK_ID(filename, driver.yylloc);
		}
		else {
			return yy::parser::make_TOK_VALUE(filename, driver.yylloc);
		}
	}
}

<<EOF>> {
	yypop_buffer_state();
	if ( !YY_CURRENT_BUFFER )
		yyterminate();
}

<INITIAL,MOUNT_MODE,DBUS_MODE,SIGNAL_MODE,PTRACE_MODE,UNIX_MODE>{
	(peer|xattrs)/{WS}*={WS}*\(	{
		/* we match to the = in the lexer so that we can switch scanner
		 * state.  By the time the parser see the = it may be too late
		 * as bison may have requested the next token from the scanner
		 */
		std::string pid = processid(yytext, yyleng);
		PUSH(EXTCONDLIST_MODE);
		return yy::parser::make_TOK_CONDLISTID(pid, driver.yylloc);
	}
	{VARIABLE_NAME}/{WS}*=	{
		/* we match to the = in the lexer so that we can switch scanner
		 * state.  By the time the parser see the = it may be too late
		 * as bison may have requested the next token from the scanner
		 */
		std::string pid = processid(yytext, yyleng);
		PUSH(EXTCOND_MODE);
		return yy::parser::make_TOK_CONDID(pid, driver.yylloc);
	}
	{VARIABLE_NAME}/{WS}+in{WS}*\(	{
		/* we match to 'in' in the lexer so that we can switch scanner
		 * state.  By the time the parser see the 'in' it may be to
		 * late as bison may have requested the next token from the
		 * scanner
		 */
		std::string pid = processid(yytext, yyleng);
		PUSH(EXTCOND_MODE);
		return yy::parser::make_TOK_CONDID(pid, driver.yylloc);
	}
}

<SUB_ID,SUB_ID_WS>{
	({IDS}|{QUOTED_ID}) {
		/* Go into separate state to match generic ID strings */
		std::string pid = processid(yytext, yyleng);
		POP();
		return yy::parser::make_TOK_ID(pid, driver.yylloc);
	}
}

<SUB_VALUE>{
	({IDS}|{QUOTED_ID}) {
		/* Go into separate state to match generic VALUE strings */
		std::string pid = processid(yytext, yyleng);
		POP();
		return yy::parser::make_TOK_VALUE(pid, driver.yylloc);
	}
}

<LIST_VAL_MODE>{
	{CLOSE_PAREN} { 
		POP();
		return yy::parser::make_TOK_CLOSEPAREN(driver.yylloc);
	}

	{COMMA}	{ EAT_TOKEN("listval: ,\n"); }

	({LIST_VALUE_ID}|{QUOTED_ID}) {
		std::string pid = processid(yytext, yyleng);
		return yy::parser::make_TOK_VALUE(pid, driver.yylloc);
	}
}

<EXTCOND_MODE>{
	{EQUALS}{WS}*/[^(\n]{-}{WS} {
		BEGIN(SUB_VALUE); 
		return yy::parser::make_TOK_EQUALS(driver.yylloc);
	}

	{EQUALS} { return yy::parser::make_TOK_EQUALS(driver.yylloc); }

	/* Don't push state here as this is a transition start condition and
	 * we want to return to the start condition that invoked <EXTCOND_MODE>
	 * when LIST_VAL_ID is done
	 */
	{OPEN_PAREN} {
		BEGIN(LIST_VAL_MODE); 
		return yy::parser::make_TOK_OPENPAREN(driver.yylloc);
	}

	in { return yy::parser::make_TOK_IN(driver.yylloc); }
}

<LIST_COND_VAL>{
	({LIST_VALUE_ID}|{QUOTED_LIST_VALUE_ID}) {
		std::string pid = processid(yytext, yyleng);
		POP();
		return yy::parser::make_TOK_VALUE(pid, driver.yylloc);
	}
}

<LIST_COND_PAREN_VAL>{
	{CLOSE_PAREN}	{ POP(); }

	({LIST_VALUE_ID}|{QUOTED_LIST_VALUE_ID}) {
		std::string pid = processid(yytext, yyleng);
		return yy::parser::make_TOK_VALUE(pid, driver.yylloc);
	}
}

<LIST_COND_MODE>{
	{CLOSE_PAREN}	{ 
		POP();
		return yy::parser::make_TOK_CLOSEPAREN(driver.yylloc);
	}

	{COMMA}		{ EAT_TOKEN("listcond: , \n"); }

	{ID_CHARS_NOEQ}+	{
		std::string pid = processid(yytext, yyleng);
		return yy::parser::make_TOK_CONDID(pid, driver.yylloc);
	}

	{EQUALS}{WS}*{OPEN_PAREN}	{
		PUSH(LIST_COND_PAREN_VAL);
		return yy::parser::make_TOK_EQUALS(driver.yylloc);
	}

	{EQUALS}	{
		PUSH(LIST_COND_VAL);
		return yy::parser::make_TOK_EQUALS(driver.yylloc);
	}
}

<EXTCONDLIST_MODE>{
	{EQUALS}	{ return yy::parser::make_TOK_EQUALS(driver.yylloc); }

	{OPEN_PAREN}	{
		/* Don't push state here as this is a transition
		 * start condition and we want to return to the start
		 * condition that invoked <EXTCONDLIST_MODE> when
		 * LIST_VAL_ID is done
		 */
		BEGIN(LIST_COND_MODE);
		return yy::parser::make_TOK_OPENPAREN(driver.yylloc);
	}
}

<ASSIGN_MODE>{
	({IDS}|{QUOTED_ID}) {
		std::string pid = processid(yytext, yyleng);
		return yy::parser::make_TOK_VALUE(pid, driver.yylloc);
	}

	{END_OF_RULE} {
		// yylval.id = strdup(yytext);
		DUMP_PREPROCESS;
		yyerror(_("Variable declarations do not accept trailing commas"));
	}

	\\\n	{ DUMP_PREPROCESS; driver.current_lineno++ ; }

	\r?\n	{
		/* don't use shared rule because we need POP() here */
		DUMP_PREPROCESS;
		driver.current_lineno++;
		POP();
	}
}

<NETWORK_MODE>{
	{IDS} {
		return yy::parser::make_TOK_ID(yytext, driver.yylloc);
	}
}

<CHANGE_PROFILE_MODE>{
	safe		{ return yy::parser::make_TOK_SAFE(driver.yylloc); }
	unsafe		{ return yy::parser::make_TOK_UNSAFE(driver.yylloc); }

	{ARROW} {
		/**
		 * Push state so that we can return token::TOK_ID even when the
		 * change_profile target is 'safe' or 'unsafe'.
		 */
		PUSH(SUB_ID_WS);
		return yy::parser::make_TOK_ARROW(driver.yylloc);
	}

	({IDS}|{QUOTED_ID}) {
		std::string pid = processid(yytext, yyleng);
		return yy::parser::make_TOK_ID(pid, driver.yylloc);
	}
}

<RLIMIT_MODE>{
	-?{NUMBER} {
		return yy::parser::make_TOK_VALUE(yytext, driver.yylloc);
	}

	{KEYWORD}	{
		if (strcmp(yytext, "infinity") == 0) {
			return yy::parser::make_TOK_VALUE(yytext, driver.yylloc);
		}

		return yy::parser::make_TOK_ID(yytext, driver.yylloc);
	}

	{LT_EQUAL}	{ return yy::parser::make_TOK_LE(driver.yylloc); }
}

<UNIX_MODE>{
	listen	{ return yy::parser::make_TOK_LISTEN(driver.yylloc); }
	accept	{ return yy::parser::make_TOK_ACCEPT(driver.yylloc); }
	connect	{ return yy::parser::make_TOK_CONNECT(driver.yylloc); }
	getattr	{ return yy::parser::make_TOK_GETATTR(driver.yylloc); }
	setattr	{ return yy::parser::make_TOK_SETATTR(driver.yylloc); }
	getopt	{ return yy::parser::make_TOK_GETOPT(driver.yylloc); }
	setopt	{ return yy::parser::make_TOK_SETOPT(driver.yylloc); }
	shutdown	{ return yy::parser::make_TOK_SHUTDOWN(driver.yylloc); }
}

<UNIX_MODE,USERNS_MODE>{
	create	{ return yy::parser::make_TOK_CREATE(driver.yylloc); }
}

<DBUS_MODE,UNIX_MODE>{
	bind		{ return yy::parser::make_TOK_BIND(driver.yylloc); }
}

<DBUS_MODE>{
	eavesdrop	{ return yy::parser::make_TOK_EAVESDROP(driver.yylloc); }
}

<DBUS_MODE,SIGNAL_MODE,UNIX_MODE>{
	send		{ return yy::parser::make_TOK_SEND(driver.yylloc); }
	receive		{ return yy::parser::make_TOK_RECEIVE(driver.yylloc); }
}

<PTRACE_MODE>{
	trace		{ return yy::parser::make_TOK_TRACE(driver.yylloc); }
	readby		{ return yy::parser::make_TOK_READBY(driver.yylloc); }
	tracedby	{ return yy::parser::make_TOK_TRACEDBY(driver.yylloc); }
}

<DBUS_MODE,SIGNAL_MODE,PTRACE_MODE,UNIX_MODE>{
	read		{ return yy::parser::make_TOK_READ(driver.yylloc); }
	write		{ return yy::parser::make_TOK_WRITE(driver.yylloc); }
	{OPEN_PAREN}	{
				PUSH(LIST_VAL_MODE);
				return yy::parser::make_TOK_OPENPAREN(driver.yylloc);
			}
	(r|w|rw|wr)/([[:space:],])	{
				return yy::parser::make_TOK_MODE(yytext, driver.yylloc);
			}
}

<MOUNT_MODE>{
	{ARROW}		{ return yy::parser::make_TOK_ARROW(driver.yylloc); }
}

<MOUNT_MODE,DBUS_MODE,SIGNAL_MODE,PTRACE_MODE,UNIX_MODE>{
	({IDS_NOEQ}|{LABEL}|{QUOTED_ID}) {
		std::string pid = processid(yytext, yyleng);
		return yy::parser::make_TOK_ID(pid, driver.yylloc);
	}
}

#include{WS}+if{WS}+exists/{WS}.*\r?\n	{
	// pwarn(WARN_INCLUDE, _("deprecated use of '#include'\n"));
	PUSH(INCLUDE_EXISTS);
	return yy::parser::make_TOK_INCLUDE_IF_EXISTS(driver.yylloc);
}

include{WS}+if{WS}+exists/{WS}	{
	PUSH(INCLUDE_EXISTS);
	return yy::parser::make_TOK_INCLUDE_IF_EXISTS(driver.yylloc);
}

#include/.*\r?\n	{
	// pwarnf(WARN_INCLUDE, _("deprecated use of '#include'\n"));
	PUSH(INCLUDE);
	return yy::parser::make_TOK_INCLUDE(driver.yylloc);
}

include/{WS}	{
	PUSH(INCLUDE);
	return yy::parser::make_TOK_INCLUDE(driver.yylloc);
}

all/({WS}|[^[:alnum:]_]) {
	return yy::parser::make_TOK_ALL(driver.yylloc);
}

#.*\r?\n	{ /* normal comment */
	DUMP_AND_DEBUG("comment(%d): %s\n", driver.current_lineno, yytext);
	driver.current_lineno++;
}

{CARET}	{
	PUSH(SUB_ID);
	return yy::parser::make_TOK_CARET(driver.yylloc);
}

{ARROW} { 
	PUSH(SUB_ID_WS); 
	return yy::parser::make_TOK_ARROW(driver.yylloc);
}

{EQUALS} {
	PUSH(ASSIGN_MODE); 
	return yy::parser::make_TOK_EQUALS(driver.yylloc);
}

{ADD_ASSIGN} {
	PUSH(ASSIGN_MODE);
	return yy::parser::make_TOK_ADD_ASSIGN(driver.yylloc);
}

{SET_VARIABLE} {
	std::string text(yytext);
	return yy::parser::make_TOK_SET_VAR(text, driver.yylloc);
}

{BOOL_VARIABLE}	{
	std::string text(yytext);
	return yy::parser::make_TOK_BOOL_VAR(text, driver.yylloc);
}

{OPEN_BRACE}	{ return yy::parser::make_TOK_OPEN(driver.yylloc); }

{CLOSE_BRACE}	{
	return yy::parser::make_TOK_CLOSE(driver.yylloc);
}

({LABEL}|{QUOTED_LABEL}) {
	std::string pid = processid(yytext, yyleng);
	return yy::parser::make_TOK_ID(pid, driver.yylloc);
}

({MODES})/([[:space:],]) {
	std::string mode(yytext);
	return yy::parser::make_TOK_MODE(mode, driver.yylloc);
}

{HAT} {
	PUSH(SUB_ID);
	return yy::parser::make_TOK_HAT(driver.yylloc);
}

{PROFILE} {
	PUSH(SUB_ID);
	return yy::parser::make_TOK_PROFILE(driver.yylloc);
}

{COLON}	{ return yy::parser::make_TOK_COLON(driver.yylloc); }

{OPEN_PAREN} {
	PUSH(LIST_VAL_MODE);
	return yy::parser::make_TOK_OPENPAREN(driver.yylloc);
}

{VARIABLE_NAME}	{
	int token = get_keyword_token(yytext);
	int state = INITIAL;

	/* special cases */
	switch (token) {
	case -1:
	{
		/* no token found */
		std::string proc = processunquoted(yytext, yyleng);
		return yy::parser::make_TOK_ID(proc, driver.yylloc);
	}
	case token::TOK_RLIMIT:
		state = RLIMIT_MODE;
		break;
	case token::TOK_NETWORK:
		state = NETWORK_MODE;
		break;
	case token::TOK_CHANGE_PROFILE:
		state = CHANGE_PROFILE_MODE;
		break;
	case token::TOK_MOUNT:
	case token::TOK_REMOUNT:
	case token::TOK_UMOUNT:
		state = MOUNT_MODE;
		break;
	case token::TOK_DBUS:
		state = DBUS_MODE;
		break;
	case token::TOK_SIGNAL:
		state = SIGNAL_MODE;
		break;
	case token::TOK_PTRACE:
		state = PTRACE_MODE;
		break;
	case token::TOK_UNIX:
		state = UNIX_MODE;
		break;
	case token::TOK_ABI:
		state = ABI_MODE;
		break;
	case token::TOK_USERNS:
		state = USERNS_MODE;
		break;
	default: /* nothing */
		break;
	}

	PUSH(state);
	return yy::parser::symbol_type(token, driver.yylloc);
}

<INITIAL,NETWORK_MODE,RLIMIT_MODE,CHANGE_PROFILE_MODE,MOUNT_MODE,DBUS_MODE,SIGNAL_MODE,PTRACE_MODE,UNIX_MODE,ABI_MODE,USERNS_MODE>{
	{END_OF_RULE}	{
		if (YY_START != INITIAL)
			POP_NODUMP();

		return yy::parser::make_TOK_END_OF_RULE(driver.yylloc);
	}
}

<INITIAL,SUB_ID_WS,INCLUDE,INCLUDE_EXISTS,LIST_VAL_MODE,EXTCOND_MODE,LIST_COND_VAL,LIST_COND_PAREN_VAL,LIST_COND_MODE,EXTCONDLIST_MODE,NETWORK_MODE,CHANGE_PROFILE_MODE,RLIMIT_MODE,MOUNT_MODE,DBUS_MODE,SIGNAL_MODE,PTRACE_MODE,UNIX_MODE,ABI_MODE,USERNS_MODE>{
	\r?\n	{
		DUMP_PREPROCESS;
		driver.current_lineno++;
	}
}

<INITIAL,SUB_ID,SUB_ID_WS,SUB_VALUE,LIST_VAL_MODE,EXTCOND_MODE,LIST_COND_VAL,LIST_COND_PAREN_VAL,LIST_COND_MODE,EXTCONDLIST_MODE,ASSIGN_MODE,NETWORK_MODE,CHANGE_PROFILE_MODE,MOUNT_MODE,DBUS_MODE,SIGNAL_MODE,PTRACE_MODE,UNIX_MODE,RLIMIT_MODE,INCLUDE,INCLUDE_EXISTS,ABI_MODE,USERNS_MODE>{
	(.|\n)	{
		DUMP_PREPROCESS;
		/* Something we didn't expect */
		yyerror(_("Lexer found unexpected character: '%s' (0x%x) in state: %s"), yytext, yytext[0], state_names[YY_START].c_str());
	}
}
%%

/* Create a table mapping lexer state number to the name used in the
 * in the code.  This allows for better debug output
 */
std::unordered_map<int, std::string> state_names = {
	STATE_TABLE_ENT(INITIAL),
	STATE_TABLE_ENT(SUB_ID),
	STATE_TABLE_ENT(SUB_ID_WS),
	STATE_TABLE_ENT(SUB_VALUE),
	STATE_TABLE_ENT(EXTCOND_MODE),
	STATE_TABLE_ENT(EXTCONDLIST_MODE),
	STATE_TABLE_ENT(NETWORK_MODE),
	STATE_TABLE_ENT(LIST_VAL_MODE),
	STATE_TABLE_ENT(LIST_COND_MODE),
	STATE_TABLE_ENT(LIST_COND_VAL),
	STATE_TABLE_ENT(LIST_COND_PAREN_VAL),
	STATE_TABLE_ENT(ASSIGN_MODE),
	STATE_TABLE_ENT(RLIMIT_MODE),
	STATE_TABLE_ENT(MOUNT_MODE),
	STATE_TABLE_ENT(DBUS_MODE),
	STATE_TABLE_ENT(SIGNAL_MODE),
	STATE_TABLE_ENT(PTRACE_MODE),
	STATE_TABLE_ENT(UNIX_MODE),
	STATE_TABLE_ENT(CHANGE_PROFILE_MODE),
	STATE_TABLE_ENT(INCLUDE),
	STATE_TABLE_ENT(INCLUDE_EXISTS),
	STATE_TABLE_ENT(ABI_MODE),
	STATE_TABLE_ENT(USERNS_MODE),
};
