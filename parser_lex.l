/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *   Copyright (c) 2010 - 2012
 *   Canonical Ltd.
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

/* eliminates need to link with libfl */
%option noyywrap
%option nounput
%option stack

%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#define _(s) gettext(s)

#include "parser.h"
#include "parser_include.h"
#include "parser_yacc.h"
#include "lib.h"

#ifdef PDEBUG
#undef PDEBUG
#endif
/* #define DEBUG */
#ifdef DEBUG
#define PDEBUG(fmt, args...) printf("Lexer (state %d): " fmt, YY_START, ## args)
#else
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

#define DUMP_PREPROCESS do { if (preprocess_only) ECHO; } while (0)

#define YY_NO_INPUT

struct ignored_suffix_t {
	char * text;
	int len;
	int silent;
};

struct ignored_suffix_t ignored_suffixes[] = {
	/* Debian packging files, which are in flux during install
           should be silently ignored. */
	{ ".dpkg-new", 9, 1 },
	{ ".dpkg-old", 9, 1 },
	{ ".dpkg-dist", 10, 1 },
	{ ".dpkg-bak", 9, 1 },
	/* RPM packaging files have traditionally not been silently
           ignored */
	{ ".rpmnew", 7, 0 },
	{ ".rpmsave", 8, 0 },
	/* Backup files should be mentioned */
	{ "~", 1, 0 },
	{ NULL, 0, 0 }
};

static int is_blacklisted(const char *name, const char *path)
{
	int name_len;
	struct ignored_suffix_t *suffix;
	name_len = strlen(name);
	/* skip blacklisted suffixes */
	for (suffix = ignored_suffixes; suffix->text; suffix++) {
		char *found;
		if ( (found = strstr(name, suffix->text)) &&
		     found - name + suffix->len == name_len ) {
			if (!suffix->silent)
				PERROR("Ignoring: '%s'\n", path);
			return 1;
		}
	}

	return 0;
}

struct cb_struct {
	const char *fullpath;
	const char *filename;
};

static int include_dir_cb(__unused DIR *dir, const char *name, struct stat *st,
			  void *data)
{
	struct cb_struct *d = (struct cb_struct *) data;

	char *path;

	/* skip dotfiles silently. */
	if (*name == '.')
		return 0;

	if (asprintf(&path, "%s/%s", d->fullpath, name) < 0)
		yyerror("Out of memory");

	if (is_blacklisted(name, path))
		return 0;

	if (S_ISREG(st->st_mode)) {
		if (!(yyin = fopen(path,"r")))
			yyerror(_("Could not open '%s' in '%s'"), path, d->filename);
		PDEBUG("Opened include \"%s\" in \"%s\"\n", path, d->filename);
		update_mru_tstamp(yyin);
		push_include_stack(path);
		yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));
	}

	free(path);

	return 0;
}

void include_filename(char *filename, int search)
{
	FILE *include_file = NULL;
	struct stat my_stat;
	char *fullpath = NULL;

	if (search) {
		if (preprocess_only)
			fprintf(yyout, "\n\n##included <%s>\n", filename);
		include_file = search_path(filename, &fullpath);
	} else {
		if (preprocess_only)
			fprintf(yyout, "\n\n##included \"%s\"\n", filename);
		fullpath = strdup(filename);
		include_file = fopen(fullpath, "r");
	}

	if (!include_file)
		yyerror(_("Could not open '%s'"),
                        fullpath ? fullpath: filename);

        if (fstat(fileno(include_file), &my_stat))
		yyerror(_("fstat failed for '%s'"), fullpath);

        if (S_ISREG(my_stat.st_mode)) {
		yyin = include_file;
		update_mru_tstamp(include_file);
		PDEBUG("Opened include \"%s\"\n", fullpath);
		push_include_stack(fullpath);
		yypush_buffer_state(yy_create_buffer( yyin, YY_BUF_SIZE ));
        } else if (S_ISDIR(my_stat.st_mode)) {
		struct cb_struct data = { fullpath, filename };
		fclose(include_file);
		include_file = NULL;
		if (dirat_for_each(NULL, fullpath, &data, include_dir_cb)) {
			yyerror(_("Could not process include directory"
				  " '%s' in '%s'"), fullpath, filename);;
		}
	}

	if (fullpath)
		free(fullpath);
}

%}

CARET		"^"
OPEN_BRACE 	\{
CLOSE_BRACE 	\}
SLASH		\/
COLON		:
END_OF_RULE	[,]
RANGE		-
MODE_CHARS 	([RrWwaLlMmkXx])|(([Pp]|[Cc])[Xx])|(([Pp]|[Cc])?([IiUu])[Xx])
MODES		{MODE_CHARS}+
WS		[[:blank:]]
NUMBER		[[:digit:]]+

ID_CHARS	[^ \t\n"!,]
ID 		{ID_CHARS}|(,{ID_CHARS})
IDS		{ID}+
POST_VAR_ID_CHARS	[^ \t\n"!,]{-}[=\+]
POST_VAR_ID 	{POST_VAR_ID_CHARS}|(,{POST_VAR_ID_CHARS})
LIST_VALUE_ID_CHARS	[^ \t\n"!,]{-}[()]
LIST_VALUE_ID	{LIST_VALUE_ID_CHARS}+
ID_CHARS_NOEQ	[^ \t\n"!,]{-}[=]
ID_NOEQ		{ID_CHARS_NOEQ}|(,{ID_CHARS_NOEQ})
IDS_NOEQ	{ID_NOEQ}+
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

PATHNAME	(\/|{SET_VARIABLE}{POST_VAR_ID}){ID}*
QPATHNAME	\"(\/|{SET_VAR_PREFIX})([^\0"]|\\\")*\"

OPEN_PAREN 	\(
CLOSE_PAREN	\)
COMMA		\,
EQUALS		=
ADD_ASSIGN	\+=
ARROW		->
LT_EQUAL	<=

%x SUB_ID
%x SUB_VALUE
%x EXTCOND_MODE
%x NETWORK_MODE
%x LIST_VAL_MODE
%x ASSIGN_MODE
%x RLIMIT_MODE
%x MOUNT_MODE
%x CHANGE_PROFILE_MODE
%x INCLUDE

%%

%{
/* Copied directly into yylex function */
	if (parser_token) {
		int t = parser_token;
		parser_token = 0;
		return t;
	}
%}

<INCLUDE>{
	{WS}+	{ /* Eat whitespace */ }
	\<([^\> \t\n]+)\>	{	/* <filename> */
		char *filename = strdup(yytext);
		filename[strlen(filename) - 1] = '\0';
		include_filename(filename + 1, 1);
		free(filename);
		yy_pop_state();
		}

	\"([^\" \t\n]+)\"	{	/* "filename" */
		char *filename = strdup(yytext);
		filename[strlen(filename) - 1] = '\0';
		include_filename(filename + 1, 0);
		free(filename);
		yy_pop_state();
		}

	[^\<\>\"{WS}]+ {	/* filename */
		include_filename(yytext, 0);
		yy_pop_state();
		}
}

<<EOF>> {
	fclose(yyin);
	pop_include_stack();
	yypop_buffer_state();
	if ( !YY_CURRENT_BUFFER ) yyterminate();
}

<INITIAL,MOUNT_MODE>{
	{VARIABLE_NAME}/{WS}*=	{
				/* we match to the = in the lexer so that
				 * can switch scanner state.  By the time
				 * the parser see the = it may be to late
				 * as bison may have requested the next
				 * token from the scanner
				 */
				DUMP_PREPROCESS;
				PDEBUG("conditional %s=\n", yytext);
				yylval.id = processid(yytext, yyleng);
				yy_push_state(EXTCOND_MODE);
				return TOK_CONDID;
			}
	{VARIABLE_NAME}/{WS}+in{WS}*\(	{
				/* we match to 'in' in the lexer so that
				 * we can switch scanner state.  By the time
				 * the parser see the 'in' it may be to late
				 * as bison may have requested the next
				 * token from the scanner
				 */
				DUMP_PREPROCESS;
				PDEBUG("conditional %s=\n", yytext);
				yylval.id = processid(yytext, yyleng);
				yy_push_state(EXTCOND_MODE);
				return TOK_CONDID;
			}
}

<SUB_ID>{
	({IDS}|{QUOTED_ID})	{
			  /* Ugh, this is a gross hack. I used to use
			   * {IDS} to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			DUMP_PREPROCESS;
			yylval.id =  processid(yytext, yyleng);
			PDEBUG("Found sub name: \"%s\"\n",  yylval.id);
			yy_pop_state();
			return TOK_ID;
		}

	[^\n]	{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
		}
}

<SUB_VALUE>{
	({IDS}|{QUOTED_ID})	{
			  /* Ugh, this is a gross hack. I used to use
			   * {IDS} to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			DUMP_PREPROCESS;
			yylval.id =  processid(yytext, yyleng);
			PDEBUG("Found sub value: \"%s\"\n",  yylval.id);
			yy_pop_state();
			return TOK_VALUE;
		}

	[^\n]	{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
		}
}

<LIST_VAL_MODE>{
	{CLOSE_PAREN}	{
			DUMP_PREPROCESS;
			PDEBUG("listval: )\n");
			yy_pop_state();
			return TOK_CLOSEPAREN;
			}

	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }

	{COMMA}	{
			DUMP_PREPROCESS;
			PDEBUG("listval: , \n");
			/* East comma, its an optional separator */
			}

	({LIST_VALUE_ID}|{QUOTED_ID})	{
			DUMP_PREPROCESS;
			yylval.id = processid(yytext, yyleng);
			PDEBUG("listval: \"%s\"\n", yylval.id);
			return TOK_VALUE;
			}

	[^\n]		{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
			}
}

<EXTCOND_MODE>{
	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }

	{EQUALS}{WS}*/[^(\n]{-}{WS}	{
			DUMP_PREPROCESS;
			BEGIN(SUB_VALUE);
			return TOK_EQUALS;
		}

	{EQUALS}	{
			DUMP_PREPROCESS;
			return TOK_EQUALS;
		}

	{OPEN_PAREN}	{
			DUMP_PREPROCESS;
			PDEBUG("extcond listv\n");
			/* Don't push state here as this is a transition
			 * start condition and we want to return to the start
			 * condition that invoked <EXTCOND_MODE> when
			 * LIST_VAL_ID is done
			 */
			BEGIN(LIST_VAL_MODE);
			return TOK_OPENPAREN;
		}

	in	{
			DUMP_PREPROCESS;
			return TOK_IN;
		}

	[^\n]	{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s' %d"), yytext, *yytext);
		}

}

<ASSIGN_MODE>{
	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }

	({IDS}|{QUOTED_ID})		{
			DUMP_PREPROCESS;
			yylval.var_val = processid(yytext, yyleng);
			PDEBUG("Found assignment value: \"%s\"\n", yylval.var_val);
			return TOK_VALUE;
			}

	{END_OF_RULE}	{
			DUMP_PREPROCESS;
			yylval.id = strdup(yytext);
			yyerror(_("Variable declarations do not accept trailing commas"));
			}

	\\\n		{ DUMP_PREPROCESS; current_lineno++ ; }

	\r?\n		{
			DUMP_PREPROCESS;
			current_lineno++;
			yy_pop_state();
			}
	[^\n]		{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
			}
}

<NETWORK_MODE>{
	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }

	{IDS}		{
			DUMP_PREPROCESS;
			yylval.id = strdup(yytext);
			return TOK_ID;
			}
	{END_OF_RULE}	{
			DUMP_PREPROCESS;
			yy_pop_state();
			return TOK_END_OF_RULE;
		}
	[^\n]		{
			DUMP_PREPROCESS;
			  /* Something we didn't expect */
			yylval.id = strdup(yytext);
			yyerror(_("(network_mode) Found unexpected character: '%s'"), yylval.id);
			}

	\r?\n		{
			DUMP_PREPROCESS;
			current_lineno++;
			}
}

<CHANGE_PROFILE_MODE>{
	{ARROW}	        {
			DUMP_PREPROCESS;
			PDEBUG("Matched a change profile arrow\n");
			return TOK_ARROW;
			}

	({IDS}|{QUOTED_ID})	{
			  /* Ugh, this is a gross hack. I used to use
			   * {IDS} to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			DUMP_PREPROCESS;
			yylval.id = processid(yytext, yyleng);
			PDEBUG("Found change profile name: \"%s\"\n", yylval.id);
			yy_pop_state();
			return TOK_ID;
		}

	{WS}+			{  DUMP_PREPROCESS; /* Ignoring whitespace */ }
	[^\n]	{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
		}
}

<RLIMIT_MODE>{
	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }


	-?{NUMBER}[[:alpha:]]*  {
			DUMP_PREPROCESS;
		        yylval.var_val = strdup(yytext);
		        return TOK_VALUE;
			}

	{KEYWORD}	{
			DUMP_PREPROCESS;
		        yylval.id = strdup(yytext);
			if (strcmp(yytext, "infinity") == 0)
				return TOK_VALUE;
			return TOK_ID;
			}

	{LT_EQUAL}	{ DUMP_PREPROCESS; return TOK_LE; }

	{END_OF_RULE}	{
			DUMP_PREPROCESS;
			yy_pop_state();
			return TOK_END_OF_RULE;
			}

	\\\n		{
			DUMP_PREPROCESS;
			current_lineno++;
			yy_pop_state();
			}

	\r?\n		{
			DUMP_PREPROCESS;
			current_lineno++;
			yy_pop_state();
			}
}

<MOUNT_MODE>{
	{WS}+		{  DUMP_PREPROCESS; /* Ignoring whitespace */ }

	{ARROW}		{
			DUMP_PREPROCESS;
			PDEBUG("Matched arrow\n");
			return TOK_ARROW;
			}

	({IDS_NOEQ}|{PATHNAME}|{QUOTED_ID})	{
			DUMP_PREPROCESS;
			yylval.id = processid(yytext, yyleng);
			PDEBUG("Found ID: \"%s\"\n", yylval.id);
			return TOK_ID;
			}

	{END_OF_RULE}	{
			DUMP_PREPROCESS;
			yy_pop_state();
			return TOK_END_OF_RULE;
			}

	[^\n]		{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
			}

	\r?\n		{
			DUMP_PREPROCESS;
			current_lineno++;
			yy_pop_state();
			}
}

#include/.*\r?\n	 { /* include */
			PDEBUG("Matched #include\n");
			yy_push_state(INCLUDE);
			}

#.*\r?\n		{ /* normal comment */
			DUMP_PREPROCESS;
			PDEBUG("comment(%d): %s\n", current_lineno, yytext);
			current_lineno++;
			}

{END_OF_RULE}		{ DUMP_PREPROCESS; return TOK_END_OF_RULE; }

{CARET}			{
			DUMP_PREPROCESS;
			PDEBUG("Matched hat ^\n");
			yy_push_state(SUB_ID);
			return TOK_CARET;
			}
{ARROW}			{
			DUMP_PREPROCESS;
			PDEBUG("Matched a arrow\n");
			return TOK_ARROW;
			}
{EQUALS}		{
			DUMP_PREPROCESS;
			PDEBUG("Matched equals for assignment\n");
			yy_push_state(ASSIGN_MODE);
			return TOK_EQUALS;
			}
{ADD_ASSIGN}		{
			DUMP_PREPROCESS;
			PDEBUG("Matched additive value assignment\n");
			yy_push_state(ASSIGN_MODE);
			return TOK_ADD_ASSIGN;
			}
{SET_VARIABLE}		{
			DUMP_PREPROCESS;
			yylval.set_var = strdup(yytext);
			PDEBUG("Found set variable %s\n", yylval.set_var);
			return TOK_SET_VAR;
			}

{BOOL_VARIABLE}		{
			DUMP_PREPROCESS;
			yylval.bool_var = strdup(yytext);
			PDEBUG("Found boolean variable %s\n", yylval.bool_var);
			return TOK_BOOL_VAR;
			}

{OPEN_BRACE}		{
			DUMP_PREPROCESS;
			PDEBUG("Open Brace\n");
			return TOK_OPEN;
			}
{CLOSE_BRACE}		{
			DUMP_PREPROCESS;
			PDEBUG("Close Brace\n");
			return TOK_CLOSE;
			}

({PATHNAME}|{QPATHNAME})		{
			DUMP_PREPROCESS;
			yylval.id = processid(yytext, yyleng);
			PDEBUG("Found id: \"%s\"\n", yylval.id);
			return TOK_ID;
			}

({MODES})/([[:space:],])	{
			DUMP_PREPROCESS;
			yylval.mode = strdup(yytext);
			PDEBUG("Found modes: %s\n", yylval.mode);
			return TOK_MODE;
			}

{HAT}			{
			DUMP_PREPROCESS;
			yy_push_state(SUB_ID);
			return TOK_HAT;
			}

{PROFILE}		{
			DUMP_PREPROCESS;
			yy_push_state(SUB_ID);
			return TOK_PROFILE;
			}

{COLON}			{
			DUMP_PREPROCESS;
			PDEBUG("Found a colon\n");
			return TOK_COLON;
			}

{OPEN_PAREN}	{
			DUMP_PREPROCESS;
			PDEBUG("listval (\n");
			yy_push_state(LIST_VAL_MODE);
			return TOK_OPENPAREN;
			}

{VARIABLE_NAME}		{
			DUMP_PREPROCESS;
			int token = get_keyword_token(yytext);

			/* special cases */
			switch (token) {
			case -1:
				/* no token found */
				yylval.id = processunquoted(yytext, yyleng);
				PDEBUG("Found (var) id: \"%s\"\n", yylval.id);
				return TOK_ID;
				break;
			case TOK_RLIMIT:
				yy_push_state(RLIMIT_MODE);
				break;
			case TOK_NETWORK:
				yy_push_state(NETWORK_MODE);
				break;
			case TOK_CHANGE_PROFILE:
				yy_push_state(CHANGE_PROFILE_MODE);
				break;
			case TOK_MOUNT:
			case TOK_REMOUNT:
			case TOK_UMOUNT:
				PDEBUG("Entering mount\n");
				yy_push_state(MOUNT_MODE);
				break;
			default: /* nothing */
				break;
			}
			return token;
			}

{WS}+			{  DUMP_PREPROCESS; /* Ignoring whitespace */ }

\r?\n			{ DUMP_PREPROCESS; current_lineno++ ; }

[^\n]			{
			DUMP_PREPROCESS;

			  /* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
			}

%%
