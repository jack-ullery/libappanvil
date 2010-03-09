/* $Id$ */

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

/* Definitions section */
/* %option main */

/* eliminates need to link with libfl */
%option noyywrap

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

#ifdef PDEBUG
#undef PDEBUG
#endif
/* #define DEBUG */
#ifdef DEBUG
#define PDEBUG(fmt, args...) printf("Lexer: " fmt, ## args)
#else
#define PDEBUG(fmt, args...)	/* Do nothing */
#endif
#define NPDEBUG(fmt, args...)	/* Do nothing */

int current_lineno = 1;

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

void include_filename(char *filename, int search)
{
	FILE *include_file = NULL;
	struct stat my_stat;
	char *fullpath = NULL;

	if (search) {
		include_file = search_path(filename, &fullpath);
	} else {
		fullpath = strdup(filename);
		include_file = fopen(fullpath, "r");
	}

	if (!include_file)
		yyerror(_("Could not open '%s'"), fullpath);

        if (fstat(fileno(include_file), &my_stat))
		yyerror(_("fstat failed for '%s'"), fullpath);

        if (S_ISREG(my_stat.st_mode)) {
		yyin = include_file;
		PDEBUG("Opened include \"%s\"\n", fullpath);
		yypush_buffer_state(yy_create_buffer( yyin, YY_BUF_SIZE ));
        }

        if (S_ISDIR(my_stat.st_mode)) {
                DIR *dir = NULL;
		char *dirent_path = NULL;
                struct dirent *dirent;

		PDEBUG("Opened include directory \"%s\"\n", fullpath);
                if (!(dir = opendir(fullpath)))
			yyerror(_("opendir failed '%s'"), fullpath);
		fclose(include_file);
		include_file = NULL;

                while ((dirent = readdir(dir)) != NULL) {
			int name_len;
			struct ignored_suffix_t *suffix;
                        /* skip dotfiles silently. */
                        if (dirent->d_name[0] == '.')
                                continue;

			if (dirent_path)
				free(dirent_path);
                        if (asprintf(&dirent_path, "%s/%s", fullpath, dirent->d_name) < 0)
				yyerror("Out of memory");

			name_len = strlen(dirent->d_name);
			/* skip blacklisted suffixes */
			for (suffix = ignored_suffixes; suffix->text; suffix++) {
				char *found;
				if ( (found = strstr(dirent->d_name, suffix->text)) &&
                                     found - dirent->d_name + suffix->len == name_len ) {
					name_len = 0;
					if (!suffix->silent)
						PERROR("Ignoring: '%s'\n", dirent_path);
					break;
				}
			}
			if (!name_len) continue;

                        if (stat(dirent_path, &my_stat))
				yyerror(_("stat failed for '%s'"), dirent_path);
			if (S_ISREG(my_stat.st_mode)) {
				if (!(yyin = fopen(dirent_path,"r")))
					yyerror(_("Could not open '%s'"), filename);
				PDEBUG("Opened include \"%s\"\n", filename);
				yypush_buffer_state(yy_create_buffer(yyin, YY_BUF_SIZE));
			}
		}
		if (dirent_path)
			free(dirent_path);
		closedir(dir);
	}

	if (fullpath)
		free(fullpath);
}

%}

UP		"^"
OPEN_BRACE 	\{
CLOSE_BRACE 	\}
SLASH		\/
COLON		:
END_OF_RULE	[,]
SEPARATOR 	{UP}
RANGE		-
MODE_CHARS 	([RrWwaLlMmkXx])|(([Pp]|[Cc])[Xx])|(([Pp]|[Cc])?([IiUu])[Xx])
MODES		{MODE_CHARS}+
WS		[[:blank:]]
NUMBER		[[:digit:]]+
ID 		[^ \t\n"!,]|(,[^ \t\n"!])
POST_VAR_ID 	[^ =\+\t\n"!,]|(,[^ =\+\t\n"!])
IP		{NUMBER}\.{NUMBER}\.{NUMBER}\.{NUMBER}
ALLOWED_QUOTED_ID 	[^\0"]|\\\"
QUOTED_ID	\"{ALLOWED_QUOTED_ID}*\"

HAT		hat[ \t]+
KEYWORD         [[:alpha:]_]+
VARIABLE_NAME	[[:alpha:]][[:alnum:]_]*
SET_VAR_PREFIX  @
SET_VARIABLE	{SET_VAR_PREFIX}(\{{VARIABLE_NAME}\}|{VARIABLE_NAME})
BOOL_VARIABLE	$(\{{VARIABLE_NAME}\}|{VARIABLE_NAME})

PATHNAME	(\/|{SET_VARIABLE}{POST_VAR_ID}){ID}*
QPATHNAME	\"(\/|{SET_VAR_PREFIX})([^\0"]|\\\")*\"

FLAGOPEN_PAREN 	\(
FLAGCLOSE_PAREN	\)
FLAGSEP		\,
EQUALS		=
ADD_ASSIGN	\+=
ARROW		->
LT_EQUAL	<=

%x SUB_NAME
%x SUB_NAME2
%x NETWORK_MODE
%x FLAGS_MODE
%x ASSIGN_MODE
%x RLIMIT_MODE
%x CHANGE_PROFILE_MODE
%x INCLUDE

%%

<INCLUDE>{
	{WS}+	{ /* Eat whitespace */ }
	\<([^\> \t\n]+)\>	{	/* <filename> */
		char *filename = strdup(yytext);
		filename[strlen(filename) - 1] = '\0';
		include_filename(filename + 1, 1);
		free(filename);
		BEGIN(INITIAL);
		}

	\"([^\" \t\n]+)\"	{	/* "filename" */
		char *filename = strdup(yytext);
		filename[strlen(filename) - 1] = '\0';
		include_filename(filename + 1, 0);
		free(filename);
		BEGIN(INITIAL);
		}

	[^\<\>\"{WS}]+ {	/* filename */
		include_filename(yytext, 0);
		BEGIN(INITIAL);
		}
}

<<EOF>> {
	yypop_buffer_state();
	if ( !YY_CURRENT_BUFFER ) yyterminate();
}

<SUB_NAME>{
	{ID}+	{
			  /* Ugh, this is a gross hack. I used to use
			   * {ID}+ to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			yylval.id =  processunquoted(yytext, yyleng);
			PDEBUG("Found sub name: \"%s\"\n",  yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}
	{QUOTED_ID}	{
			  /* Ugh, this is a gross hack. I used to use
			   * {ID}+ to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			yylval.id = processquoted(yytext, yyleng);
			PDEBUG("Found sub name: \"%s\"\n", yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}

	[^\n]	{
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
		}
}

<SUB_NAME2>{
	{ID}+	{
			  /* Ugh, this is a gross hack. I used to use
			   * {ID}+ to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			yylval.id = processunquoted(yytext, yyleng);
			PDEBUG("Found sub name: \"%s\"\n", yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}
	{QUOTED_ID}	{
			  /* Ugh, this is a gross hack. I used to use
			   * {ID}+ to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			yylval.id  = processquoted(yytext, yyleng);
			PDEBUG("Found sub name: \"%s\"\n", yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}

	{WS}+			{  /* Ignoring whitespace */ }
	[^\n]	{
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
		}
}

<FLAGS_MODE>{
	{FLAGOPEN_PAREN}	{
			PDEBUG("FLag (\n");
			return TOK_FLAG_OPENPAREN;
			}
	{FLAGCLOSE_PAREN}	{
			PDEBUG("Flag )\n");
			BEGIN(INITIAL);
			return TOK_FLAG_CLOSEPAREN;
			}

	{WS}+		{ /* Eat whitespace */ }

	{FLAGSEP}	{
			PDEBUG("Flag , \n");
			return TOK_FLAG_SEP;
			}

	{EQUALS}	{
			PDEBUG("Flag = \n");
			return TOK_EQUALS;
			}
	{KEYWORD}	{
			yylval.flag_id = strdup(yytext);
			PDEBUG("Found flag: \"%s\"\n", yylval.flag_id);
			return TOK_FLAG_ID;
			}

	[^\n]		{
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
			}
}

<ASSIGN_MODE>{
	{WS}+		{ /* Eat whitespace */ }

	{ID}+		{
			yylval.var_val = processunquoted(yytext, yyleng);
			PDEBUG("Found assignment value: \"%s\"\n", yylval.var_val);
			return TOK_VALUE;
			}

	{QUOTED_ID}	{
			yylval.var_val = processquoted(yytext, yyleng);
			PDEBUG("Found assignment value: \"%s\"\n", yylval.var_val);
			return TOK_VALUE;
			}

	\\\n		{ current_lineno++ ; }

	\r?\n		{
			current_lineno++;
			BEGIN(INITIAL);
			}
}

<NETWORK_MODE>{
	{WS}+		{ /* Eat whitespace */ }

	{ID}+		{
			yylval.id = strdup(yytext);
			return TOK_ID;
			}
	{END_OF_RULE}	{
			BEGIN(INITIAL);
			return TOK_END_OF_RULE;
		}
	[^\n]		{
			  /* Something we didn't expect */
			yylval.id = strdup(yytext);
			yyerror(_("(network_mode) Found unexpected character: '%s'"), yylval.id);
			}

	\r?\n		{
			current_lineno++;
			}
}

<CHANGE_PROFILE_MODE>{
	{ARROW}	        {
			PDEBUG("Matched a change profile arrow\n");
			return TOK_ARROW;
			}

	{ID}+	{
			  /* Ugh, this is a gross hack. I used to use
			   * {ID}+ to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			yylval.id = processunquoted(yytext, yyleng);
			PDEBUG("Found change profile name: \"%s\"\n", yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}
	{QUOTED_ID}	{
			  /* Ugh, this is a gross hack. I used to use
			   * {ID}+ to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			yylval.id = processquoted(yytext, yyleng);
			PDEBUG("Found change profile quoted name: \"%s\"\n", yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}

	{WS}+			{  /* Ignoring whitespace */ }
	[^\n]	{
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
		}
}

#include/.*\r?\n	 { /* include */
			PDEBUG("Matched #include\n");
			current_lineno++;
			BEGIN(INCLUDE);
			}

#.*\r?\n		{ /* normal comment */
			PDEBUG("comment(%d): %s\n", current_lineno, yytext);
			current_lineno++;
			BEGIN(INITIAL);
}

{END_OF_RULE}		{ return TOK_END_OF_RULE; }

{SEPARATOR}		{
			PDEBUG("Matched a separator\n");
			BEGIN(SUB_NAME);
			return TOK_SEP;
			}
{ARROW}			{
			PDEBUG("Matched a arrow\n");
			return TOK_ARROW;
			}
{EQUALS}		{
			PDEBUG("Matched equals for assignment\n");
			BEGIN(ASSIGN_MODE);
			return TOK_EQUALS;
			}
{ADD_ASSIGN}		{
			PDEBUG("Matched additive value assignment\n");
			BEGIN(ASSIGN_MODE);
			return TOK_ADD_ASSIGN;
			}
<RLIMIT_MODE>{
	{WS}+		{ /* Eat whitespace */ }


	-?{NUMBER}[kKMG]?  {
		        yylval.var_val = strdup(yytext);
		        return TOK_VALUE;
			}

	{KEYWORD}	{
		        yylval.id = strdup(yytext);
			if (strcmp(yytext, "infinity") == 0)
				return TOK_VALUE;
			return TOK_ID;
			}

	{LT_EQUAL}	{ return TOK_LE; }

	{END_OF_RULE}	{
			BEGIN(INITIAL);
			return TOK_END_OF_RULE;
			}

	\\\n		{
			current_lineno++;
			BEGIN(INITIAL);
			}

	\r?\n		{
			current_lineno++;
			BEGIN(INITIAL);
			}
}

{SET_VARIABLE}		{
			yylval.set_var = strdup(yytext);
			PDEBUG("Found set variable %s\n", yylval.set_var);
			return TOK_SET_VAR;
			}

{BOOL_VARIABLE}		{
			yylval.bool_var = strdup(yytext);
			PDEBUG("Found boolean variable %s\n", yylval.bool_var);
			return TOK_BOOL_VAR;
			}

{OPEN_BRACE}		{
			PDEBUG("Open Brace\n");
			return TOK_OPEN;
			}
{CLOSE_BRACE}		{
			PDEBUG("Close Brace\n");
			return TOK_CLOSE;
			}

{PATHNAME}		{
			yylval.id = processunquoted(yytext, yyleng);
			PDEBUG("Found id: \"%s\"\n", yylval.id);
			return TOK_ID;
			}

{QPATHNAME}		{
			yylval.id = processquoted(yytext, yyleng);
			PDEBUG("Found id: \"%s\"\n", yylval.id);
			return TOK_ID;
			}

{MODES}			{
			yylval.mode = strdup(yytext);
			PDEBUG("Found modes: %s\n", yylval.mode);
			return TOK_MODE;
			}

{HAT}			{
			BEGIN(SUB_NAME2);
			return TOK_HAT;
			}

{COLON}			{
			PDEBUG("Found a colon\n");
			return TOK_COLON;
			}

{FLAGOPEN_PAREN}	{
			PDEBUG("FLag (\n");
			BEGIN(FLAGS_MODE);
			return TOK_FLAG_OPENPAREN;
			}

{VARIABLE_NAME}		{
			int token = get_keyword_token(yytext);

			/* special cases */
			switch (token) {
			case -1:
				/* no token found */
				yylval.id = processunquoted(yytext, yyleng);
				PDEBUG("Found (var) id: \"%s\"\n", yylval.id);
				return TOK_ID;
				break;
			case TOK_PROFILE:
				BEGIN(SUB_NAME2);
				break;
			case TOK_FLAGS:
				BEGIN(FLAGS_MODE);
				break;
			case TOK_RLIMIT:
				BEGIN(RLIMIT_MODE);
				break;
			case TOK_NETWORK:
				BEGIN(NETWORK_MODE);
				break;
			case TOK_CHANGE_PROFILE:
				BEGIN(CHANGE_PROFILE_MODE);
				break;
			default: /* nothing */
				break;
			}
			return token;
			}

{WS}+			{  /* Ignoring whitespace */ }

\r?\n			{ current_lineno++ ; }

[^\n]			{
			  /* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
			}

%%
