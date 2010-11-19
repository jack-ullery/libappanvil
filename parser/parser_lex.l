/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *   Copyright (c) 2010
 *   Canonical, Ltd.
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

#define DUMP_PREPROCESS do { if (preprocess_only) ECHO; } while (0)

#define YY_NO_INPUT

int current_lineno     = 1;
char *current_filename = NULL;

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
					yyerror(_("Could not open '%s' in '%s'"), dirent_path, filename);
				PDEBUG("Opened include \"%s\" in \"%s\"\n", dirent_path, filename);
				update_mru_tstamp(yyin);
				push_include_stack(dirent_path);
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
	fclose(yyin);
	pop_include_stack();
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
			DUMP_PREPROCESS;
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
			DUMP_PREPROCESS;
			yylval.id = processquoted(yytext, yyleng);
			PDEBUG("Found sub name: \"%s\"\n", yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}

	[^\n]	{
			DUMP_PREPROCESS;
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
			DUMP_PREPROCESS;
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
			DUMP_PREPROCESS;
			yylval.id  = processquoted(yytext, yyleng);
			PDEBUG("Found sub name: \"%s\"\n", yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}

	{WS}+	{ DUMP_PREPROCESS; /* Ignoring whitespace */ }
	[^\n]	{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
		}
}

<FLAGS_MODE>{
	{FLAGOPEN_PAREN}	{
			DUMP_PREPROCESS;
			PDEBUG("FLag (\n");
			return TOK_FLAG_OPENPAREN;
			}
	{FLAGCLOSE_PAREN}	{
			DUMP_PREPROCESS;
			PDEBUG("Flag )\n");
			BEGIN(INITIAL);
			return TOK_FLAG_CLOSEPAREN;
			}

	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }

	{FLAGSEP}	{
			DUMP_PREPROCESS;
			PDEBUG("Flag , \n");
			return TOK_FLAG_SEP;
			}

	{EQUALS}	{
			DUMP_PREPROCESS;
			PDEBUG("Flag = \n");
			return TOK_EQUALS;
			}
	{KEYWORD}	{
			DUMP_PREPROCESS;
			yylval.flag_id = strdup(yytext);
			PDEBUG("Found flag: \"%s\"\n", yylval.flag_id);
			return TOK_FLAG_ID;
			}

	[^\n]		{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
			}
}

<ASSIGN_MODE>{
	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }

	{ID}+		{
			DUMP_PREPROCESS;
			yylval.var_val = processunquoted(yytext, yyleng);
			PDEBUG("Found assignment value: \"%s\"\n", yylval.var_val);
			return TOK_VALUE;
			}

	{QUOTED_ID}	{
			DUMP_PREPROCESS;
			yylval.var_val = processquoted(yytext, yyleng);
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
			BEGIN(INITIAL);
			}
}

<NETWORK_MODE>{
	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }

	{ID}+		{
			DUMP_PREPROCESS;
			yylval.id = strdup(yytext);
			return TOK_ID;
			}
	{END_OF_RULE}	{
			DUMP_PREPROCESS;
			BEGIN(INITIAL);
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

	{ID}+	{
			  /* Ugh, this is a gross hack. I used to use
			   * {ID}+ to match all TOK_IDs, but that would
			   * also match TOK_MODE + TOK_END_OF_RULE
			   * without any spaces in between (because it's
			   * a longer match). So now, when I want to
			   * match any random string, I go into a
			   * separate state. */
			DUMP_PREPROCESS;
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
			DUMP_PREPROCESS;
			yylval.id = processquoted(yytext, yyleng);
			PDEBUG("Found change profile quoted name: \"%s\"\n", yylval.id);
			BEGIN(INITIAL);
			return TOK_ID;
		}

	{WS}+			{  DUMP_PREPROCESS; /* Ignoring whitespace */ }
	[^\n]	{
			DUMP_PREPROCESS;
			/* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
		}
}

#include/.*\r?\n	 { /* include */
			PDEBUG("Matched #include\n");
			BEGIN(INCLUDE);
			}

#.*\r?\n		{ /* normal comment */
			DUMP_PREPROCESS;
			PDEBUG("comment(%d): %s\n", current_lineno, yytext);
			current_lineno++;
			BEGIN(INITIAL);
}

{END_OF_RULE}		{ DUMP_PREPROCESS; return TOK_END_OF_RULE; }

{SEPARATOR}		{
			DUMP_PREPROCESS;
			PDEBUG("Matched a separator\n");
			BEGIN(SUB_NAME);
			return TOK_SEP;
			}
{ARROW}			{
			DUMP_PREPROCESS;
			PDEBUG("Matched a arrow\n");
			return TOK_ARROW;
			}
{EQUALS}		{
			DUMP_PREPROCESS;
			PDEBUG("Matched equals for assignment\n");
			BEGIN(ASSIGN_MODE);
			return TOK_EQUALS;
			}
{ADD_ASSIGN}		{
			DUMP_PREPROCESS;
			PDEBUG("Matched additive value assignment\n");
			BEGIN(ASSIGN_MODE);
			return TOK_ADD_ASSIGN;
			}
<RLIMIT_MODE>{
	{WS}+		{ DUMP_PREPROCESS; /* Eat whitespace */ }


	-?{NUMBER}[kKMG]?  {
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
			BEGIN(INITIAL);
			return TOK_END_OF_RULE;
			}

	\\\n		{
			DUMP_PREPROCESS;
			current_lineno++;
			BEGIN(INITIAL);
			}

	\r?\n		{
			DUMP_PREPROCESS;
			current_lineno++;
			BEGIN(INITIAL);
			}
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

{PATHNAME}		{
			DUMP_PREPROCESS;
			yylval.id = processunquoted(yytext, yyleng);
			PDEBUG("Found id: \"%s\"\n", yylval.id);
			return TOK_ID;
			}

{QPATHNAME}		{
			DUMP_PREPROCESS;
			yylval.id = processquoted(yytext, yyleng);
			PDEBUG("Found id: \"%s\"\n", yylval.id);
			return TOK_ID;
			}

{MODES}			{
			DUMP_PREPROCESS;
			yylval.mode = strdup(yytext);
			PDEBUG("Found modes: %s\n", yylval.mode);
			return TOK_MODE;
			}

{HAT}			{
			DUMP_PREPROCESS;
			BEGIN(SUB_NAME2);
			return TOK_HAT;
			}

{COLON}			{
			DUMP_PREPROCESS;
			PDEBUG("Found a colon\n");
			return TOK_COLON;
			}

{FLAGOPEN_PAREN}	{
			DUMP_PREPROCESS;
			PDEBUG("FLag (\n");
			BEGIN(FLAGS_MODE);
			return TOK_FLAG_OPENPAREN;
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

{WS}+			{  DUMP_PREPROCESS; /* Ignoring whitespace */ }

\r?\n			{ DUMP_PREPROCESS; current_lineno++ ; }

[^\n]			{
			DUMP_PREPROCESS;

			  /* Something we didn't expect */
			yyerror(_("Found unexpected character: '%s'"), yytext);
			}

%%
