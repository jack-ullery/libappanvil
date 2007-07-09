/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     TOK_DIGITS = 258,
     TOK_QUOTED_STRING = 259,
     TOK_PATH = 260,
     TOK_ID = 261,
     TOK_NULL_COMPLAIN = 262,
     TOK_MODE = 263,
     TOK_SINGLE_QUOTED_STRING = 264,
     TOK_AUDIT_DIGITS = 265,
     TOK_EQUALS = 266,
     TOK_COLON = 267,
     TOK_OPEN_PAREN = 268,
     TOK_CLOSE_PAREN = 269,
     TOK_PERIOD = 270,
     TOK_TYPE_REJECT = 271,
     TOK_TYPE_AUDIT = 272,
     TOK_TYPE_COMPLAIN = 273,
     TOK_TYPE_HINT = 274,
     TOK_TYPE_STATUS = 275,
     TOK_TYPE_ERROR = 276,
     TOK_OLD_TYPE_APPARMOR = 277,
     TOK_OLD_APPARMOR_REJECT = 278,
     TOK_OLD_APPARMOR_PERMIT = 279,
     TOK_OLD_APPARMOR_LOGPROF_HINT = 280,
     TOK_OLD_UNKNOWN_HAT = 281,
     TOK_OLD_ACTIVE = 282,
     TOK_OLD_UNKNOWN_PROFILE = 283,
     TOK_OLD_MISSING_PROFILE = 284,
     TOK_OLD_ACCESS = 285,
     TOK_OLD_TO = 286,
     TOK_OLD_PIPE = 287,
     TOK_OLD_EXTENDED = 288,
     TOK_OLD_ATTRIBUTE = 289,
     TOK_OLD_ON = 290,
     TOK_OLD_MKDIR = 291,
     TOK_OLD_RMDIR = 292,
     TOK_OLD_XATTR = 293,
     TOK_OLD_CHANGE = 294,
     TOK_OLD_CAPABILITY = 295,
     TOK_OLD_FORK = 296,
     TOK_OLD_CHILD = 297,
     TOK_KEY_TYPE = 298,
     TOK_KEY_MSG = 299,
     TOK_KEY_OPERATION = 300,
     TOK_KEY_NAME = 301,
     TOK_KEY_NAME2 = 302,
     TOK_KEY_DENIED_MASK = 303,
     TOK_KEY_REQUESTED_MASK = 304,
     TOK_KEY_ATTRIBUTE = 305,
     TOK_KEY_TASK = 306,
     TOK_KEY_PARENT = 307,
     TOK_KEY_MAGIC_TOKEN = 308,
     TOK_KEY_INFO = 309,
     TOK_KEY_PID = 310,
     TOK_KEY_PROFILE = 311,
     TOK_AUDIT = 312,
     TOK_KEY_IMAGE = 313
   };
#endif
/* Tokens.  */
#define TOK_DIGITS 258
#define TOK_QUOTED_STRING 259
#define TOK_PATH 260
#define TOK_ID 261
#define TOK_NULL_COMPLAIN 262
#define TOK_MODE 263
#define TOK_SINGLE_QUOTED_STRING 264
#define TOK_AUDIT_DIGITS 265
#define TOK_EQUALS 266
#define TOK_COLON 267
#define TOK_OPEN_PAREN 268
#define TOK_CLOSE_PAREN 269
#define TOK_PERIOD 270
#define TOK_TYPE_REJECT 271
#define TOK_TYPE_AUDIT 272
#define TOK_TYPE_COMPLAIN 273
#define TOK_TYPE_HINT 274
#define TOK_TYPE_STATUS 275
#define TOK_TYPE_ERROR 276
#define TOK_OLD_TYPE_APPARMOR 277
#define TOK_OLD_APPARMOR_REJECT 278
#define TOK_OLD_APPARMOR_PERMIT 279
#define TOK_OLD_APPARMOR_LOGPROF_HINT 280
#define TOK_OLD_UNKNOWN_HAT 281
#define TOK_OLD_ACTIVE 282
#define TOK_OLD_UNKNOWN_PROFILE 283
#define TOK_OLD_MISSING_PROFILE 284
#define TOK_OLD_ACCESS 285
#define TOK_OLD_TO 286
#define TOK_OLD_PIPE 287
#define TOK_OLD_EXTENDED 288
#define TOK_OLD_ATTRIBUTE 289
#define TOK_OLD_ON 290
#define TOK_OLD_MKDIR 291
#define TOK_OLD_RMDIR 292
#define TOK_OLD_XATTR 293
#define TOK_OLD_CHANGE 294
#define TOK_OLD_CAPABILITY 295
#define TOK_OLD_FORK 296
#define TOK_OLD_CHILD 297
#define TOK_KEY_TYPE 298
#define TOK_KEY_MSG 299
#define TOK_KEY_OPERATION 300
#define TOK_KEY_NAME 301
#define TOK_KEY_NAME2 302
#define TOK_KEY_DENIED_MASK 303
#define TOK_KEY_REQUESTED_MASK 304
#define TOK_KEY_ATTRIBUTE 305
#define TOK_KEY_TASK 306
#define TOK_KEY_PARENT 307
#define TOK_KEY_MAGIC_TOKEN 308
#define TOK_KEY_INFO 309
#define TOK_KEY_PID 310
#define TOK_KEY_PROFILE 311
#define TOK_AUDIT 312
#define TOK_KEY_IMAGE 313




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 42 "grammar.y"
{
	char	*t_str;
	long	t_long;
}
/* Line 1529 of yacc.c.  */
#line 170 "grammar.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



