/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Using locations.  */
#define YYLSP_NEEDED 0

/* Substitute the variable and function names.  */
#define yyparse libaalogparse_parse
#define yylex   libaalogparse_lex
#define yyerror libaalogparse_error
#define yylval  libaalogparse_lval
#define yychar  libaalogparse_char
#define yydebug libaalogparse_debug
#define yynerrs libaalogparse_nerrs


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




/* Copy the first part of user declarations.  */
#line 19 "grammar.y"


#define YYDEBUG 0
#include <string.h>
#include "aalogparse.h"
#include "parser.h"
#include "grammar.h"
#include "scanner.h"

aa_log_record *ret_record;
void libaalogparse_error(void *scanner, char const *s)
{
	printf("Error: %s\n", s);
}


/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 42 "grammar.y"
{
	char	*t_str;
	long	t_long;
}
/* Line 193 of yacc.c.  */
#line 241 "grammar.c"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 254 "grammar.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int i)
#else
static int
YYID (i)
    int i;
#endif
{
  return i;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss;
  YYSTYPE yyvs;
  };

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack, Stack, yysize);				\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  4
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   223

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  59
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  18
/* YYNRULES -- Number of rules.  */
#define YYNRULES  50
/* YYNRULES -- Number of states.  */
#define YYNSTATES  199

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   313

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint8 yyprhs[] =
{
       0,     0,     3,     7,     9,    11,    15,    19,    23,    27,
      31,    35,    39,    42,    45,    47,    49,    63,    77,    92,
     110,   125,   127,   129,   132,   135,   138,   149,   151,   156,
     161,   164,   173,   174,   181,   183,   185,   197,   199,   202,
     206,   210,   214,   218,   222,   226,   230,   234,   238,   242,
     246
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      60,     0,    -1,    43,    11,    61,    -1,    62,    -1,    63,
      -1,    22,    74,    64,    -1,    16,    74,    75,    -1,    17,
      74,    75,    -1,    18,    74,    75,    -1,    19,    74,    75,
      -1,    20,    74,    75,    -1,    21,    74,    75,    -1,    65,
      66,    -1,    25,    69,    -1,    23,    -1,    24,    -1,     8,
      30,    68,    13,     6,    13,     6,    14,    56,    73,    27,
      73,    14,    -1,    67,    35,     5,    13,     6,    13,     6,
      14,    56,    73,    27,    73,    14,    -1,    38,     6,    35,
       5,    13,     6,    13,     6,    14,    56,    73,    27,    73,
      14,    -1,    50,    13,     6,    14,    39,    31,     5,    13,
       6,    13,     6,    14,    56,    73,    27,    73,    14,    -1,
      30,    31,    40,     9,    13,     6,    13,     6,    14,    56,
      73,    27,    73,    14,    -1,    36,    -1,    37,    -1,    31,
       5,    -1,    31,    32,    -1,    33,    50,    -1,    70,    55,
      11,     3,    56,    11,    73,    27,    11,    73,    -1,    71,
      -1,    28,    58,    11,     6,    -1,    29,    58,    11,     6,
      -1,    26,     6,    -1,    41,    55,    11,     3,    42,    11,
       3,    72,    -1,    -1,    56,    11,    73,    27,    11,    73,
      -1,     5,    -1,     7,    -1,    44,    11,    57,    13,    10,
      15,    10,    12,    10,    14,    12,    -1,    76,    -1,    75,
      76,    -1,    45,    11,     4,    -1,    46,    11,     4,    -1,
      47,    11,     4,    -1,    48,    11,     4,    -1,    49,    11,
       4,    -1,    50,    11,     4,    -1,    51,    11,     4,    -1,
      52,    11,     4,    -1,    53,    11,     4,    -1,    54,    11,
       4,    -1,    55,    11,     4,    -1,    56,    11,     4,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   104,   104,   106,   107,   110,   113,   114,   115,   116,
     117,   118,   122,   123,   127,   128,   132,   148,   163,   181,
     200,   219,   220,   224,   229,   233,   239,   248,   252,   259,
     266,   277,   286,   288,   298,   303,   309,   328,   329,   332,
     334,   336,   338,   340,   342,   344,   346,   348,   350,   352,
     354
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "TOK_DIGITS", "TOK_QUOTED_STRING",
  "TOK_PATH", "TOK_ID", "TOK_NULL_COMPLAIN", "TOK_MODE",
  "TOK_SINGLE_QUOTED_STRING", "TOK_AUDIT_DIGITS", "TOK_EQUALS",
  "TOK_COLON", "TOK_OPEN_PAREN", "TOK_CLOSE_PAREN", "TOK_PERIOD",
  "TOK_TYPE_REJECT", "TOK_TYPE_AUDIT", "TOK_TYPE_COMPLAIN",
  "TOK_TYPE_HINT", "TOK_TYPE_STATUS", "TOK_TYPE_ERROR",
  "TOK_OLD_TYPE_APPARMOR", "TOK_OLD_APPARMOR_REJECT",
  "TOK_OLD_APPARMOR_PERMIT", "TOK_OLD_APPARMOR_LOGPROF_HINT",
  "TOK_OLD_UNKNOWN_HAT", "TOK_OLD_ACTIVE", "TOK_OLD_UNKNOWN_PROFILE",
  "TOK_OLD_MISSING_PROFILE", "TOK_OLD_ACCESS", "TOK_OLD_TO",
  "TOK_OLD_PIPE", "TOK_OLD_EXTENDED", "TOK_OLD_ATTRIBUTE", "TOK_OLD_ON",
  "TOK_OLD_MKDIR", "TOK_OLD_RMDIR", "TOK_OLD_XATTR", "TOK_OLD_CHANGE",
  "TOK_OLD_CAPABILITY", "TOK_OLD_FORK", "TOK_OLD_CHILD", "TOK_KEY_TYPE",
  "TOK_KEY_MSG", "TOK_KEY_OPERATION", "TOK_KEY_NAME", "TOK_KEY_NAME2",
  "TOK_KEY_DENIED_MASK", "TOK_KEY_REQUESTED_MASK", "TOK_KEY_ATTRIBUTE",
  "TOK_KEY_TASK", "TOK_KEY_PARENT", "TOK_KEY_MAGIC_TOKEN", "TOK_KEY_INFO",
  "TOK_KEY_PID", "TOK_KEY_PROFILE", "TOK_AUDIT", "TOK_KEY_IMAGE",
  "$accept", "type", "type_syntax", "old_syntax", "new_syntax", "old_msg",
  "old_permit_reject_syntax", "old_permit_reject_syntax2",
  "mkdir_or_rmdir", "old_permit_reject_path_pipe_extended",
  "old_logprof_syntax", "old_logprof_syntax2", "old_logprof_fork_syntax",
  "old_logprof_fork_addition", "old_profile", "audit_msg", "key",
  "key_list", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    59,    60,    61,    61,    62,    63,    63,    63,    63,
      63,    63,    64,    64,    65,    65,    66,    66,    66,    66,
      66,    67,    67,    68,    68,    68,    69,    69,    70,    70,
      70,    71,    72,    72,    73,    73,    74,    75,    75,    76,
      76,    76,    76,    76,    76,    76,    76,    76,    76,    76,
      76
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     3,     1,     1,     3,     3,     3,     3,     3,
       3,     3,     2,     2,     1,     1,    13,    13,    14,    17,
      14,     1,     1,     2,     2,     2,    10,     1,     4,     4,
       2,     8,     0,     6,     1,     1,    11,     1,     2,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     0,     0,     0,     1,     0,     0,     0,     0,     0,
       0,     0,     2,     3,     4,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     6,    37,     7,     8,
       9,    10,    11,    14,    15,     0,     5,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,    38,     0,     0,     0,     0,    13,     0,    27,     0,
       0,    21,    22,     0,     0,    12,     0,     0,    39,    40,
      41,    42,    43,    44,    45,    46,    47,    48,    49,    50,
      30,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    28,    29,     0,     0,    23,    24,    25,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,    32,    34,    35,     0,     0,     0,     0,     0,
       0,     0,     0,    31,     0,     0,     0,     0,     0,     0,
      36,     0,     0,     0,     0,     0,     0,     0,     0,    26,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    33,    16,     0,
       0,     0,    17,    20,    18,     0,     0,     0,    19
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,     2,    12,    13,    14,    46,    47,    75,    76,   107,
      66,    67,    68,   153,   145,    16,    36,    37
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -161
static const yytype_int16 yypact[] =
{
     -29,     7,    17,    27,  -161,   -25,   -25,   -25,   -25,   -25,
     -25,   -25,  -161,  -161,  -161,    14,     6,     6,     6,     6,
       6,     6,   -15,   -31,    16,    22,    23,    29,    30,    52,
      54,    71,    72,    73,    74,    75,     6,  -161,     6,     6,
       6,     6,     6,  -161,  -161,     9,  -161,    -8,    26,    83,
      84,    85,    86,    87,    88,    89,    90,    91,    92,    93,
      94,  -161,    95,    41,    42,    47,  -161,    48,  -161,    76,
      77,  -161,  -161,    98,    96,  -161,    70,    97,  -161,  -161,
    -161,  -161,  -161,  -161,  -161,  -161,  -161,  -161,  -161,  -161,
    -161,    99,   100,   101,   102,   -27,    78,    79,   109,   111,
     104,   114,   115,   119,   120,     0,    67,   112,   117,   122,
     110,   116,   118,  -161,  -161,   103,    80,  -161,  -161,  -161,
     124,   121,   125,   105,   126,   123,   128,   129,   130,   127,
     131,   132,   133,   137,   138,     8,   136,   135,   139,   144,
     145,   140,   106,  -161,  -161,   134,   141,   147,   150,   146,
     143,   148,   153,  -161,   154,   113,   152,   156,   161,   142,
    -161,     8,     8,     8,   149,   151,   155,     8,   157,  -161,
     158,     8,     8,   165,   159,   162,     8,   160,   163,   164,
       8,     8,   166,     8,     8,   167,   168,  -161,  -161,   169,
     174,     8,  -161,  -161,  -161,   170,     8,   175,  -161
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -161,  -161,  -161,  -161,  -161,  -161,  -161,  -161,  -161,  -161,
    -161,  -161,  -161,  -161,  -160,    65,    60,    28
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
      69,   168,   169,   170,   105,   117,   106,   174,    43,    44,
      45,   177,   178,   143,     1,   144,   182,     4,     3,    15,
     186,   187,    70,   189,   190,    23,    48,    49,    71,    72,
      73,   195,   118,    50,    51,    62,   197,    63,    64,    77,
      52,    53,    74,     5,     6,     7,     8,     9,    10,    11,
      65,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    54,    61,    55,    61,    61,    61,    61,
      61,    17,    18,    19,    20,    21,    22,    38,    39,    40,
      41,    42,    56,    57,    58,    59,    60,    78,    79,    80,
      81,    82,    83,    84,    85,    86,    87,    88,    89,    91,
      92,    90,    93,    94,    97,    99,    95,   100,    96,    98,
     101,   102,   103,   104,   109,   110,   111,   119,   108,   112,
     113,   114,   115,   116,   123,   120,   121,   122,   125,   124,
     128,     0,   132,   137,   129,   133,   127,   138,   130,   134,
     135,   142,   146,   136,   131,   126,   140,   141,   147,   149,
       0,   150,   148,   156,   151,   155,   157,   159,     0,   158,
     160,   154,   152,   139,   161,   162,   164,   166,   173,   163,
     165,   179,     0,   181,     0,     0,     0,     0,   185,     0,
     188,     0,   192,   193,   175,   176,   180,   183,   194,   198,
     184,     0,     0,     0,     0,     0,     0,   196,   167,     0,
       0,     0,     0,     0,     0,   171,     0,   172,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   191
};

static const yytype_int16 yycheck[] =
{
       8,   161,   162,   163,    31,     5,    33,   167,    23,    24,
      25,   171,   172,     5,    43,     7,   176,     0,    11,    44,
     180,   181,    30,   183,   184,    11,    57,    11,    36,    37,
      38,   191,    32,    11,    11,    26,   196,    28,    29,    13,
      11,    11,    50,    16,    17,    18,    19,    20,    21,    22,
      41,    45,    46,    47,    48,    49,    50,    51,    52,    53,
      54,    55,    56,    11,    36,    11,    38,    39,    40,    41,
      42,     6,     7,     8,     9,    10,    11,    17,    18,    19,
      20,    21,    11,    11,    11,    11,    11,     4,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,    58,
      58,     6,    55,    55,     6,    35,    30,    10,    31,    13,
      11,    11,    11,    11,    35,     6,     5,    50,    40,    15,
       6,     6,     3,     3,    14,    13,     9,     5,    10,    13,
       6,    -1,     6,     6,    13,    12,    56,     6,    13,    11,
      11,     3,     6,    13,    39,    42,    13,    10,    13,     5,
      -1,     6,    13,     6,    14,    14,     6,    14,    -1,    13,
      12,    27,    56,    31,    11,    11,    14,     6,    13,    56,
      14,     6,    -1,    11,    -1,    -1,    -1,    -1,    14,    -1,
      14,    -1,    14,    14,    27,    27,    27,    27,    14,    14,
      27,    -1,    -1,    -1,    -1,    -1,    -1,    27,    56,    -1,
      -1,    -1,    -1,    -1,    -1,    56,    -1,    56,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    56
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    43,    60,    11,     0,    16,    17,    18,    19,    20,
      21,    22,    61,    62,    63,    44,    74,    74,    74,    74,
      74,    74,    74,    11,    45,    46,    47,    48,    49,    50,
      51,    52,    53,    54,    55,    56,    75,    76,    75,    75,
      75,    75,    75,    23,    24,    25,    64,    65,    57,    11,
      11,    11,    11,    11,    11,    11,    11,    11,    11,    11,
      11,    76,    26,    28,    29,    41,    69,    70,    71,     8,
      30,    36,    37,    38,    50,    66,    67,    13,     4,     4,
       4,     4,     4,     4,     4,     4,     4,     4,     4,     4,
       6,    58,    58,    55,    55,    30,    31,     6,    13,    35,
      10,    11,    11,    11,    11,    31,    33,    68,    40,    35,
       6,     5,    15,     6,     6,     3,     3,     5,    32,    50,
      13,     9,     5,    14,    13,    10,    42,    56,     6,    13,
      13,    39,     6,    12,    11,    11,    13,     6,     6,    31,
      13,    10,     3,     5,     7,    73,     6,    13,    13,     5,
       6,    14,    56,    72,    27,    14,     6,     6,    13,    14,
      12,    11,    11,    56,    14,    14,     6,    56,    73,    73,
      73,    56,    56,    13,    73,    27,    27,    73,    73,     6,
      27,    11,    73,    27,    27,    14,    73,    73,    14,    73,
      73,    56,    14,    14,    14,    73,    27,    73,    14
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (scanner, YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, scanner)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, scanner); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *scanner)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, scanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    void *scanner;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (scanner);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, void *scanner)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, scanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    void *scanner;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep, scanner);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *bottom, yytype_int16 *top)
#else
static void
yy_stack_print (bottom, top)
    yytype_int16 *bottom;
    yytype_int16 *top;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; bottom <= top; ++bottom)
    YYFPRINTF (stderr, " %d", *bottom);
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule, void *scanner)
#else
static void
yy_reduce_print (yyvsp, yyrule, scanner)
    YYSTYPE *yyvsp;
    int yyrule;
    void *scanner;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      fprintf (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       , scanner);
      fprintf (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule, scanner); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, void *scanner)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, scanner)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    void *scanner;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (scanner);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void *scanner);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */






/*----------.
| yyparse.  |
`----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *scanner)
#else
int
yyparse (scanner)
    void *scanner;
#endif
#endif
{
  /* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;

  int yystate;
  int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Look-ahead token as an internal (translated) token number.  */
  int yytoken = 0;
#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack.  */
  yytype_int16 yyssa[YYINITDEPTH];
  yytype_int16 *yyss = yyssa;
  yytype_int16 *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  YYSIZE_T yystacksize = YYINITDEPTH;

  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;


  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;


	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),

		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss);
	YYSTACK_RELOCATE (yyvs);

#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;


      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     look-ahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to look-ahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a look-ahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the look-ahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 3:
#line 106 "grammar.y"
    { ret_record->version = AA_RECORD_SYNTAX_V1; ;}
    break;

  case 4:
#line 107 "grammar.y"
    { ret_record->version = AA_RECORD_SYNTAX_V2; ;}
    break;

  case 6:
#line 113 "grammar.y"
    { ret_record->event = AA_RECORD_DENIED; ;}
    break;

  case 7:
#line 114 "grammar.y"
    { ret_record->event = AA_RECORD_AUDIT; ;}
    break;

  case 8:
#line 115 "grammar.y"
    { ret_record->event = AA_RECORD_ALLOWED; ;}
    break;

  case 9:
#line 116 "grammar.y"
    { ret_record->event = AA_RECORD_HINT; ;}
    break;

  case 10:
#line 117 "grammar.y"
    { ret_record->event = AA_RECORD_STATUS; ;}
    break;

  case 11:
#line 118 "grammar.y"
    { ret_record->event = AA_RECORD_ERROR; ;}
    break;

  case 13:
#line 123 "grammar.y"
    { ret_record->event = AA_RECORD_HINT; ;}
    break;

  case 14:
#line 127 "grammar.y"
    { ret_record->event = AA_RECORD_DENIED; ;}
    break;

  case 15:
#line 128 "grammar.y"
    { ret_record->event = AA_RECORD_ALLOWED; ;}
    break;

  case 16:
#line 135 "grammar.y"
    {
		ret_record->requested_mask = strdup((yyvsp[(1) - (13)].t_str));
		free((yyvsp[(1) - (13)].t_str));
		ret_record->info = strdup((yyvsp[(5) - (13)].t_str));
		free((yyvsp[(5) - (13)].t_str));
		ret_record->pid = atol((yyvsp[(7) - (13)].t_str));
		free((yyvsp[(7) - (13)].t_str));
		ret_record->profile = strdup((yyvsp[(10) - (13)].t_str));
		free((yyvsp[(10) - (13)].t_str));
		ret_record->active_hat = strdup((yyvsp[(12) - (13)].t_str));
		free((yyvsp[(12) - (13)].t_str));
		ret_record->operation = strdup("access");
	;}
    break;

  case 17:
#line 151 "grammar.y"
    {
		ret_record->name = strdup((yyvsp[(3) - (13)].t_str));
		free((yyvsp[(3) - (13)].t_str));
		ret_record->info = strdup((yyvsp[(5) - (13)].t_str));
		free((yyvsp[(5) - (13)].t_str));
		ret_record->pid = atol((yyvsp[(7) - (13)].t_str));
		free((yyvsp[(7) - (13)].t_str));
		ret_record->profile = strdup((yyvsp[(10) - (13)].t_str));
		free((yyvsp[(10) - (13)].t_str));
		ret_record->active_hat = strdup((yyvsp[(12) - (13)].t_str));
		free((yyvsp[(12) - (13)].t_str));
	;}
    break;

  case 18:
#line 166 "grammar.y"
    {
		ret_record->operation = strdup("xattr");
		ret_record->attribute = strdup((yyvsp[(2) - (14)].t_str));
		free((yyvsp[(2) - (14)].t_str));
		ret_record->name = strdup((yyvsp[(4) - (14)].t_str));
		free((yyvsp[(4) - (14)].t_str));
		ret_record->info = strdup((yyvsp[(6) - (14)].t_str));
		free((yyvsp[(6) - (14)].t_str));
		ret_record->pid = atol((yyvsp[(8) - (14)].t_str));
		free((yyvsp[(8) - (14)].t_str));
		ret_record->profile = strdup((yyvsp[(11) - (14)].t_str));
		free((yyvsp[(11) - (14)].t_str));
		ret_record->active_hat = strdup((yyvsp[(13) - (14)].t_str));
		free((yyvsp[(13) - (14)].t_str));
	;}
    break;

  case 19:
#line 185 "grammar.y"
    {
		ret_record->operation = strdup("setattr");
		ret_record->attribute = strdup((yyvsp[(3) - (17)].t_str));
		free((yyvsp[(3) - (17)].t_str));
		ret_record->name = strdup((yyvsp[(7) - (17)].t_str));
		free((yyvsp[(7) - (17)].t_str));
		ret_record->info = strdup((yyvsp[(9) - (17)].t_str));
		free((yyvsp[(9) - (17)].t_str));
		ret_record->pid = atol((yyvsp[(11) - (17)].t_str));
		free((yyvsp[(11) - (17)].t_str));
		ret_record->profile = strdup((yyvsp[(14) - (17)].t_str));
		free((yyvsp[(14) - (17)].t_str));
		ret_record->active_hat = strdup((yyvsp[(16) - (17)].t_str));
		free((yyvsp[(16) - (17)].t_str));
	;}
    break;

  case 20:
#line 203 "grammar.y"
    {
		ret_record->operation = strdup("capability");
		ret_record->name = strdup((yyvsp[(4) - (14)].t_str));
		free((yyvsp[(4) - (14)].t_str));
		ret_record->info = strdup((yyvsp[(6) - (14)].t_str));
		free((yyvsp[(6) - (14)].t_str));
		ret_record->pid = atol((yyvsp[(8) - (14)].t_str));
		free((yyvsp[(8) - (14)].t_str));
		ret_record->profile = strdup((yyvsp[(11) - (14)].t_str));
		free((yyvsp[(11) - (14)].t_str));
		ret_record->active_hat = strdup((yyvsp[(13) - (14)].t_str));
		free((yyvsp[(13) - (14)].t_str));
	;}
    break;

  case 21:
#line 219 "grammar.y"
    { ret_record->operation = strdup("mkdir"); ;}
    break;

  case 22:
#line 220 "grammar.y"
    { ret_record->operation = strdup("rmdir"); ;}
    break;

  case 23:
#line 225 "grammar.y"
    {
			ret_record->name = strdup((yyvsp[(2) - (2)].t_str));
			free((yyvsp[(2) - (2)].t_str));
		;}
    break;

  case 24:
#line 230 "grammar.y"
    {
			ret_record->info = strdup("pipe");
		;}
    break;

  case 25:
#line 234 "grammar.y"
    {
			ret_record->info = strdup("extended attribute");
		;}
    break;

  case 26:
#line 241 "grammar.y"
    {
				ret_record->pid = (yyvsp[(4) - (10)].t_long);
				ret_record->profile = strdup((yyvsp[(7) - (10)].t_str));
				free((yyvsp[(7) - (10)].t_str));
				ret_record->active_hat = strdup((yyvsp[(10) - (10)].t_str));
				free((yyvsp[(10) - (10)].t_str));
			;}
    break;

  case 28:
#line 253 "grammar.y"
    {
			ret_record->operation = strdup("profile_set");
			ret_record->info = strdup("unknown profile");
			ret_record->name = strdup((yyvsp[(4) - (4)].t_str));
			free((yyvsp[(4) - (4)].t_str));
		;}
    break;

  case 29:
#line 260 "grammar.y"
    {
			ret_record->operation = strdup("exec");
			ret_record->info = strdup("mandatory profile missing");
			ret_record->name = strdup((yyvsp[(4) - (4)].t_str));
			free((yyvsp[(4) - (4)].t_str));
		;}
    break;

  case 30:
#line 267 "grammar.y"
    {
			ret_record->operation = strdup("change_hat");
			ret_record->name = strdup((yyvsp[(2) - (2)].t_str)); 
			free((yyvsp[(2) - (2)].t_str));
			ret_record->info = strdup("unknown_hat");
		;}
    break;

  case 31:
#line 279 "grammar.y"
    {
		ret_record->operation = strdup("clone");
		ret_record->task = (yyvsp[(7) - (8)].t_long);
		ret_record->pid = (yyvsp[(4) - (8)].t_long);
	;}
    break;

  case 33:
#line 289 "grammar.y"
    {
		ret_record->profile = strdup((yyvsp[(3) - (6)].t_str));
		free((yyvsp[(3) - (6)].t_str));
		ret_record->active_hat = strdup((yyvsp[(6) - (6)].t_str));
		free((yyvsp[(6) - (6)].t_str));
	;}
    break;

  case 34:
#line 299 "grammar.y"
    {
			(yyval.t_str) = strdup((yyvsp[(1) - (1)].t_str));
			free((yyvsp[(1) - (1)].t_str));
		;}
    break;

  case 35:
#line 304 "grammar.y"
    {
			(yyval.t_str) = strdup("null-complain-profile");
		;}
    break;

  case 36:
#line 310 "grammar.y"
    {
		/* TOK_AUDIT_DIGITS is actually a character string, and this could be done in a better way. */
		int len1 = strlen((yyvsp[(5) - (11)].t_str));
		int len2 = strlen((yyvsp[(7) - (11)].t_str));
		int len3 = strlen((yyvsp[(9) - (11)].t_str));
		int len = len1 + len2 + len3;
		ret_record->audit_id = (char *) malloc(len + 3);
		strncat(ret_record->audit_id, (yyvsp[(5) - (11)].t_str), len1);
		strncat(ret_record->audit_id, ".", 1);
		strncat(ret_record->audit_id, (yyvsp[(7) - (11)].t_str), len2);
		strncat(ret_record->audit_id, ":", 1);
		strncat(ret_record->audit_id, (yyvsp[(9) - (11)].t_str), len3);
		free((yyvsp[(5) - (11)].t_str));
		free((yyvsp[(7) - (11)].t_str));
		free((yyvsp[(9) - (11)].t_str));
	;}
    break;

  case 39:
#line 333 "grammar.y"
    { ret_record->operation = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str)); ;}
    break;

  case 40:
#line 335 "grammar.y"
    { ret_record->name = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str)); ;}
    break;

  case 41:
#line 337 "grammar.y"
    { ret_record->name2 = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str)); ;}
    break;

  case 42:
#line 339 "grammar.y"
    { ret_record->denied_mask = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;

  case 43:
#line 341 "grammar.y"
    { ret_record->requested_mask = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;

  case 44:
#line 343 "grammar.y"
    { ret_record->attribute = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;

  case 45:
#line 345 "grammar.y"
    { ret_record->task = atol((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;

  case 46:
#line 347 "grammar.y"
    { ret_record->parent = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;

  case 47:
#line 349 "grammar.y"
    { ret_record->magic_token = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;

  case 48:
#line 351 "grammar.y"
    { ret_record->info = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;

  case 49:
#line 353 "grammar.y"
    { ret_record->pid = atol((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;

  case 50:
#line 355 "grammar.y"
    { ret_record->profile = strdup((yyvsp[(3) - (3)].t_str)); free((yyvsp[(3) - (3)].t_str));;}
    break;


/* Line 1267 of yacc.c.  */
#line 1948 "grammar.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;


  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (scanner, YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (scanner, yymsg);
	  }
	else
	  {
	    yyerror (scanner, YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse look-ahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, scanner);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse look-ahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  if (yyn == YYFINAL)
    YYACCEPT;

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (scanner, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEOF && yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, scanner);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, scanner);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}


#line 358 "grammar.y"


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

	libaalogparse_lex_init(&scanner);
	lex_buf = libaalogparse__scan_string(str, scanner);
	/*libaalogparse_restart(NULL, scanner); */
	parser_return = libaalogparse_parse(scanner);
	libaalogparse__delete_buffer(lex_buf, scanner);
	libaalogparse_lex_destroy(scanner);
	return ret_record;
}

