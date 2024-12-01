%{
/*
 *   Copyright (c) 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
 *   NOVELL (All rights reserved)
 *   Copyright (c) 2010-2012
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

#define YYERROR_VERBOSE 1
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#include "parser.h"
#include "lexer.hh"

// For tracking location
# define YYLLOC_DEFAULT(Cur, Rhs, N)                \
do                                                  \
  if (N)                                            \
    {                                               \
      (Cur).first_pos = YYRHSLOC(Rhs, 1).first_pos; \
      (Cur).last_pos  = YYRHSLOC(Rhs, N).last_pos;  \
    }                                               \
  else                                              \
    {                                               \
      (Cur).first_pos = (Cur).last_pos =            \
        YYRHSLOC(Rhs, 0).last_pos;                  \
    }                                               \
while (0)

%}

%require "3.2"
%language "c++"

// To keep track of character positions
%define api.location.type {YYLTYPE};

%define api.value.type variant
%define api.token.constructor
%define api.token.raw

%token TOK_ID
%token TOK_CONDID
%token TOK_CONDLISTID
%token TOK_CARET
%token TOK_OPEN
%token TOK_CLOSE
%token TOK_MODE
%token TOK_END_OF_RULE
%token TOK_EQUALS
%token TOK_ARROW
%token TOK_ADD_ASSIGN
%token TOK_LE
%token TOK_SET_VAR
%token TOK_BOOL_VAR
%token TOK_VALUE
%token TOK_IF
%token TOK_ELSE
%token TOK_NOT
%token TOK_DEFINED
%token TOK_CHANGE_PROFILE
%token TOK_NETWORK
%token TOK_UNIX
%token TOK_CREATE
%token TOK_SHUTDOWN
%token TOK_ACCEPT
%token TOK_CONNECT
%token TOK_LISTEN
%token TOK_SETOPT
%token TOK_GETOPT
%token TOK_SETATTR
%token TOK_GETATTR
%token TOK_HAT
%token TOK_UNSAFE
%token TOK_SAFE
%token TOK_COLON
%token TOK_LINK
%token TOK_OWNER
%token TOK_OTHER
%token TOK_SUBSET
%token TOK_AUDIT
%token TOK_DENY
%token TOK_ALLOW
%token TOK_PROFILE
%token TOK_SET
%token TOK_ALIAS
%token TOK_PTRACE
%token TOK_OPENPAREN
%token TOK_CLOSEPAREN
%token TOK_COMMA
%token TOK_FILE
%token TOK_MOUNT
%token TOK_REMOUNT
%token TOK_UMOUNT
%token TOK_PIVOTROOT
%token TOK_IN
%token TOK_DBUS
%token TOK_SIGNAL
%token TOK_SEND
%token TOK_RECEIVE
%token TOK_BIND
%token TOK_READ
%token TOK_WRITE
%token TOK_EAVESDROP
%token TOK_PEER
%token TOK_TRACE
%token TOK_TRACEDBY
%token TOK_READBY
%token TOK_ABI
%token TOK_USERNS
%token TOK_INCLUDE
%token TOK_INCLUDE_IF_EXISTS
%token TOK_ALL

 /* rlimits */
%token TOK_RLIMIT
%token TOK_SOFT_RLIMIT
%token TOK_RLIMIT_CPU
%token TOK_RLIMIT_FSIZE
%token TOK_RLIMIT_DATA
%token TOK_RLIMIT_STACK
%token TOK_RLIMIT_CORE
%token TOK_RLIMIT_RSS
%token TOK_RLIMIT_NOFILE
%token TOK_RLIMIT_OFILE
%token TOK_RLIMIT_AS
%token TOK_RLIMIT_NPROC
%token TOK_RLIMIT_MEMLOCK
%token TOK_RLIMIT_LOCKS
%token TOK_RLIMIT_SIGPENDING
%token TOK_RLIMIT_MSGQUEUE
%token TOK_RLIMIT_NICE
%token TOK_RLIMIT_RTPRIO

/* capabilities */
%token TOK_CAPABILITY

/* debug flag values */
%token TOK_FLAGS

%code requires {
  #include <memory>
  #include <sstream>

  #include "parser.h"
  #include "tree/AbstractionRule.hh"
  #include "tree/AliasNode.hh"
  #include "tree/FileRule.hh"
  #include "tree/LinkRule.hh"
  #include "tree/ParseTree.hh"
  #include "tree/ProfileRule.hh"
  #include "tree/PrefixNode.hh"
  #include "tree/RuleList.hh"
  #include "tree/FileMode.hh"
  #include "tree/RuleNode.hh"
  #include "tree/TreeNode.hh"
  #include "tree/AllRule.hh"

  class Driver;
  class Lexer;

  using namespace AppArmor::Tree;
}

// The parsing context.
%parse-param {Lexer& scanner}
%param { Driver& driver }

%code{
  #undef yylex
  #define yylex scanner.yylex
  using namespace AppArmor::Tree;
}

%type <std::shared_ptr<ParseTree>> 				tree
%type <std::shared_ptr<std::list<ProfileRule>>> profilelist
%type <ProfileRule> 							profile_base
%type <ProfileRule> 							profile
%type <ProfileRule> 							local_profile
%type <TreeNode> 								preamble
%type <RuleList> 								rules
%type <TreeNode> 								alias
%type <PrefixNode> 								opt_prefix

%type <AbstractionRule> abstraction
%type <TreeNode> abi_rule
%type <RuleNode> network_rule
%type <RuleNode> mnt_rule
%type <RuleNode> dbus_rule
%type <RuleNode> signal_rule
%type <RuleNode> ptrace_rule
%type <RuleNode> unix_rule
%type <RuleNode> userns_rule
%type <RuleNode> change_profile
%type <RuleNode> capability
%type <RuleNode> hat
%type <RuleNode> cond_rule
%type <LinkRule> link_rule
%type <FileRule> file_rule
%type <FileRule> frule
%type <FileRule> file_rule_tail
%type <AllRule>	 all_rule

%type <std::string> TOK_ID
%type <std::string>	TOK_CONDID
%type <std::string>	TOK_CONDLISTID
%type <std::string>	TOK_ALIAS
%type <std::string> TOK_MODE
%type <std::string> TOK_SET_VAR
%type <std::string> TOK_BOOL_VAR
%type <std::string>	TOK_VALUE

%type <bool> opt_subset_flag
%type <bool> opt_audit_flag
%type <bool> opt_owner_flag
%type <bool> opt_profile_flag
%type <bool> opt_flags
%type <bool> opt_perm_mode
%type <bool> opt_exec_mode
%type <bool> opt_file

%type <FileMode> file_mode
%type <std::string>	id_or_var
%type <std::string>	opt_id_or_var
%type <std::string>	opt_id
%type <std::string>	opt_target
%type <std::string>	opt_named_transition
%%


tree: preamble profilelist { 
								$$ = std::make_shared<ParseTree>($1, $2);
								driver.ast = $$;
								driver.success = true;
						   };

profilelist:					 { $$ = std::make_shared<std::list<ProfileRule>>(); }
		   | profilelist profile { $$ = $1; $$->push_back($2); }

opt_profile_flag:				{ $$ = PROFILE_MODE_EMPTY; }
				| TOK_PROFILE	{ $$ = PROFILE_MODE_START; }
				| hat_start		{ $$ = PROFILE_MODE_HAT; }

opt_id:			{ $$ = ""; }
	  | TOK_ID	{ $$ = $1; }

opt_id_or_var:				{ $$ = ""; }
			 | id_or_var	{ $$ = $1; }

// Should eventually add optional stuff into 
profile_base: TOK_ID opt_id_or_var opt_cond_list flags TOK_OPEN rules TOK_CLOSE {
		$6.setStartPosition(@6.first_pos);
		$6.setStopPosition(@6.last_pos);

		$$ = ProfileRule($1, $6);
	}

profile: opt_profile_flag profile_base { $$ = $2; }

local_profile: TOK_PROFILE profile_base { $$ = $2; }

hat: hat_start profile_base

preamble:					 	{ $$ = TreeNode(); }
		| preamble alias	 	{ $$ = $1; $$.appendChild($2); }
		| preamble varassign 	{ $$ = $1; /*$$.appendChild($2);*/ }
		| preamble abi_rule	 	{ $$ = $1; $$.appendChild($2); }
		| preamble abstraction	{ $$ = $1; /*$$.appendChild($2);*/ }

alias: TOK_ALIAS TOK_ID TOK_ARROW TOK_ID TOK_END_OF_RULE {
		$$ = AliasNode($2, $4);
	}

varassign: TOK_SET_VAR TOK_EQUALS valuelist
		 | TOK_SET_VAR TOK_ADD_ASSIGN valuelist
		 | TOK_BOOL_VAR TOK_EQUALS TOK_VALUE

valuelist: TOK_VALUE
		 | valuelist TOK_VALUE

opt_flags:					{ $$ = false; }
	| TOK_CONDID TOK_EQUALS	{ 
							  if($1 != "flags") {
								yyerror("expected flags= got %s=", $1.c_str());
							  }
							  $$ = true;
							}

flags:
	 | opt_flags TOK_OPENPAREN flagvals TOK_CLOSEPAREN

flagvals: flagvals flagval
		| flagval

flagval:	TOK_VALUE

opt_subset_flag:			{$$ = false;}
			   | TOK_SUBSET	{$$ = true;}
			   | TOK_LE		{$$ = true;}

opt_audit_flag:				{$$ = false;}
			  | TOK_AUDIT	{$$ = true;}

// Should change: ideally 'owner' != 'other'
opt_owner_flag:				{$$ = false;}
			  | TOK_OWNER	{$$ = true;}
			  | TOK_OTHER	{$$ = true;}

opt_perm_mode:				{$$ = false;}
			 | TOK_ALLOW	{$$ = false;}
			 | TOK_DENY		{$$ = true;}

opt_prefix: opt_audit_flag opt_perm_mode opt_owner_flag {$$ = PrefixNode($1, $2, $3);}

rules:												{$$ = RuleList(@0.last_pos);}
	 | rules abi_rule								{$$ = $1;}
	 | rules opt_prefix file_rule					{$$ = $1; $$.appendFileRule($2, $3);}
	 | rules opt_prefix link_rule					{$$ = $1; $$.appendLinkRule($2, $3);}
	 | rules opt_prefix TOK_OPEN rules TOK_CLOSE	{$$ = $1; $$.appendRuleList($2, $4);}
	 | rules opt_prefix network_rule				{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules opt_prefix mnt_rule					{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules opt_prefix dbus_rule					{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules opt_prefix signal_rule					{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules opt_prefix ptrace_rule					{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules opt_prefix unix_rule					{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules opt_prefix userns_rule					{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules opt_prefix change_profile				{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules opt_prefix capability					{$$ = $1; /* $$.appendChildren({$2, $3}); */}
	 | rules all_rule								{$$ = $1; /* $$.appendChild({$2}); */}
	 | rules hat									{$$ = $1; /* $$.appendChild($2); */}
	 | rules local_profile							{$$ = $1; $$.appendSubprofile($2);}
	 | rules cond_rule								{$$ = $1; /* $$.appendChild($2); */}
	 | rules abstraction							{$$ = $1; $$.appendAbstraction($2);}
	 | rules TOK_SET TOK_RLIMIT TOK_ID TOK_LE TOK_VALUE opt_id TOK_END_OF_RULE	{$$ = $1;}

cond_rule: TOK_IF expr TOK_OPEN rules TOK_CLOSE
		 | TOK_IF expr TOK_OPEN rules TOK_CLOSE TOK_ELSE TOK_OPEN rules TOK_CLOSE
		 | TOK_IF expr TOK_OPEN rules TOK_CLOSE TOK_ELSE cond_rule

expr:	TOK_NOT expr
	|	TOK_BOOL_VAR
	|	TOK_DEFINED TOK_SET_VAR
	|	TOK_DEFINED TOK_BOOL_VAR

id_or_var: TOK_ID		{$$ = $1;}
		 | TOK_SET_VAR	{$$ = $1;}

opt_target: /* nothing */		{ $$ = ""; }
		  | TOK_ARROW id_or_var	{ $$ = $2; }

opt_named_transition: /* nothing */			{$$ = "";}
					| TOK_ARROW id_or_var	{$$ = $2;}

abi_rule: TOK_ABI TOK_ID 	TOK_END_OF_RULE	{$$ = TreeNode($2);}
		| TOK_ABI TOK_VALUE TOK_END_OF_RULE	{$$ = TreeNode($2);}

abstraction: TOK_INCLUDE		   TOK_ID 	 {$$ = AbstractionRule(@1.first_pos, @2.last_pos, $2, false);}
		   | TOK_INCLUDE		   TOK_VALUE {$$ = AbstractionRule(@1.first_pos, @2.last_pos, $2, false);}
		   | TOK_INCLUDE_IF_EXISTS TOK_ID 	 {$$ = AbstractionRule(@1.first_pos, @2.last_pos, $2, true);}
		   | TOK_INCLUDE_IF_EXISTS TOK_VALUE {$$ = AbstractionRule(@1.first_pos, @2.last_pos, $2, true);}

opt_exec_mode:				{ $$ = EXEC_MODE_EMPTY; }
			 | TOK_UNSAFE	{ $$ = EXEC_MODE_UNSAFE; }
			 | TOK_SAFE		{ $$ = EXEC_MODE_SAFE; }

opt_file:			{ $$ = 0; }
		| TOK_FILE  { $$ = 1; }

// Should utilize the deleted get_mode() from parser.h instead of yylval mode
frule: id_or_var file_mode opt_named_transition TOK_END_OF_RULE					{$$ = FileRule(@1.first_pos, @4.last_pos, $1, $2, $3);}
//	 | file_mode opt_subset_flag id_or_var opt_named_transition TOK_END_OF_RULE	{$$ = FileRule(@1.first_pos, @5.last_pos, $3, $1, $4, $2);}

file_rule: TOK_FILE TOK_END_OF_RULE	{$$ = FileRule(@1.first_pos, @2.last_pos);}
		 | opt_file file_rule_tail	{$$ = $2;}

file_rule_tail: opt_exec_mode frule							{$$ = $2;}
			  | opt_exec_mode id_or_var file_mode id_or_var	{$$ = FileRule(@1.first_pos, @4.last_pos, $2, $3, $4);}

link_rule: TOK_LINK opt_subset_flag id_or_var TOK_ARROW id_or_var TOK_END_OF_RULE	{$$ = LinkRule(@1.first_pos, @6.last_pos, $2, $3, $5);}

network_rule: TOK_NETWORK opt_net_perm               opt_conds opt_cond_list TOK_END_OF_RULE {$$ = RuleNode(@1.first_pos, @5.last_pos);}
			| TOK_NETWORK opt_net_perm TOK_ID        opt_conds opt_cond_list TOK_END_OF_RULE {$$ = RuleNode(@1.first_pos, @6.last_pos);}
			| TOK_NETWORK opt_net_perm TOK_ID TOK_ID opt_conds opt_cond_list TOK_END_OF_RULE {$$ = RuleNode(@1.first_pos, @7.last_pos);}

cond: TOK_CONDID
	| TOK_CONDID TOK_EQUALS TOK_VALUE
	| TOK_CONDID TOK_EQUALS TOK_OPENPAREN valuelist TOK_CLOSEPAREN
	| TOK_CONDID TOK_IN TOK_OPENPAREN valuelist TOK_CLOSEPAREN

opt_conds:
		 | opt_conds cond

cond_list: TOK_CONDLISTID TOK_EQUALS TOK_OPENPAREN opt_conds TOK_CLOSEPAREN

opt_cond_list:
			 | cond_list

mnt_rule: TOK_MOUNT opt_conds opt_id TOK_END_OF_RULE
		| TOK_MOUNT opt_conds opt_id TOK_ARROW opt_conds TOK_ID TOK_END_OF_RULE
		| TOK_REMOUNT opt_conds opt_id TOK_END_OF_RULE
		| TOK_UMOUNT opt_conds opt_id TOK_END_OF_RULE
		| TOK_PIVOTROOT opt_conds opt_id opt_target TOK_END_OF_RULE

dbus_perm: TOK_VALUE
	| TOK_BIND
	| TOK_SEND
	| TOK_RECEIVE
	| TOK_READ
	| TOK_WRITE
	| TOK_EAVESDROP
	| TOK_MODE

dbus_perms:
		  | dbus_perms dbus_perm
		  | dbus_perms TOK_COMMA dbus_perm

opt_dbus_perm:
			 | dbus_perm
			 | TOK_OPENPAREN dbus_perms TOK_CLOSEPAREN

dbus_rule: TOK_DBUS opt_dbus_perm opt_conds opt_cond_list TOK_END_OF_RULE

net_perm: TOK_VALUE
		| TOK_CREATE
		| TOK_BIND
		| TOK_LISTEN
		| TOK_ACCEPT
		| TOK_CONNECT
		| TOK_SHUTDOWN
		| TOK_GETATTR
		| TOK_SETATTR
		| TOK_GETOPT
		| TOK_SETOPT
		| TOK_SEND
		| TOK_RECEIVE
		| TOK_READ
		| TOK_WRITE
		| TOK_MODE

net_perms:
		 | net_perms net_perm
		 | net_perms TOK_COMMA net_perm

opt_net_perm:
	 		| net_perm
	 		| TOK_OPENPAREN net_perms TOK_CLOSEPAREN

unix_rule: TOK_UNIX opt_net_perm opt_conds opt_cond_list TOK_END_OF_RULE

signal_perm: TOK_VALUE
		   | TOK_SEND
		   | TOK_RECEIVE
		   | TOK_READ
		   | TOK_WRITE
		   | TOK_MODE

signal_perms:
			| signal_perms signal_perm
			| signal_perms TOK_COMMA signal_perm

opt_signal_perm:
			   | signal_perm
			   | TOK_OPENPAREN signal_perms TOK_CLOSEPAREN

signal_rule: TOK_SIGNAL opt_signal_perm opt_conds TOK_END_OF_RULE

ptrace_perm: TOK_VALUE
		   | TOK_TRACE
		   | TOK_TRACEDBY
		   | TOK_READ
		   | TOK_WRITE
		   | TOK_READBY
		   | TOK_MODE

ptrace_perms:
			| ptrace_perms ptrace_perm
			| ptrace_perms TOK_COMMA ptrace_perm

opt_ptrace_perm:
			   | ptrace_perm
			   | TOK_OPENPAREN ptrace_perms TOK_CLOSEPAREN

ptrace_rule: TOK_PTRACE opt_ptrace_perm opt_conds TOK_END_OF_RULE

userns_perm: TOK_VALUE
		   | TOK_CREATE

userns_perms:
			| userns_perms userns_perm
			| userns_perms TOK_COMMA userns_perm

opt_userns_perm:
			   | userns_perm
			   | TOK_OPENPAREN userns_perms TOK_CLOSEPAREN

userns_rule: TOK_USERNS opt_userns_perm opt_conds TOK_END_OF_RULE


all_rule: opt_prefix TOK_ALL TOK_END_OF_RULE {
		{$$ = AllRule($1, @1.first_pos, @3.last_pos);}
}

hat_start: TOK_CARET
		 | TOK_HAT

file_mode: TOK_MODE {
		try {
			$$ = FileMode($1);
		} catch(const std::exception &ex) {
			std::cerr << ex.what() << std::endl;
			yy::parser::error(@1, ex.what());
		}
	}

change_profile: TOK_CHANGE_PROFILE opt_exec_mode opt_id opt_named_transition TOK_END_OF_RULE

capability:	TOK_CAPABILITY caps TOK_END_OF_RULE

caps:
	| caps TOK_ID
%%

void yyerror(const char *msg, ...)
{
	std::stringstream out;

	// Print all arguments to 'out'
	va_list arg;
	va_start(arg, msg);	
	while(*msg != '\0') {
		out << msg;
		++msg;
	}
	va_end(arg);

	std::runtime_error ex(out.str());
	std::throw_with_nested(ex);
}

void yy::parser::error(YYLTYPE const& location, 
					   std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const& str)
{
	yyerror("(%lu, %lu): %s", location.first_pos, location.last_pos, str.c_str());
}