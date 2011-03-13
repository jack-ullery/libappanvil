/*
 * (C) 2006, 2007 Andreas Gruenbacher <agruen@suse.de>
 * Copyright (c) 2003-2008 Novell, Inc. (All rights reserved)
 * Copyright 2009-2010 Canonical Ltd.
 *
 * The libapparmor library is licensed under the terms of the GNU
 * Lesser General Public License, version 2.1. Please see the file
 * COPYING.LGPL.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  */

#ifndef APPARMOR_RE_H
#define APPARMOR_RE_H

typedef enum dfaflags {
  DFA_CONTROL_EQUIV =		1 << 0,
  DFA_CONTROL_TREE_NORMAL =	1 << 1,
  DFA_CONTROL_TREE_SIMPLE =	1 << 2,
  DFA_CONTROL_TREE_LEFT =	1 << 3,
  DFA_CONTROL_MINIMIZE =	1 << 4,
  DFA_CONTROL_MINIMIZE_HASH_TRANS = 1 << 5,
  DFA_CONTROL_MINIMIZE_HASH_PERMS = 1 << 6,
  DFA_CONTROL_REMOVE_UNREACHABLE =	1 << 7,
  DFA_CONTROL_TRANS_HIGH =	1 << 8,

  DFA_DUMP_UNIQ_PERMS =		1 << 14,
  DFA_DUMP_MIN_UNIQ_PERMS =	1 << 15,
  DFA_DUMP_TREE_STATS =		1 << 16,
  DFA_DUMP_TREE =		1 << 17,
  DFA_DUMP_SIMPLE_TREE =	1 << 18,
  DFA_DUMP_PROGRESS =		1 << 19,
  DFA_DUMP_STATS =		1 << 20,
  DFA_DUMP_STATES =		1 << 21,
  DFA_DUMP_GRAPH =		1 << 22,
  DFA_DUMP_TRANS_PROGRESS =	1 << 23,
  DFA_DUMP_TRANS_STATS =	1 << 24,
  DFA_DUMP_TRANS_TABLE =	1 << 25,
  DFA_DUMP_EQUIV =		1 << 26,
  DFA_DUMP_EQUIV_STATS =	1 << 27,
  DFA_DUMP_MINIMIZE =		1 << 28,
  DFA_DUMP_UNREACHABLE =	1 << 29,
  DFA_DUMP_RULE_EXPR =		1 << 30,
  DFA_DUMP_NODE_TO_DFA =	1 << 31,
} dfaflags_t;

#endif /* APPARMOR_RE_H */
