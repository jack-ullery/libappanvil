/*
 *   Copyright (c) 2022
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
 *   along with this program; if not, contact Novell, Inc. or Canonical
 *   Ltd.
 */
#ifndef __AA_USERNS_H
#define __AA_USERNS_H

#include "parser.h"

#define AA_USERNS_CREATE	8
#define AA_VALID_USERNS_PERMS (AA_USERNS_CREATE)

class userns_rule: public rule_t {
	void move_conditionals(struct cond_entry *conds);
public:
	int mode;
	int audit;
	int deny;

	userns_rule(int mode, struct cond_entry *conds);
	virtual ~userns_rule()
	{
	};

	virtual ostream &dump(ostream &os);
	virtual int expand_variables(void);
	virtual int gen_policy_re(Profile &prof);
	virtual void post_process(Profile &prof unused) { };

protected:
	virtual void warn_once(const char *name) override;
};

#endif /* __AA_USERNS_H */
