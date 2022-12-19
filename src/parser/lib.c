/*
 *   Copyright (c) 2012
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
 *   along with this program; if not, contact Novell, Inc. or Canonical,
 *   Ltd.
 */

#include "lib.h"
#include "parser.h"

#include <ctype.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <sys/apparmor_private.h>

/**
 * isodigit - test if a character is an octal digit
 * @c: character to test
 *
 * Returns: true if an octal digit, else false
 */
int isodigit(char c)
{
	return (c >= '0' && c <= '7') ? true : false;
}

/* convert char character 0..9a..z into a number 0-35
 *
 * Returns: digit value of character or -1 if character is invalid
 */
static int chrtoi(char c, int base)
{
	int val = -1;

	if (base < 2 || base > 36)
		return -1;

	if (isdigit(c))
		val = c - '0';
	else if (isalpha(c) && isascii(c))
		val = tolower(c) - 'a' + 10;

	if (val >= base)
		return -1;

	return val;
}

/**
 * strntol - convert a sequence of characters as a hex number
 * @str: pointer to a string of character to convert
 * @endptr: RETURNS: if not NULL, the first char after converted chars.
 * @base: base of convertion
 * @maxval: maximum value. don't consume next char if value will exceed @maxval
 * @n: maximum number of characters to consume doing the conversion
 *
 * Returns: converted number. If there is no conversion 0 is returned and
 *          *@endptr = @str
 *
 * Not a complete replacement for strtol yet, Does not process base prefixes,
 * nor +/- sign yet.
 *
 * - take the largest sequence of character that is in range of 0-@maxval
 * - will consume the minimum of @maxlen or @base digits in @maxval
 * - if there is not n valid characters for the base only the n-1 will be taken
 *   eg. for the sequence string 4z with base 16 only 4 will be taken as the
 *   hex number
 */
long strntol(const char *str, const char **endptr, int base, long maxval,
	     size_t n)
{
	long c, val = 0;

	if (base > 1 && base < 37) {
		for (; n && (c = chrtoi(*str, base)) != -1; str++, n--) {
			long tmp = (val * base) + c;
			if (tmp > maxval)
				break;
			val = tmp;
		}
	}

	if (endptr)
		*endptr = str;

	return val;
}

size_t min(size_t a, size_t b) {
	return (a <= b)? a : b;
} 

/**
 * strn_escseq -
 * @pos: position of first character in esc sequence
 * @chrs: list of exact return chars to support eg. \+ returns + instead of -1
 * @n: maximum length of string to processes
 *
 * Returns: character for escape sequence or -1 if an error
 *
 * pos will point to first character after esc sequence
 * OR
 * pos will point to first character where an error was discovered
 * errors can be unrecognized esc character, octal, decimal, or hex
 * character encoding with no valid number. eg. \xT
 */
int strn_escseq(const char **pos, const char *chrs, size_t n)
{
	const char *end;
	long tmp;

	if (n < 1)
		return -1;

	if (isodigit(**pos)) {
		tmp = strntol(*pos, &end, 8, 255, min((size_t) 3, n));
		if (tmp == 0 && end == *pos) {
			/* this should never happen because of isodigit test */
			return -1;
		}
		*pos = end;
		return tmp;
	}

	char c = *(*pos)++;
	switch(c) {
	case '\\':
		return '\\';
	case '"':
		return '"';
	case 'd':
		tmp = strntol(*pos, &end, 10, 255, min((size_t) 3, n));
		if (tmp == 0 && end == *pos) {
			/* \d no valid encoding */
			return -1;
		}
		*pos = end;
		return tmp;
	case 'x':
		tmp = strntol(*pos, &end, 16, 255, min((size_t) 2, n));
		if (tmp == 0 && end == *pos) {
			/* \x no valid encoding */
			return -1;
		}
		*pos = end;
		return tmp;
	case 'a':
		return '\a';
	case 'e':
		return 033  /* ESC */;
	case 'f':
		return '\f';
	case 'n':
		return '\n';
	case 'r':
		return '\r';
	case 't':
		return '\t';
	}

	if (strchr(chrs, c))
		return c;

	/* unsupported escape sequence, backup to return that char */
	pos--;
	return -1;
}
