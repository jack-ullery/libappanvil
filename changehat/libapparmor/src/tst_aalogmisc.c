#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "aalogparse.h"
#include "parser.h"


#define MY_TEST(statement, error)               \
	if (!(statement)) {                     \
		fprintf(stderr, "FAIL: %s\n", error); \
		rc = 1; \
	}

int main(void)
{
	int rc = 0;
	char *retstr = NULL;

	retstr = hex_to_string(NULL);
	MY_TEST(!retstr, "basic NULL test");

	retstr = hex_to_string("2F746D702F646F6573206E6F74206578697374");
	MY_TEST(retstr, "basic allocation");
	MY_TEST(strcmp(retstr, "/tmp/does not exist") == 0, "basic dehex 1");

	retstr = hex_to_string("61");
	MY_TEST(strcmp(retstr, "a") == 0, "basic dehex 2");

	retstr = hex_to_string("");
	MY_TEST(strcmp(retstr, "") == 0, "empty string");

	return rc;
}


