/*
   Copyright 2017 Canonical, Ltd.
   Author: Steve Beattie <steve.beattie@canonical.com>
   License: GPLv3

   Report whether a passed environment variable is defined
*/

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[])
{
	char *query_env = NULL;
	int rc = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s ENV_VAR\n\n", argv[0]);
		fprintf(stderr, "  Returns error if ENV_VAR is not\n");
		fprintf(stderr, "  a defined environment variable.\n");
		exit(1);
	}

	query_env = argv[1];

	if (getenv(query_env) == NULL) {
		printf("Env var '%s' is not defined\n", query_env);
		rc = 1;
	} else {
		printf("Env var '%s' is set\n", query_env);
	}

	return rc;

}
