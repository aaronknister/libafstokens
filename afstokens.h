#ifndef MAXKTCNAMELEN
#define MAXKTCNAMELEN 256
#endif

#define DATABASE "afs_token_cache"
#define DB_HOME "/tmp/atc"

#include <afs/stds.h>
#include <afs/auth.h>
#include <afs/dirpath.h>
#include <rx/rxkad.h>
#include "logging.h"

#define AFSTOKENCACHE_MAXERRLEN 1024
#define FUDGETIME (5 * 60)
#define MAX_TOKEN_AGE (6 * 60 * 60) + FUDGETIME
#define PACKAGE_NAME "libafstokens"

char afs_token_cache_errmsg[AFSTOKENCACHE_MAXERRLEN];
int afs_token_cache_errno;

void (*atc_log_func)();

struct afs_auth_creds {
	struct ktc_token token;
 	struct ktc_principal client;
	struct ktc_principal server;
};

