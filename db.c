#include "/usr/include/db.h"
#include <sys/stat.h>
#include "afstokens.h"

DB *dbp;
DB_ENV *dbe;

#define DB_RW 0
#define DB_R0 1

static int _init() {
	int db_ret;
	int ret=0;
	struct stat st;

	/* We would previously not initialize the db environment (namely the locking subsystem) if 
 	 * the request was a read-only request. This caused weird issues if the retreived credential
 	 * was being updated as it was being retrieved
 	 */ 

	atc_log_info("Initializing database handles");

	if(stat(DB_HOME,&st) != 0) {
		sprintf(afs_token_cache_errmsg, "Unable to stat database home '%s'", DB_HOME);
		goto fail;
	}

	/* Create the database environment */
	atc_log_debug("Creating the database environment");
	if ((db_ret = db_env_create(&dbe,0)) != 0) {
		sprintf(afs_token_cache_errmsg, "db_env_create: %s",db_strerror(db_ret));
		goto fail;
	}

	/* Open the database environment */
	atc_log_debug("Opening the database environment");
	if ((db_ret = dbe->open(dbe,DB_HOME,DB_INIT_MPOOL|DB_INIT_CDB|DB_CREATE, 0600)) != 0) {
		sprintf(afs_token_cache_errmsg, "dbe->open: %s",db_strerror(db_ret));
		goto fail;
	}

	/* Create the database handle */
	atc_log_debug("Creating the database handle");
	if ((ret = db_create(&dbp, dbe, 0)) != 0) {
		sprintf(afs_token_cache_errmsg, "db_create: %s", db_strerror(ret));
		goto fail;
	}

	/* Open the database */
	atc_log_debug("Opening the database handle");
	if ((ret = dbp->open(dbp,NULL,DATABASE,NULL,DB_BTREE,DB_CREATE, 0600)) != 0 ) {
		dbp->err(dbp,ret,"%s",DATABASE);
		sprintf(afs_token_cache_errmsg, "dbip->open: %s", db_strerror(ret));
		goto fail;
	}

	return 0;

	fail:
		atc_log_debug(afs_token_cache_errmsg);
		return 1;

}

int db_close() {
	int ret;

	atc_log_info("Cleaning up database handles");
	if ( dbp ) {
		atc_log_debug("Cleaning up the database handle");
		if ((ret=dbp->close(dbp,0))) {
			sprintf(afs_token_cache_errmsg, "dbp->close: %s",db_strerror(ret));
			atc_log_debug(afs_token_cache_errmsg);
		}
	}
	
	if ( dbe ) {
		atc_log_debug("Cleaning up the database environment handle");
		if ((ret=dbe->close(dbe,0))) {
			sprintf(afs_token_cache_errmsg, "dbe->close: %s",db_strerror(ret));
			atc_log_debug(afs_token_cache_errmsg);
		}
	}
}

int db_get_credential(const char *username, struct afs_auth_creds *afscred) {
	DBT key, data;
	char name[1024];
	int db_ret=0;
	int ret=0;

	if (_init()) {
		goto fail;
	}

	/*
	 * key = the principal name
	 * data = the credentials cache object
	 */

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	key.data = username;
	key.size = strlen(username);	


	atc_log_info("Retreiving get credentials  for '%s' from database",username);
	if (db_ret=dbp->get(dbp,NULL,&key,&data,0)) {
		sprintf(afs_token_cache_errmsg, "db->get: %s",db_strerror(db_ret));
		/* If the error is becaue the db wasn't found then don't log an error
		 * log an info message */
		if (db_ret == DB_NOTFOUND) {
			ret=1;
			atc_log_debug(afs_token_cache_errmsg);
			goto cleanup;
		}		
		goto fail;
	}
	atc_log_info("Retreived credentials for '%s' from database",username);

	*afscred=*(struct afs_auth_creds*)(data.data);

	cleanup:
		db_close();
		return ret;

	fail:
		ret=1;
		atc_log_err(afs_token_cache_errmsg);
		goto cleanup;
}


int db_put_credential(const char *username, struct afs_auth_creds afscreds ) {
	DBT key, data;
	char name[1024];
	int db_ret;
	int ret=0;

	if (_init()) {
		goto fail;
	}

	/*
	 * key = the principal name
	 * data = the credentials cache object
	 */

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	key.data = username;
	key.size = strlen(username);	

	data.data=malloc(sizeof(afscreds));
	memmove(data.data,&afscreds,sizeof(afscreds));
	data.size = sizeof(struct afs_auth_creds);
	
	atc_log_info("Attempting to cache credentials for '%s' in database",username);
	if (db_ret=dbp->put(dbp,NULL,&key,&data,0)) {
		sprintf(afs_token_cache_errmsg, "dbp->put: %s",db_strerror(db_ret));
		goto fail;
	}

	cleanup:
		db_close();
		return ret;
	
	fail:
		ret=1;
		atc_log_err(afs_token_cache_errmsg);
		goto cleanup;

}

