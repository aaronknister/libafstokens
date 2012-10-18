// vim: number
#include <unistd.h>
#include <krb5.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "afstokens.h"

int afstokens_get_token(char *username, char* cell, char *keytab) {

	krb5_context context;
	krb5_error_code krb5err;
	struct afs_auth_creds afscreds;
	krb5_creds *krb5spcreds;
	krb5_get_init_creds_opt krb5opts;
	krb5_principal krb5serviceprinc;
	char *name;
	char err_msg[1024];
	int get_new_creds=1;
	int ret=0;
	time_t curTime;

	setvbuf(stdout, NULL, _IONBF, 0);


/*
 * Attempt to read credential structure from database
 */
	int i=0;
	srand(time(NULL));


	for (i=0; i<2; i++ ) {
		ret=db_get_credential(username,&afscreds);
		if ( ! ret ) { get_new_creds=0; break;}
		usleep(rand() % 10);
	}


	if ( ret ) {
		atc_log_info("Failed to retreive credential from database for user '%s'",username);
		/* We failed to retreive a credential from the database */

		//DEBUG: printf("db error: %s\n",afs_token_cache_errmsg);
		/*
		 * Figure out what went wrong and print an error message accordingly
		 */
	} else {
		/* We got a credential from the database */
		if ((time(NULL) + MAX_TOKEN_AGE) > afscreds.token.endTime) {
			atc_log_notice("credentials for user '%s' have fewer than %d seconds left",username,MAX_TOKEN_AGE);
			get_new_creds=1;
		} else { 
			/* If the credentials look ok, double check them */
			if ( (afscreds.token.endTime < 946684800) || (afscreds.token.endTime == 0) ) {
				atc_log_warn("Retreived credentials for user '%s' are invalid",username);
				get_new_creds=1;
			}
		}
	}

	if ( get_new_creds ) {
		atc_log_notice("Obtaining credentials for user '%s'",username);
		// Get a service ticket (krb5spcreds)
		ret=krb5_afs_service_ticket_from_keytab(username,keytab,&krb5spcreds);
		if ( ret ) {
			goto fail;
		}
		// Create an afs_auth_creds struct from the service ticket
		ret=afs_get_auth_creds(krb5spcreds,&afscreds,cell);
		if ( ret ) {
			goto fail;
		}
		// Store the credentials
		db_put_credential(username,afscreds); 
	}

	atc_log_notice("Setting tokens for user '%s'",username);
	ret=afs_set_token(afscreds,err_msg);
	if ( ret ) {
		goto fail;
	}

	return 0;

	fail:
		return 1;


}
