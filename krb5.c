#include <krb5.h>
#include <stdio.h>
#include <string.h>

#include "afstokens.h"

krb5_context context;
krb5_error_code krb5err;

static krb5_error_code _init() {
	if ( ! context ) {
		atc_log_debug("Initializing kerberos context");
		krb5err=krb5_init_context(&context);
		if ( krb5err ) {
			sprintf(afs_token_cache_errmsg,"Unable to initialize krb context: %s",error_message(krb5err));
			atc_log_err(afs_token_cache_errmsg);
			return 1;
		}
	}

	return 0;
}


static krb5_error_code _get_afs_service_ticket(krb5_context context, krb5_ccache krb5ccache, krb5_creds **krb5spcreds) {

	krb5_creds krb5increds;
	krb5_error_code krb5err;
	const char *ccache;

	/*
	 * 2.1 Get an AFS service kerberos ticket
	 */
		
	memset((char *) &krb5increds, 0, sizeof(krb5increds));

	// Get the name of the ccache
	ccache=krb5_cc_get_name(context, krb5ccache);

	// Store the principal name of the service in a principal struct in krb5increds
	atc_log_debug("Parsing krb5 principal name");
	krb5err=krb5_parse_name(context, "afs@UMBC.EDU", &krb5increds.server);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Unable to parse krb5 name '%s': %s","afs@UMBC.EDU",error_message(krb5err));
		goto fail;
	}

	// Get the principal object from the ccache and store in the client attribute in krb5increds
	atc_log_debug("Reading principal name from credentials cache");
	krb5err=krb5_cc_get_principal(context, krb5ccache, &krb5increds.client);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Unable to get principal from krb5 ccache '%s' and store in krb5increds: %s",ccache,error_message(krb5err));
		goto fail;
	}

	krb5increds.times.endtime = 0;
//	krb5increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;

	// Get credentials for the afs service principal and store in the credentials cache
	atc_log_info("Obtaining afs service ticket and storing in credentials cache");
	krb5err=krb5_get_credentials(context, 0, krb5ccache, &krb5increds, krb5spcreds );
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Unable to parse krb5 name '%s': %s","afs@UMBC.EDU",error_message(krb5err));
		goto fail;
	}

	return 0;

	fail:
		atc_log_err(afs_token_cache_errmsg);
		return 1;

}

static krb5_error_code _init_cc_from_keytab(krb5_context context, const char* principal, const char* keytab, const char* ccache, krb5_ccache *krb5ccache) {

	krb5_error_code krb5err;
	krb5_keytab krb5kt;
	krb5_creds krb5_init_creds;
	krb5_principal krb5princ;
	
	/*
	 * 1. Obtain a kerberos ticket from a keytab
	 */


	/*
	 * 1.1 Obtain a TGT
	 */

	// Parse textual principal name and create a krb5princ object
	atc_log_debug("Creating a krb5princ object from the principal name");
	krb5err=krb5_parse_name(context, principal, &krb5princ);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Unable to parse krb5 name '%s'",principal);
		goto fail;
	}

	// Resolve the keytab and store it in the krb5kt struct
	atc_log_debug("Resolving the keytab '%s'",keytab);
	krb5err=krb5_kt_resolve(context, keytab, &krb5kt);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Unable to resolve keytab '%s'",keytab);
		goto fail;
	}

	// Get a tgt from the keytab krb5kt for principal krb5princ and store it in the krb5_init_creds struct
	atc_log_info("Getting initial credentials (TGT) from keytab '%s'",keytab);
	krb5err=krb5_get_init_creds_keytab(context, &krb5_init_creds, krb5princ, krb5kt, 0, NULL, NULL);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Unable to get credentials for principal '%s' from keytab '%s'",principal,keytab);
		goto fail;
	}

		
	/*
	 * 1.2 Store the TGT in a credentials cache
	 */

	// Resolve the credentials cache 
	atc_log_debug("Resolving credentials cache '%s'",ccache);
	krb5err=krb5_cc_resolve(context, ccache, krb5ccache);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Unable to resolve credentials cache '%s'",ccache);
		goto fail;
	}

	// Initialize the credentials cache
	atc_log_debug("Initializing credentials cache '%s'",ccache);
	krb5err=krb5_cc_initialize(context, *krb5ccache, krb5princ);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Unable to initialize credentials cache '%s'",ccache);
		goto fail;
	}

	// Store the obtained krb5_init_creds in the credentials cache
	atc_log_info("Storing initial credentials in credentials cache '%s'",ccache);
	krb5err=krb5_cc_store_cred(context, *krb5ccache, &krb5_init_creds);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg, "Unable to store credentials in credentials cache '%s'",ccache);
		goto fail;
	}

	return 0;

	fail:
		atc_log_err(afs_token_cache_errmsg);
		return 1;
}

int krb5_service_ticket_user(const krb5_creds *krb5spcreds, char *username, int username_size) {

	char buf[1024];
	int buflen=0;
	int ret=0;
	// Build the name by copying the client (princ) name from the ticket
	memmove( buf, krb5spcreds->client->data[0].data, min(krb5spcreds->client->data[0].length, MAXKTCNAMELEN -1 ));
	buf[krb5spcreds->client->data[0].length] = '\0';

	// If the name has an extra component (foo.bar) then pull it from the service ticket and append
	// 	to the buffer
	if ( krb5spcreds->client->length > 1 ) {
		strncat(buf, ".", sizeof(buf) - strlen(buf) - 1);
		buflen = strlen(buf);
		memmove(buf + buflen, krb5spcreds->client->data[1].data,
		min(krb5spcreds->client->data[1].length,
		MAXKTCNAMELEN - strlen(buf) - 1));
		buf[buflen + krb5spcreds->client->data[1].length] = '\0';
	}

	if ( strlen(buf) > username_size ) {
		sprintf(afs_token_cache_errmsg,"Failed to retreive user from service ticket: retrieved buffer too large for size of username variable");
		goto fail;
	}

	strncpy(username, buf, username_size);

	return 0;

	fail:
		atc_log_err(afs_token_cache_errmsg);
		return 1;

}

int krb5_afs_service_ticket_from_keytab(const char *kprinc, const char *keytab, krb5_creds **krb5spcreds) {

	char kccache[]="MEMORY:tmpcache";
	krb5_ccache krb5ccache;
	char *err_msg;

	if ( ! context ) {
		_init();
	}

	atc_log_debug("Initializing credentials cache from keytab '%s'",keytab);
	krb5err=_init_cc_from_keytab(context,kprinc,keytab,kccache,&krb5ccache);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Failed to initialize cc from kt: %s",error_message(krb5err));
		goto fail;
	}

	atc_log_info("Obtaining an afs service ticket from credentials cache",keytab);
	krb5err=_get_afs_service_ticket(context,krb5ccache,krb5spcreds);
	if ( krb5err ) {
		sprintf(afs_token_cache_errmsg,"Failed to get afs service ticket from cc: %s",error_message(krb5err));
		goto fail;
	}


	return 0;
	
	fail:
		atc_log_err(afs_token_cache_errmsg);
		return 1;

}
