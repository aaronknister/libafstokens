// vim: number
#include <krb5.h>
//include <stdio.h>
//include <string.h>
//include <afs/stds.h>
//include <afs/auth.h>
//include <afs/dirpath.h>
//include <rx/rxkad.h>
//include "/usr/include/db.h"

#include "afstokens.h"

int afs_get_auth_creds(const krb5_creds *krb5spcreds, struct afs_auth_creds *afscreds, const char *afs_cell) {

 	struct ktc_principal client,server;
 	struct ktc_token token;
	char buf[1024];

	/*
	 * Build the token struct 	
	 */

		memset(&token, 0, sizeof(struct ktc_token)); /* Allocate memory */
		token.startTime = krb5spcreds->times.starttime ? krb5spcreds->times.starttime : krb5spcreds->times.authtime; /* Set the start time on the token */
		token.endTime = krb5spcreds->times.endtime; /* Set the end time on the token */
		memmove( &token.sessionKey, krb5spcreds->keyblock.contents, krb5spcreds->keyblock.length); /* Copy the key to the token from the service ticket */
		token.kvno = RXKAD_TKT_TYPE_KERBEROS_V5; /* yeah i have no idea */
		token.ticketLen = krb5spcreds->ticket.length; /* Set the length of the ticket */
		memmove( token.ticket, krb5spcreds->ticket.data, token.ticketLen);

	/*
	 * Build the client struct
	 */
		//memset(&buf,0,sizeof(buf));
		krb5_service_ticket_user(krb5spcreds,buf,sizeof(buf));
		
		strncpy(client.name,buf, sizeof(client.name) - 1 );
		strncpy(client.instance,"",sizeof(client.instance) - 1 );

		// Get the realm from the service ticket and copy into the client struct
		memmove(buf,krb5spcreds->client->realm.data, min(krb5spcreds->client->realm.length,
								MAXKTCNAMELEN - 1));
		buf[krb5spcreds->client->realm.length] = '\0';
		strncpy(client.cell, buf, sizeof(client.cell) - 1);

	/*
	 * Build the server struct
	 */

		strcpy(server.name,"afs");
		strncpy(server.cell,afs_cell,sizeof(server.cell) - 1 );

	memcpy(&afscreds->token,&token,sizeof(afscreds->token));
	memcpy(&afscreds->client,&client,sizeof(afscreds->client));
	memcpy(&afscreds->server,&server,sizeof(afscreds->server));
	
	return 0;

}


int afs_set_token(struct afs_auth_creds afscreds ) {
	/*
	 * Set tokens in kernel
	 */

	int afs_status;
	char buf[1024];
	int buflen=0;
	afs_int32 viceId;

	/*
	 * Initialize afs? and map the afs user (client.name) to an id
	 */
	atc_log_debug("Initialize afs client?");
	if (afs_status=pr_Initialize(0,AFSDIR_CLIENT_ETC_DIRPATH,afscreds.server.cell)) {
		sprintf(afs_token_cache_errmsg,"Failed to initialize afs stuff for cell '%s'",afscreds.server.cell);
		goto fail;
	}

	atc_log_debug("Mapping username to afs pts id");
	if ( afs_status=afs_status=pr_SNameToId(afscreds.client.name,&viceId)) {
		sprintf(afs_token_cache_errmsg,"Failed to map name '%s' to id",afscreds.client.name);
		goto fail;
	}

 
	/*
	 * Set the token if the afs id is greater than 0 and not anonymous (32766)
	 */
	if ( viceId != 32766 && viceId > 0 ) {
		atc_log_info("Setting afs tokens in kernel for user '%s'", afscreds.client.name);
		afs_status=ktc_SetToken(&afscreds.server, &afscreds.token, &afscreds.client, 0);
		if ( afs_status ) {
			sprintf(afs_token_cache_errmsg, "Failed to set tokens in kernel for user '%s'", afscreds.client.name);
			goto fail;
		}
	} else {
		atc_log_info("User id is either 0 or the afs anonymous id (32766), not setting tokens");
	}
 
	return 0;

	fail:
		atc_log_err(afs_token_cache_errmsg);
		return 1;
}
