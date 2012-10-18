// vim: number
#include <unistd.h>
#include <krb5.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
//include "afstokens.h"

extern *atc_log_func;
extern char afs_token_cache_errmsg[1035];

void log_callback(int level, const char *fmt, va_list args) {
		printf("here\n");
                vfprintf(stderr,fmt, args);
} 

int main() {
	char username[]="aaronk/cgi";
	char cell[]="umbc.edu";
	char keytab[]="/tmp/umbc_cgi.keytab";
	int ret;

	atc_log_func=log_callback;
	ret=afstokens_get_token(username,cell,keytab);

	printf("ret:%d\n",ret);

	if ( ret ) {
		printf("errmsg: %s\n",afs_token_cache_errmsg);
	}

	return ret;

}
