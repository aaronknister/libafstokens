#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afstokens.h"

void atc_log_msg(int level, const char *file, const char *func,  const char *fmt, ...) {

        va_list args;

        va_start(args,fmt);
	if ( LOG_LEVEL >= level ) {
		//char *fmt2 = (char *)malloc(strlen(PACKAGE_NAME) + strlen(file) + strlen(func) + strlen(fmt) + 15);
		char fmt2[strlen(PACKAGE_NAME) + strlen(file) + strlen(func) + strlen(fmt) + 15];
		sprintf(fmt2, "%s: %s: %s(): %s\n", PACKAGE_NAME, file, func, fmt);
		//vfprintf(stderr,fmt2, args);
		atc_log_func(level, fmt2, args);
	}
        va_end(args);

}

void atc_log_set_callback(void *log_func) {
	atc_log_func=log_func;
}

void atc_log_syslog(int level, const char *fmt, va_list args) {
	openlog(PACKAGE_NAME,LOG_PID,LOG_DAEMON);
	vsyslog(level, fmt, args);
	closelog();
}
