#include <syslog.h>
#define LOG_LEVEL LOG_NOTICE

#define atc_log_debug(format, ...) atc_log_msg(LOG_DEBUG, __FILE__, __FUNCTION__, format, ##__VA_ARGS__)
#define atc_log_info(format, ...) atc_log_msg(LOG_INFO, __FILE__, __FUNCTION__, format, ##__VA_ARGS__)
#define atc_log_warn(format, ...) atc_log_msg(LOG_WARNING, __FILE__, __FUNCTION__, format, ##__VA_ARGS__)
#define atc_log_err(format, ...) atc_log_msg(LOG_ERR, __FILE__, __FUNCTION__, format, ##__VA_ARGS__)
#define atc_log_notice(format, ...) atc_log_msg(LOG_NOTICE, __FILE__, __FUNCTION__, format, ##__VA_ARGS__)
