#ifndef _LOG_MSG_H
#define _LOG_MSG_H 1

#include <syslog.h>

extern int debug_flag;
extern int logfile_flag;

extern void log_msg (int type, const char *, ...);
extern void close_logfile (void);
extern void log2file (const char *);

#endif
