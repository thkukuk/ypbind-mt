/* Copyright (c) 2000, 2002, 2006, 2009 Thorsten Kukuk
   This file is part of ypbind-mt.
   Author: Thorsten Kukuk <kukuk@suse.de>

   The ypbind-mt are free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License version 2
   as published by the Free Software Foundation.

   ypbind-mt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with ypbind-mt; see the file COPYING.  If not,
   write to the Free Software Foundation, Inc., 51 Franklin Street - Suite 500,
   Boston, MA 02110-1335, USA. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _GNU_SOURCE

#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include "log_msg.h"

#include <sys/syscall.h>
#ifdef __NR_gettid
static pid_t
gettid (void)
{
  return syscall (__NR_gettid);
}
#else
pid_t
gettid (void)
{
    return getpid ();
}
#endif

int debug_flag = 0;
int logfile_flag = 0;

void
log_msg (int type, const char *fmt,...)
{
  va_list ap;
#ifndef HAVE_VSYSLOG
  char msg[512];
#endif

  va_start (ap, fmt);

  if (debug_flag)
    {
      fprintf (stderr, "%d: ", gettid ());
      vfprintf (stderr, fmt, ap);
      fputc ('\n', stderr);
    }
  else
    {
#ifndef HAVE_VSYSLOG
      vsnprintf (msg, 512, fmt, ap);
      syslog (type, "%s", msg);
#else
      vsyslog (type, fmt, ap);
#endif
    }

  va_end (ap);
}

static FILE *logfp = NULL;
static const char *logfilename = "/var/log/ypbind-mt.log";

void
close_logfile (void)
{
  if (logfp == NULL)
    return;

  fclose (logfp);
  logfp = NULL;
}

static int
open_logfile (void)
{
  if (logfp != NULL)
    close_logfile();

  if ((logfp = fopen (logfilename, "a+")) == NULL)
    {
      log_msg (LOG_ERR, "Cannot open log file '%s': %m",
	       logfilename);
      return 1;
    }
  return 0;
}

void
log2file (const char *fmt,...)
{
  va_list ap;
  char date[128];
  time_t tmp;
  struct tm *t;

  if (logfp == NULL)
    {
      if (open_logfile () != 0)
	return;
    }

  tmp = time (NULL);
  t = localtime (&tmp);
  strftime (date, sizeof (date), "%F %T", t);

  va_start (ap, fmt);

  fprintf (logfp, "%s (%d): ", date, gettid ());
  vfprintf (logfp, fmt, ap);
  fputc ('\n', logfp);
  fflush (logfp);

  va_end (ap);
}
