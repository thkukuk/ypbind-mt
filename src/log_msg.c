/* Copyright (c) 2000 Thorsten Kukuk
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
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include "log_msg.h"

int debug_flag = 0;

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
