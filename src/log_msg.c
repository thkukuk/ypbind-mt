/* Copyright (c) 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Thorsten Kukuk <kukuk@vt.uni-paderborn.de>, 1998.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA. */

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
  char msg[512];

  va_start (ap, fmt);
  vsnprintf (msg, sizeof (msg), fmt, ap);

  if (debug_flag)
    {
      fputs (msg, stderr);
      fputs ("\n", stderr);
    }
  else
    syslog (type, msg);

  va_end (ap);
}
