/* Copyright (c) 1998, 1999 Thorsten Kukuk, Germany

   This file is part of ypbind-mt.

   Author: Thorsten Kukuk <kukuk@suse.de>

   The ypbind-mt are free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   ypbind-mt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with ypbind-mt; see the file COPYING.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA. */

#ifndef _PTHREAD_NP_H
#define _PTHREAD_NP_H

#include <pthread.h>

typedef struct {
  int readers;
  int writers;
  int wishwrite;
  pthread_mutex_t mutex;
  pthread_cond_t lock_free;
} pthread_rdwr_t;

#define PTHREAD_RDWR_INITIALIZER \
         {0, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER}

int pthread_rdwr_init_np (pthread_rdwr_t *rdwrp);
int pthread_rdwr_rlock_np (pthread_rdwr_t *rdwrp);
int pthread_rdwr_wlock_np (pthread_rdwr_t *rdwrp);
int pthread_rdwr_runlock_np (pthread_rdwr_t *rdwrp);
int pthread_rdwr_wunlock_np (pthread_rdwr_t *rdwrp);

#endif
