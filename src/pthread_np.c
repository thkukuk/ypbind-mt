/* Copyright (c) 1998, 1999, 2000 Thorsten Kukuk, Germany

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

#include <pthread.h>
#include <pthread_np.h>

int
pthread_rdwr_init_np (pthread_rdwr_t *rdwrp)
{
  rdwrp->readers = 0;
  rdwrp->writers = 0;
  rdwrp->wishwrite = 0;
  pthread_mutex_init (&(rdwrp->mutex), NULL);
  pthread_cond_init (&(rdwrp->lock_free), NULL);
  return 0;
}

int
pthread_rdwr_rlock_np (pthread_rdwr_t *rdwrp)
{
  pthread_mutex_lock (&(rdwrp->mutex));

  while (rdwrp->writers || rdwrp->wishwrite)
    pthread_cond_wait (&(rdwrp->lock_free), &(rdwrp->mutex));

  rdwrp->readers++;
  pthread_mutex_unlock (&(rdwrp->mutex));
  return 0;
}

int
pthread_rdwr_wlock_np (pthread_rdwr_t *rdwrp)
{
  pthread_mutex_lock (&(rdwrp->mutex));
  rdwrp->wishwrite++;
  while (rdwrp->writers || rdwrp->readers)
    pthread_cond_wait (&(rdwrp->lock_free), &(rdwrp->mutex));
  rdwrp->writers++;
  rdwrp->wishwrite--;
  pthread_mutex_unlock (&(rdwrp->mutex));
  return 0;
}

int
pthread_rdwr_runlock_np (pthread_rdwr_t *rdwrp)
{
  int status;

  pthread_mutex_lock (&(rdwrp->mutex));
  if (rdwrp->readers == 0)
    {
      status = -1;
    }
  else
    {
      rdwrp->readers--;
      if (rdwrp->readers == 0)
       pthread_cond_signal (&(rdwrp->lock_free));
      status = 0;
    }
  pthread_mutex_unlock (&rdwrp->mutex);
  return status;
}

int
pthread_rdwr_wunlock_np (pthread_rdwr_t *rdwrp)
{
  int status;

  pthread_mutex_lock (&(rdwrp->mutex));
  if (rdwrp->writers == 0)
    {
      status = -1;
    }
  else
    {
      rdwrp->writers = 0;
      pthread_cond_broadcast (&(rdwrp->lock_free));
      status = 0;
    }
  pthread_mutex_unlock (&(rdwrp->mutex));
  return status;
}
