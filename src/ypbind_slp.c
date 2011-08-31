/* Copyright (c) 2004 Thorsten Kukuk
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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#ifdef USE_SLP

#include <slp.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <rpc/rpc.h>

#include "ypbind.h"
#include "local.h"
#include "log_msg.h"

#ifndef _
#define _(String) gettext (String)
#endif

/* Ask SLP server for ypserv service.  */

struct slpcb {
  char *srvurl;
  SLPError err;
  struct slpcb *next;
};

static SLPBoolean
MySLPSrvURLCallback (SLPHandle hslp __attribute__((unused)),
                     const char *srvurl,
                     unsigned short lifetime __attribute__((unused)),
                     SLPError errcode, void *cookie)
{
  struct slpcb *cb = (struct slpcb *) cookie;

  if (errcode == SLP_OK)
    {
      if (cb->srvurl != NULL)
	{
	  struct slpcb *cbt = malloc (sizeof (struct slpcb));
	  if (cbt == NULL)
	    return SLP_FALSE;

	  cbt->srvurl = cb->srvurl;
	  cbt->err = cb->err;
	  cbt->next = cb->next;
	  cb->next = cbt;
	}
      cb->srvurl = strdup (srvurl);
      cb->err = SLP_OK;
      return SLP_TRUE;
    }
  else if (errcode != SLP_LAST_CALL)
    cb->err = errcode;

  return SLP_FALSE; /* We don't wan't to be called again.  */
}

int
query_slp (const char *domain)
{
  struct slpcb *cb, callbackres = {NULL, 0, NULL};
  SLPError err;
  SLPHandle hslp;
  int found = 0;

  err = SLPOpen ("en", SLP_FALSE, &hslp);
  if (err != SLP_OK)
    {
      log_msg (LOG_ERR, _("Error opening SLP handle: %i."), err);
      return 0;
    }

  err = SLPFindSrvs (hslp, "ypserv", 0, 0,
                     MySLPSrvURLCallback, &callbackres);

  /* err may contain an error code that occurred as the slp library
     _prepared_ to make the call.  */
  if (err != SLP_OK || callbackres.err != SLP_OK)
    {
      log_msg (LOG_ERR, _("No service found with SLP."));
      return 0;
    }

  /* Now that we're done using slp, close the slp handle */
  SLPClose (hslp);

  cb = &callbackres;
  while (cb != NULL)
    {
      if (cb->srvurl != NULL)
	{
	  char *hostp = strstr (cb->srvurl, "://");
	  char *cp;

	  if (!hostp || strlen(hostp) < strlen("://") + 1)
	    {
	      free (cb->srvurl);
	      continue;
	    }
	  
	  hostp += strlen ("://");

	  cp = strrchr (hostp, '/');
	  if (cp)
	    *cp = '\0';

	  /* Remove any port specification (we should use it!). */
	  cp = strchr (hostp, ':');
	  if (cp)
	    *cp = '\0';

	  if (add_server (domain, hostp, 0))
	    {
	      log_msg (LOG_INFO, "SLP: found server %s for domain %s.",
		       hostp, domain);
	      found++;
	    }
	  /* Free memory. */
	  free (cb->srvurl);
	}
      cb = cb->next;
    }
  return found;
}

#endif
