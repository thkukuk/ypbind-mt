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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rpc/rpc.h>
#if defined(HAVE_RPC_SVC_SOC_H)
#include <rpc/svc_soc.h>
#endif

#include "ypbind.h"
#include "log_msg.h"
#include "local.h"

#ifndef _
#define _(String) gettext (String)
#endif

bool_t
ypbindproc_oldnull_1_svc (void *argp __attribute__ ((unused)), void *result,
			  struct svc_req *rqstp __attribute__ ((unused)))
{
  memset (result, 0, sizeof (char *));
  return TRUE;
}

bool_t
ypbindproc_null_2_svc (void *argp __attribute__ ((unused)), void *result,
		       struct svc_req *rqstp __attribute__ ((unused)))
{
  memset (result, 0, sizeof (char *));
  return TRUE;
}

static bool_t
ypbindproc_domain (char *domain, ypbind_resp *result,
		   struct svc_req *rqstp __attribute__ ((unused)))
{
  memset (result, 0, sizeof (ypbind_resp));
  result->ypbind_status = YPBIND_FAIL_VAL;
  result->ypbind_resp_u.ypbind_error = YPBIND_ERR_NOSERV;

  if (strchr (domain, '/'))
    {
      log_msg (LOG_ERR, _("Domain name '%s' has embedded slash -- rejecting."),
	       domain);
      return TRUE;
    }

  find_domain (domain, result);

  if (debug_flag)
    {
      if (result->ypbind_status == YPBIND_FAIL_VAL)
	log_msg (LOG_DEBUG, _("Status: YPBIND_FAIL_VAL"));
      else
	log_msg (LOG_DEBUG, _("Status: YPBIND_SUCC_VAL"));
    }
  return TRUE;
}

bool_t
ypbindproc_olddomain_1_svc (olddomainname *argp, ypbind_resp *result,
			    struct svc_req *rqstp)
{
  if (debug_flag)
    log_msg (LOG_DEBUG, "ypbindproc_olddomain_1_svc (%s)", argp);

  return ypbindproc_domain (argp, result, rqstp);
}

bool_t
ypbindproc_domain_2_svc (domainname *argp, ypbind_resp *result,
			 struct svc_req *rqstp)
{
  if (debug_flag)
    log_msg (LOG_DEBUG, "ypbindproc_domain_2_svc (%s)", *argp);

  return ypbindproc_domain (*argp, result, rqstp);
}

static bool_t
ypbindproc_setdom (const char *domain, ypbind_binding *binding,
		   struct sockaddr_in *fromhost)
{
  if (strchr (domain, '/'))
    {
      log_msg (LOG_ERR, _("Domain name '%s' has embedded slash -- rejecting."),
	       domain);
      return TRUE;
    }

  switch(ypset)
    {
    case SET_YPSETME:
      if (fromhost->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG,
		     _("User from '%s' try's to change the binding."),
		     inet_ntoa (fromhost->sin_addr));
	  return TRUE;
	}
      break;
    case SET_YPSET:
      break;
    case SET_NO:
    default:
      log_msg (LOG_ERR, _("Changing the binding is not allowed."));
      return TRUE;
    }
  if (ntohs (fromhost->sin_port) >= IPPORT_RESERVED)
    {
      log_msg (LOG_ERR, _("SETDOM request doesn't come from reserved port."));
      return TRUE;
    }

  change_binding (domain, binding);

  return TRUE;
}

bool_t
ypbindproc_oldsetdom_1_svc (ypbind_oldsetdom *argp, void *result,
			    struct svc_req *rqstp)
{
  if (debug_flag)
    log_msg (LOG_DEBUG, "ypbindproc_oldsetdom_1_svc (%s)",
	     argp->ypoldsetdom_domain);

  memset (result, 0, sizeof (char *));

  return ypbindproc_setdom (argp->ypoldsetdom_domain,
			    &argp->ypoldsetdom_binding,
			    svc_getcaller (rqstp->rq_xprt));
}

bool_t
ypbindproc_setdom_2_svc (ypbind_setdom *argp, void *result,
			 struct svc_req *rqstp)
{
  if (debug_flag)
    log_msg (LOG_DEBUG, "ypbindproc_setdom_2_svc (%s)",
	     argp->ypsetdom_domain);

  memset (result, 0, sizeof (char *));

  return ypbindproc_setdom (argp->ypsetdom_domain,
			    &argp->ypsetdom_binding,
			    svc_getcaller (rqstp->rq_xprt));
}

int
ypbindprog_1_freeresult (SVCXPRT *transp __attribute__ ((unused)),
			 xdrproc_t xdr_result, caddr_t result)
{
  xdr_free (xdr_result, result);

  return 1;
}

int
ypbindprog_2_freeresult (SVCXPRT *transp __attribute__ ((unused)),
			 xdrproc_t xdr_result, caddr_t result)
{
  xdr_free (xdr_result, result);

  return 1;
}
