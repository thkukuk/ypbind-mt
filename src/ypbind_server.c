/* Copyright (c) 1998, 1999, 2000, 2001, 2006, 2009, 2014 Thorsten Kukuk, Germany
   This file is part of ypbind-mt.
   Author: Thorsten Kukuk <kukuk@suse.de>

   The ypbind-mt are free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License version 2
   as published by the Free Software Foundation.

   ypbind-mt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.  */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rpc/rpc.h>

#include "ypbind.h"
#include "log_msg.h"
#include "local.h"

#ifndef _
#define _(String) gettext (String)
#endif

bool_t
ypbindproc_oldnull_1_svc (void *argp __attribute__ ((unused)), void *result,
			  struct svc_req *rqstp)
{
  if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	  svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char *uaddr = taddr2uaddr (nconf, rqhost);
	  log2file ("ypbindproc_oldnull_1 from %s", uaddr);
	  free (uaddr);
	}
    }

  memset (result, 0, sizeof (char *));
  return TRUE;
}

bool_t
ypbindproc_null_2_svc (void *argp __attribute__ ((unused)), void *result,
		       struct svc_req *rqstp)
{
  if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	  svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char *uaddr = taddr2uaddr (nconf, rqhost);
	  log2file ("ypbindproc_null_2 from %s", uaddr);
	  free (uaddr);
	}
    }

  memset (result, 0, sizeof (char *));
  return TRUE;
}

bool_t
ypbindproc_null_3_svc (void *argp __attribute__ ((unused)), void *result,
		       struct svc_req *rqstp)
{
  if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char *uaddr = taddr2uaddr (nconf, rqhost);
	  log2file ("ypbindproc_null_3 from %s", uaddr);
	  free (uaddr);
	}
    }

  memset (result, 0, sizeof (char *));
  return TRUE;
}

static bool_t
ypbindproc_domain (char *domain_name, ypbind2_resp *result)
{
  memset (result, 0, sizeof (ypbind2_resp));
  result->ypbind_status = YPBIND_FAIL_VAL;
  result->ypbind_respbody.ypbind_error = YPBIND_ERR_NOSERV;

  if (strchr (domain_name, '/'))
    {
      log_msg (LOG_ERR, _("Domain name '%s' has embedded slash -- rejecting."),
	       domain_name);
      return TRUE;
    }

  test_bindings_once (1, domain_name);
  find_domain (domain_name, result);

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
ypbindproc_olddomain_1_svc (domainname *argp, ypbind2_resp *result,
			    struct svc_req *rqstp)
{
  if (debug_flag || logfile_flag)
    {
      char *uaddr = NULL;
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	{
	  svcerr_systemerr (rqstp->rq_xprt);
	  uaddr = strdup ("getnetconfigent error");
	}
      else
	uaddr = taddr2uaddr (nconf, rqhost);

      if (debug_flag)
	log_msg (LOG_DEBUG, "ypbindproc_olddomain_1_svc (%s,%s)",
		 *argp, uaddr);

      if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
	log2file ("ypbindproc_olddomain_1 (%s) from %s",
		  *argp, uaddr);

      if (uaddr)
	free (uaddr);
    }

  return ypbindproc_domain (*argp, result);
}

bool_t
ypbindproc_domain_2_svc (domainname *argp, ypbind2_resp *result,
			 struct svc_req *rqstp)
{
  if (debug_flag || logfile_flag)
    {
      char *uaddr = NULL;
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	{
	  svcerr_systemerr (rqstp->rq_xprt);
	  uaddr = strdup ("getnetconfigent error");
	}
      else
	uaddr = taddr2uaddr (nconf, rqhost);

      if (debug_flag)
	log_msg (LOG_DEBUG, "ypbindproc_domain_2_svc (%s,%s)",
		 *argp, uaddr);

      if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
	log2file ("ypbindproc_domain_2 (%s) from %s",
		  *argp, uaddr);

      if (uaddr)
	free (uaddr);
    }


  return ypbindproc_domain (*argp, result);
}


bool_t
ypbindproc_domain_3_svc (domainname *argp, ypbind3_resp *result,
			 struct svc_req *rqstp)
{
  if (debug_flag || logfile_flag)
    {
      char *uaddr = NULL;
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	{
	  svcerr_systemerr (rqstp->rq_xprt);
	  uaddr = strdup ("getnetconfigent error");
	}
      else
	uaddr = taddr2uaddr (nconf, rqhost);

      if (debug_flag)
	log_msg (LOG_DEBUG, "ypbindproc_domain_3_svc (%s,%s)",
		 *argp, uaddr);

      if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
	log2file ("ypbindproc_domain_3 (%s) from %s",
		  *argp, uaddr);

      if (uaddr)
	free (uaddr);
    }

  memset (result, 0, sizeof (ypbind3_resp));
  result->ypbind_status = YPBIND_FAIL_VAL;
  result->ypbind_respbody.ypbind_error = YPBIND_ERR_NOSERV;

  if (strchr (*argp, '/'))
    {
      log_msg (LOG_ERR, _("Domain name '%s' has embedded slash -- rejecting."),
	       *argp);
      return TRUE;
    }

#if 0 /* XXX */
  test_bindings_once (1, domain_name);
  find_domain (domain_name, result);
#endif

  if (debug_flag)
    {
      if (result->ypbind_status == YPBIND_FAIL_VAL)
	log_msg (LOG_DEBUG, _("Status: YPBIND_FAIL_VAL"));
      else
	log_msg (LOG_DEBUG, _("Status: YPBIND_SUCC_VAL"));
    }
  return TRUE;

}

static bool_t
ypbindproc_setdom (const char *domain_name, ypbind2_binding *binding,
		   struct netbuf *fromhost)
{
  struct sockaddr *sap = (struct sockaddr *)(fromhost->buf);

  if (strchr (domain_name, '/'))
    {
      log_msg (LOG_ERR, _("Domain name '%s' has embedded slash -- rejecting."),
	       domain_name);
      return TRUE;
    }

  switch(sap->sa_family)
    {
    case AF_INET:
      {
	struct sockaddr_in *sin = (struct sockaddr_in *) sap;

	switch(ypset)
	  {
	  case SET_YPSETME:
	    if (sin->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
	      {
		if (debug_flag)
		  log_msg (LOG_DEBUG,
			   _("User from '%s' try's to change the binding."),
			   inet_ntoa (sin->sin_addr));
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
	if (ntohs (sin->sin_port) >= IPPORT_RESERVED)
	  {
	    log_msg (LOG_ERR,
		     _("SETDOM request doesn't come from reserved port."));
	    return TRUE;
	  }
      }
      break;
    case AF_INET6:
      {
	static const unsigned char localhost_bytes[] =
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	static const unsigned char mapped_ipv4_localhost[] =
	  { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1 };
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *) sap;

	switch(ypset)
	  {
	  case SET_YPSETME:
	    if (memcmp(sin->sin6_addr.s6_addr, localhost_bytes, 16) != 0 &&
		memcmp(sin->sin6_addr.s6_addr, mapped_ipv4_localhost, 16) != 0)
	      {
		if (debug_flag)
		  {
		    char buf[INET6_ADDRSTRLEN];

		    if (inet_ntop(AF_INET6, &(sin->sin6_addr),
				  buf, sizeof(buf)) != NULL)
		      log_msg (LOG_DEBUG,
			       _("User from '%s' try's to change the binding."),
			       buf);
		  }
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
	if (ntohs (sin->sin6_port) >= IPPORT_RESERVED)
	  {
	    log_msg (LOG_ERR,
		     _("SETDOM request doesn't come from reserved port."));
	    return TRUE;
	  }
      }
      break;
    }

  change_binding (domain_name, binding);

  return TRUE;
}

bool_t
ypbindproc_oldsetdom_1_svc (ypbind_oldsetdom *argp, void *result,
			    struct svc_req *rqstp)
{
  if (debug_flag)
    log_msg (LOG_DEBUG, "ypbindproc_oldsetdom_1_svc (%s)",
	     argp->ypoldsetdom_domain);

  if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  uint16_t port;
	  char *uaddr = taddr2uaddr (nconf, rqhost);
	  port = ntohs(argp->ypoldsetdom_binding.ypbind_binding_port);
	  log2file ("ypbindproc_oldsetdom_1 (%s:%s:%d) from %s",
		    *argp->ypoldsetdom_domain,
		    inet_ntoa (argp->ypoldsetdom_binding.ypbind_binding_addr),
		    port, uaddr);
	  free (uaddr);
	}
    }

  memset (result, 0, sizeof (char *));

  return ypbindproc_setdom (argp->ypoldsetdom_domain,
			    &argp->ypoldsetdom_binding,
			    svc_getrpccaller (rqstp->rq_xprt));
}

bool_t
ypbindproc_setdom_2_svc (ypbind2_setdom *argp, void *result,
			 struct svc_req *rqstp)
{
  if (debug_flag)
    log_msg (LOG_DEBUG, "ypbindproc_setdom_2_svc (%s)",
	     argp->ypsetdom_domain);

  if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  uint16_t port;
	  char *uaddr = taddr2uaddr (nconf, rqhost);
	  port = ntohs (argp->ypsetdom_binding.ypbind_binding_port);
	  log2file ("ypbindproc_setdom_2 (%s:%s:%d) from %s",
		    *argp->ypsetdom_domain,
		    inet_ntoa (argp->ypsetdom_binding.ypbind_binding_addr),
		    port, uaddr);
	  free (uaddr);
	}
    }

  memset (result, 0, sizeof (char *));

  return ypbindproc_setdom (argp->ypsetdom_domain,
			    &argp->ypsetdom_binding,
			    svc_getrpccaller (rqstp->rq_xprt));
}

bool_t
ypbindproc_setdom_3_svc (ypbind3_setdom *argp, void *result,
			 struct svc_req *rqstp)
{
  if (debug_flag)
    log_msg (LOG_DEBUG, "ypbindproc_setdom_3_svc (%s)",
	     argp->ypsetdom_domain);

#if 0 /* XXX */
  if (logfile_flag && (logfile_flag & LOG_RPC_CALLS))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  uint16_t port;
	  char *uaddr = taddr2uaddr (nconf, rqhost);
	  port = ntohs (argp->ypsetdom_binding.ypbind_binding_port);
	  log2file ("ypbindproc_setdom_3 (%s:%s:%d) from %s",
		    *argp->ypsetdom_domain,
		    inet_ntoa (argp->ypsetdom_binding.ypbind_binding_addr),
		    port, uaddr);
	  free (uaddr);
	}
    }
#endif

  memset (result, 0, sizeof (char *));

#if 0 /* XXX */
  return ypbindproc_setdom (argp->ypsetdom_domain,
			    &argp->ypsetdom_binding,
			    svc_getrpccaller (rqstp->rq_xprt));
#else
  return TRUE;
#endif
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

int
ypbindprog_3_freeresult (SVCXPRT *transp __attribute__ ((unused)),
			 xdrproc_t xdr_result, caddr_t result)
{
  xdr_free (xdr_result, result);

  return 1;
}
