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
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];
	  log_msg (LOG_DEBUG, "ypbindproc_oldnull_1 from %s port %i",
		   taddr2ipstr (nconf, rqhost,
				namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));
	  freenetconfigent (nconf);
	}
    }

  memset (result, 0, sizeof (char *));
  return TRUE;
}

bool_t
ypbindproc_null_2_svc (void *argp __attribute__ ((unused)), void *result,
		       struct svc_req *rqstp)
{
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	  svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];
	  log_msg (LOG_DEBUG, "ypbindproc_null_3 from %s port %i",
		   taddr2ipstr (nconf, rqhost,
				namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));
	  freenetconfigent (nconf);
	}
    }

  memset (result, 0, sizeof (char *));
  return TRUE;
}

bool_t
ypbindproc_null_3_svc (void *argp __attribute__ ((unused)), void *result,
		       struct svc_req *rqstp)
{
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];
	  log_msg (LOG_DEBUG, "ypbindproc_null_3 from %s port %i",
		   taddr2ipstr (nconf, rqhost,
				namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));
	  freenetconfigent (nconf);
	}
    }

  memset (result, 0, sizeof (char *));
  return TRUE;
}

static bool_t
ypbindproc_domain_v2 (char *domain_name, ypbind2_resp *result)
{
  memset (result, 0, sizeof (ypbind2_resp));
  result->ypbind_status = YPBIND_FAIL_VAL;
  result->ypbind2_error = YPBIND_ERR_NOSERV;

  if (strchr (domain_name, '/'))
    {
      log_msg (LOG_ERR, _("Domain name '%s' has embedded slash -- rejecting."),
	       domain_name);
      result->ypbind2_error = YPBIND_ERR_NODOMAIN;
      return TRUE;
    }

  if (check_binding (domain_name) != 0)
    return TRUE; /* No server available for domain domain_name */
  find_domain_v2 (domain_name, result);

  if (debug_flag)
    {
      if (result->ypbind_status == YPBIND_FAIL_VAL)
	log_msg (LOG_DEBUG, _("Status: YPBIND_FAIL_VAL, %s"),
		 ypbinderr_string (result->ypbind2_error));
      else
	log_msg (LOG_DEBUG, _("Status: YPBIND_SUCC_VAL"));
    }
  return TRUE;
}

bool_t
ypbindproc_olddomain_1_svc (domainname *argp, ypbind2_resp *result,
			    struct svc_req *rqstp)
{
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];
	  log_msg (LOG_DEBUG, "ypbindproc_olddomain_1_svc (%s) from %s port %i",
		   *argp,
		   taddr2ipstr (nconf, rqhost,
				namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));
	  freenetconfigent (nconf);
	}
    }

  return ypbindproc_domain_v2 (*argp, result);
}

bool_t
ypbindproc_domain_2_svc (domainname *argp, ypbind2_resp *result,
			 struct svc_req *rqstp)
{
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];
	  log_msg (LOG_DEBUG, "ypbindproc_domain_2_svc (%s) from %s port %i",
		   *argp,
		   taddr2ipstr (nconf, rqhost,
				namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));
	  freenetconfigent (nconf);
	}
    }

  return ypbindproc_domain_v2 (*argp, result);
}


bool_t
ypbindproc_domain_3_svc (domainname *argp, ypbind3_resp *result,
			 struct svc_req *rqstp)
{
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];
	  log_msg (LOG_DEBUG, "ypbindproc_domain_3_svc (%s) from %s port %i",
		   *argp,
		   taddr2ipstr (nconf, rqhost,
				namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));
	  freenetconfigent (nconf);
	}
    }

  memset (result, 0, sizeof (ypbind3_resp));
  result->ypbind_status = YPBIND_FAIL_VAL;
  result->ypbind3_error = YPBIND_ERR_NOSERV;

  if (strchr (*argp, '/'))
    {
      log_msg (LOG_ERR, _("Domain name '%s' has embedded slash -- rejecting."),
	       *argp);
      result->ypbind3_error = YPBIND_ERR_NODOMAIN;
      return TRUE;
    }

  if (check_binding (*argp) != 0)
    return TRUE; /* No server available for domain *argp */
  find_domain_v3 (*argp, result);

#if 0
  /* ugly hack, somehow this goes still wrong somewhere */
  if (result->ypbind3_servername == NULL)
    result->ypbind3_servername = strdup ("");
#endif

  if (debug_flag)
    {
      if (result->ypbind_status == YPBIND_FAIL_VAL)
	log_msg (LOG_DEBUG, _("Status: YPBIND_FAIL_VAL, %s"),
		 ypbinderr_string (result->ypbind2_error));
      else
	{
	  log_msg (LOG_DEBUG, _("Status: YPBIND_SUCC_VAL"));
#if 0 /* only for debugging */
	  char namebuf6[INET6_ADDRSTRLEN];

	  if (result->ypbind3_nconf && result->ypbind3_svcaddr)
	    printf ("ypbind_netbuf:\n\taddr: %s\n\tport: %i\n",
		    taddr2ipstr (result->ypbind3_nconf,
				 result->ypbind3_svcaddr,
				 namebuf6, sizeof namebuf6),
		    taddr2port (result->ypbind3_nconf, result->ypbind3_svcaddr));
	  if (result->ypbind3_servername)
	    printf ("ypbind_servername: %s\n", result->ypbind3_servername);
	  else
	    printf ("ypbind_servername: NULL\n");
	  printf ("ypbind_hi_vers: %u\n", (u_int32_t)result->ypbind3_hi_vers);
	  printf ("ypbind_lo_vers: %u\n", (u_int32_t)result->ypbind3_lo_vers);
#endif
	}
    }
  return TRUE;

}

static bool_t
ypbindproc_setdom_v3 (const char *domain_name, ypbind3_binding *binding,
		      struct netbuf *fromhost, SVCXPRT *xprt)
{
  struct __rpc_sockinfo si;
  struct netconfig *nconf;

  if (strchr (domain_name, '/'))
    {
      log_msg (LOG_ERR, _("Domain name '%s' has embedded slash -- rejecting."),
	       domain_name);
      svcerr_noprog (xprt);
      return FALSE;
    }

  if ((nconf = getnetconfigent (xprt->xp_netid)) == NULL)
    {
      svcerr_systemerr (xprt);
      return FALSE;
    }

  if (!__rpc_nconf2sockinfo (nconf, &si))
    {
      freenetconfigent (nconf);
      svcerr_systemerr (xprt);
      return FALSE;
    }
  freenetconfigent (nconf);

  switch(si.si_af)
    {
    case AF_INET:
      {
	struct sockaddr_in *sin = fromhost->buf;

	switch(ypset)
	  {
	  case SET_YPSETME:
	    if (sin->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
	      {
		if (debug_flag)
		  log_msg (LOG_DEBUG,
			   _("User from '%s' try's to change the binding."),
			   inet_ntoa (sin->sin_addr));
		svcerr_noprog (xprt);
		return FALSE;
	      }
	    break;
	  case SET_YPSET:
	    break;
	  case SET_NO:
	  default:
	    if (debug_flag)
	      log_msg (LOG_DEBUG
		       , _("Changing the binding is not allowed."));
	    svcerr_noprog (xprt);
	    return FALSE;
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
	struct sockaddr_in6 *sin = fromhost->buf;

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
		svcerr_noprog (xprt);
		return FALSE;
	      }
	    break;
	  case SET_YPSET:
	    break;
	  case SET_NO:
	  default:
	    if (debug_flag)
	      log_msg (LOG_DEBUG, _("Changing the binding is not allowed."));
	    svcerr_noprog (xprt);
	    return FALSE;
	  }
	if (ntohs (sin->sin6_port) >= IPPORT_RESERVED)
	  {
	    log_msg (LOG_ERR,
		     _("SETDOM request doesn't come from reserved port."));
	    svcerr_noprog (xprt);
	    return FALSE;
	  }
      }
      break;
    }

  if (change_binding (domain_name, binding))
    {
      svcerr_systemerr (xprt);
      return FALSE;
    }
  /* Trigger check of new server */
  check_binding (domain_name);

  return TRUE;
}


static bool_t
ypbindproc_setdom (const char *domain_name, ypbind2_binding *binding,
		   struct netbuf *fromhost, SVCXPRT *xprt)
{
  bool_t retval;
  struct ypbind3_binding *ypb3;

  ypb3 = __host2ypbind3_binding (inet_ntoa (binding->ypbind_binding_addr));

  retval = ypbindproc_setdom_v3 (domain_name, ypb3, fromhost, xprt);

  __ypbind3_binding_free (ypb3);

  return retval;
}

bool_t
ypbindproc_oldsetdom_1_svc (ypbind_oldsetdom *argp, void *result,
			    struct svc_req *rqstp)
{
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];
	  uint16_t port;

	  port = ntohs(argp->ypoldsetdom_binding.ypbind_binding_port);
	  log_msg (LOG_DEBUG, "ypbindproc_oldsetdom_1 (%s:%s:%d) from %s port %i",
		   *argp->ypoldsetdom_domain,
		   inet_ntoa (argp->ypoldsetdom_binding.ypbind_binding_addr),
		   port, taddr2ipstr (nconf, rqhost,
				      namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));
	  freenetconfigent (nconf);
	}
    }

  memset (result, 0, sizeof (char *));

  return ypbindproc_setdom (argp->ypoldsetdom_domain,
			    &argp->ypoldsetdom_binding,
			    svc_getrpccaller (rqstp->rq_xprt), rqstp->rq_xprt);
}

bool_t
ypbindproc_setdom_2_svc (ypbind2_setdom *argp, void *result,
			 struct svc_req *rqstp)
{
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];

	  log_msg (LOG_DEBUG, "ypbindproc_setdom_2 (%s) from %s port %i",
		   argp->ypsetdom_domain,
		   taddr2ipstr (nconf, rqhost, namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));
	  freenetconfigent (nconf);
	}
    }

  memset (result, 0, sizeof (char *));

  return ypbindproc_setdom (argp->ypsetdom_domain,
			    &argp->ypsetdom_binding,
			    svc_getrpccaller (rqstp->rq_xprt),
			    rqstp->rq_xprt);
}

bool_t
ypbindproc_setdom_3_svc (ypbind3_setdom *argp, void *result,
			 struct svc_req *rqstp)
{
  if (debug_flag)
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(rqstp->rq_xprt);

      if ((nconf = getnetconfigent (rqstp->rq_xprt->xp_netid)) == NULL)
	svcerr_systemerr (rqstp->rq_xprt);
      else
	{
	  char namebuf6[INET6_ADDRSTRLEN];

	  log_msg (LOG_DEBUG, "ypbindproc_setdom_3 (%s) from %s port %i",
		   argp->ypsetdom_domain,
		   taddr2ipstr (nconf, rqhost, namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, rqhost));

#if 0 /* only for debugging */
	  if (argp->ypsetdom3_nconf && argp->ypsetdom3_svcaddr)
	    printf ("ypbind_netbuf:\n\taddr: %s\n\tport: %i\n",
		    taddr2ipstr (argp->ypsetdom3_nconf,
				 argp->ypsetdom3_svcaddr,
				 namebuf6, sizeof namebuf6),
		    taddr2port (argp->ypsetdom3_nconf, argp->ypsetdom3_svcaddr));
	  if (argp->ypsetdom3_servername)
	    printf ("ypbind_servername: %s\n", argp->ypsetdom3_servername);
	  else
	    printf ("ypbind_servername: NULL\n");
	  printf ("ypbind_hi_vers: %u\n", (u_int32_t)argp->ypsetdom3_hi_vers);
	  printf ("ypbind_lo_vers: %u\n", (u_int32_t)argp->ypsetdom3_lo_vers);
#endif
	  freenetconfigent (nconf);
	}
    }

  memset (result, 0, sizeof (char *));

  return ypbindproc_setdom_v3 (argp->ypsetdom_domain,
			       argp->ypsetdom_bindinfo,
			       svc_getrpccaller (rqstp->rq_xprt),
			       rqstp->rq_xprt);
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
