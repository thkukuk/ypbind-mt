/* Copyright (c) 1998 - 2014 Thorsten Kukuk
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <syslog.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <locale.h>
#include <libintl.h>
#include "ypbind.h"
#include "log_msg.h"
#include "local.h"

#define _(String) gettext (String)

void
ypbindprog_1 (struct svc_req *rqstp, register SVCXPRT *transp)
{
  union
    {
      domainname ypbindproc_olddomain_1_arg;
      ypbind_oldsetdom ypbindproc_oldsetdom_1_arg;
    }
  argument;
  union
    {
      ypbind2_resp ypbindproc_olddomain_1_res;
    }
  result;
  bool_t retval;
  xdrproc_t xdr_argument, xdr_result;
  bool_t (*local) (char *, void *, struct svc_req *);

  switch (rqstp->rq_proc)
    {
    case YPBINDPROC_OLDNULL:
      xdr_argument = (xdrproc_t) xdr_void;
      xdr_result = (xdrproc_t) xdr_void;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_oldnull_1_svc;
      break;

    case YPBINDPROC_OLDDOMAIN:
      xdr_argument = (xdrproc_t) xdr_domainname;
      xdr_result = (xdrproc_t) xdr_ypbind2_resp;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_olddomain_1_svc;
      break;

    case YPBINDPROC_OLDSETDOM:
      xdr_argument = (xdrproc_t) xdr_ypbind_oldsetdom;
      xdr_result = (xdrproc_t) xdr_void;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_oldsetdom_1_svc;
      break;

    default:
      svcerr_noproc (transp);
      return;
    }
  memset ((char *) &argument, 0, sizeof (argument));
  if (!svc_getargs (transp, xdr_argument, (caddr_t) & argument))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(transp);

      if ((nconf = getnetconfigent (transp->xp_netid)) == NULL)
        svcerr_systemerr (transp);
      else
        {
          char namebuf6[INET6_ADDRSTRLEN];

	  log_msg (LOG_ERR, "ypbindprog_1: cannot decode arguments for %d from %s port %i",
		   rqstp->rq_proc, taddr2ipstr (nconf, rqhost,
						namebuf6, sizeof (namebuf6)),
		   rqstp->rq_xprt->xp_port);

          freenetconfigent (nconf);
        }

      /* try to free already allocated memory during decoding.
	 bnc#471924 */
      svc_freeargs (transp, xdr_argument, (caddr_t) &argument);

      svcerr_decode (transp);
      return;
    }
  retval = (bool_t) (*local) ((char *) &argument, (void *) &result, rqstp);
  if (retval > 0 && !svc_sendreply (transp, xdr_result, (char *) &result))
    {
      svcerr_systemerr (transp);
    }
  if (!svc_freeargs (transp, xdr_argument, (caddr_t) &argument))
    log_msg (LOG_ERR, _("unable to free arguments"));

  if (!ypbindprog_1_freeresult (transp, xdr_result, (caddr_t) &result))
    log_msg (LOG_ERR, _("unable to free results"));

  return;
}

void
ypbindprog_2 (struct svc_req *rqstp, register SVCXPRT *transp)
{
  union
  {
    domainname ypbindproc_domain_2_arg;
    ypbind2_setdom ypbindproc_setdom_2_arg;
  }
  argument;
  union
    {
      ypbind2_resp ypbindproc_domain_2_res;
    }
  result;
  bool_t retval;
  xdrproc_t xdr_argument, xdr_result;
  bool_t (*local) (char *, void *, struct svc_req *);

  switch (rqstp->rq_proc)
    {
    case YPBINDPROC_NULL:
      xdr_argument = (xdrproc_t) xdr_void;
      xdr_result = (xdrproc_t) xdr_void;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_null_2_svc;
      break;

    case YPBINDPROC_DOMAIN:
      xdr_argument = (xdrproc_t) xdr_domainname;
      xdr_result = (xdrproc_t) xdr_ypbind2_resp;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_domain_2_svc;
      break;

    case YPBINDPROC_SETDOM:
      xdr_argument = (xdrproc_t) xdr_ypbind2_setdom;
      xdr_result = (xdrproc_t) xdr_void;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_setdom_2_svc;
      break;

    default:
      svcerr_noproc (transp);
      return;
    }
  memset ((char *) &argument, 0, sizeof (argument));
  if (!svc_getargs (transp, xdr_argument, (caddr_t) & argument))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(transp);

      if ((nconf = getnetconfigent (transp->xp_netid)) == NULL)
        svcerr_systemerr (transp);
      else
        {
          char namebuf6[INET6_ADDRSTRLEN];

	  log_msg (LOG_ERR, "ypbindprog_2: cannot decode arguments for %d from %s port %i",
		   rqstp->rq_proc, taddr2ipstr (nconf, rqhost,
						namebuf6, sizeof (namebuf6)),
		   rqstp->rq_xprt->xp_port);

          freenetconfigent (nconf);
        }

      /* try to free already allocated memory during decoding.
	 bnc#471924 */
      svc_freeargs (transp, xdr_argument, (caddr_t) &argument);

      svcerr_decode (transp);
      return;
    }
  retval = (bool_t) (*local) ((char *) &argument, (void *) &result, rqstp);
  if (retval > 0 && !svc_sendreply (transp, xdr_result, (char *) &result))
    {
      svcerr_systemerr (transp);
    }
  if (!svc_freeargs (transp, xdr_argument, (caddr_t) & argument))
    log_msg (LOG_ERR, _("unable to free arguments"));

  if (!ypbindprog_2_freeresult (transp, xdr_result, (caddr_t) & result))
    log_msg (LOG_ERR, _("unable to free results"));

  return;
}

void
ypbindprog_3 (struct svc_req *rqstp, register SVCXPRT *transp)
{
  union
  {
    domainname ypbindproc_domain_3_arg;
    ypbind3_setdom ypbindproc_setdom_3_arg;
  }
  argument;
  union
    {
      ypbind3_resp ypbindproc_domain_3_res;
    }
  result;
  bool_t retval;
  xdrproc_t xdr_argument, xdr_result;
  bool_t (*local) (char *, void *, struct svc_req *);

  switch (rqstp->rq_proc)
    {
    case YPBINDPROC_NULL:
      xdr_argument = (xdrproc_t) xdr_void;
      xdr_result = (xdrproc_t) xdr_void;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_null_3_svc;
      break;

    case YPBINDPROC_DOMAIN:
      xdr_argument = (xdrproc_t) xdr_domainname;
      xdr_result = (xdrproc_t) xdr_ypbind3_resp;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_domain_3_svc;
      break;

    case YPBINDPROC_SETDOM:
      xdr_argument = (xdrproc_t) xdr_ypbind3_setdom;
      xdr_result = (xdrproc_t) xdr_void;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_setdom_3_svc;
      break;

    default:
      svcerr_noproc (transp);
      return;
    }
  memset ((char *) &argument, 0, sizeof (argument));
  if (!svc_getargs (transp, xdr_argument, (caddr_t) & argument))
    {
      struct netconfig *nconf;
      struct netbuf *rqhost = svc_getrpccaller(transp);

      if ((nconf = getnetconfigent (transp->xp_netid)) == NULL)
        svcerr_systemerr (transp);
      else
        {
          char namebuf6[INET6_ADDRSTRLEN];

	  log_msg (LOG_ERR, "ypbindprog_3: cannot decode arguments for %d from %s port %i",
		   rqstp->rq_proc, taddr2ipstr (nconf, rqhost,
						namebuf6, sizeof (namebuf6)),
		   rqstp->rq_xprt->xp_port);

          freenetconfigent (nconf);
        }

      /* try to free already allocated memory during decoding.
	 bnc#471924 */
      svc_freeargs (transp, xdr_argument, (caddr_t) &argument);

      svcerr_decode (transp);
      return;
    }
  retval = (bool_t) (*local) ((char *) &argument, (void *) &result, rqstp);
  if (retval > 0 && !svc_sendreply (transp, xdr_result, (char *) &result))
    {
      svcerr_systemerr (transp);
    }
  if (!svc_freeargs (transp, xdr_argument, (caddr_t) & argument))
    log_msg (LOG_ERR, _("unable to free arguments"));

  if (!ypbindprog_3_freeresult (transp, xdr_result, (caddr_t) & result))
    log_msg (LOG_ERR, _("unable to free results"));

  return;
}
