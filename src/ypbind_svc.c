
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <string.h>
#include <memory.h>
#include <syslog.h>
#include <sys/socket.h>
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
      olddomainname *ypbindproc_olddomain_1_arg;
      ypbind_oldsetdom ypbindproc_oldsetdom_1_arg;
    }
  argument;
  union
    {
      ypbind_resp ypbindproc_olddomain_1_res;
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
      xdr_argument = (xdrproc_t) ypbind_xdr_olddomainname;
      xdr_result = (xdrproc_t) ypbind_xdr_resp;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_olddomain_1_svc;
      break;

    case YPBINDPROC_OLDSETDOM:
      xdr_argument = (xdrproc_t) ypbind_xdr_oldsetdom;
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
    ypbind_setdom ypbindproc_setdom_2_arg;
  }
  argument;
  union
    {
      ypbind_resp ypbindproc_domain_2_res;
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
      xdr_argument = (xdrproc_t) ypbind_xdr_domainname;
      xdr_result = (xdrproc_t) ypbind_xdr_resp;
      local = (bool_t (*)(char *, void *, struct svc_req *))
	ypbindproc_domain_2_svc;
      break;

    case YPBINDPROC_SETDOM:
      xdr_argument = (xdrproc_t) ypbind_xdr_setdom;
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
