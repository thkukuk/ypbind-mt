
#include "ypbind.h"

bool_t
ypbind_xdr_domainname (XDR *xdrs, domainname *objp)
{
  if (!xdr_string (xdrs, objp, YPMAXDOMAIN))
    return FALSE;
  return TRUE;
}

bool_t
ypbind_xdr_olddomainname (XDR *xdrs, olddomainname *objp)
{
  if (!xdr_string (xdrs, &objp, YPMAXDOMAIN))
    return FALSE;
  return TRUE;
}

bool_t
ypbind_xdr_resptype (XDR *xdrs, ypbind_resptype *objp)
{
  if (!xdr_enum (xdrs, (enum_t *) objp))
    return FALSE;
  return TRUE;
}

bool_t
ypbind_xdr_binding (XDR *xdrs, ypbind_binding *objp)
{
  if (!xdr_opaque (xdrs, objp->ypbind_binding_addr, 4))
    return FALSE;
  if (!xdr_opaque (xdrs, objp->ypbind_binding_port, 2))
    return FALSE;
  return TRUE;
}

bool_t
ypbind_xdr_resp (XDR *xdrs, ypbind_resp *objp)
{
  if (!ypbind_xdr_resptype (xdrs, &objp->ypbind_status))
    return FALSE;
  switch (objp->ypbind_status)
    {
    case YPBIND_FAIL_VAL:
      if (!xdr_u_int (xdrs, &objp->ypbind_resp_u.ypbind_error))
	return FALSE;
      break;
    case YPBIND_SUCC_VAL:
      if (!ypbind_xdr_binding (xdrs, &objp->ypbind_resp_u.ypbind_bindinfo))
	return FALSE;
      break;
    default:
      return FALSE;
    }
  return TRUE;
}

bool_t
ypbind_xdr_oldsetdom (XDR *xdrs, ypbind_oldsetdom *objp)
{
  if (!xdr_vector (xdrs, (char *)objp->ypoldsetdom_domain, YPMAXDOMAIN,
		   sizeof (char), (xdrproc_t) xdr_char))
    return FALSE;
  if (!ypbind_xdr_binding (xdrs, &objp->ypoldsetdom_binding))
    return FALSE;
  return TRUE;
}

bool_t
ypbind_xdr_setdom (XDR *xdrs, ypbind_setdom *objp)
{
  if (!ypbind_xdr_domainname (xdrs, &objp->ypsetdom_domain))
    return FALSE;
  if (!ypbind_xdr_binding (xdrs, &objp->ypsetdom_binding))
    return FALSE;
  if (!xdr_u_int (xdrs, &objp->ypsetdom_vers))
    return FALSE;
  return TRUE;
}
