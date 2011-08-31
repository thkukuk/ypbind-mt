/* Copyright (c) 1998, 1999, 2001 Thorsten Kukuk
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

#ifndef __YPBIND_H__
#define __YPBIND_H__

#include <rpc/rpc.h>

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define YPMAXDOMAIN 256

#define SET_NO 0
#define SET_YPSET 1
#define SET_YPSETME 2

extern int ypset;

typedef char *domainname;

/*
 * Response structure and overall result status codes.  Success and failure
 * represent two separate response message types.
 */

enum ypbind_resptype {
	YPBIND_SUCC_VAL = 1,
	YPBIND_FAIL_VAL = 2,
};
typedef enum ypbind_resptype ypbind_resptype;

struct ypbind_binding {
	char ypbind_binding_addr[4];
	char ypbind_binding_port[2];
};
typedef struct ypbind_binding ypbind_binding;

struct ypbind_resp {
	ypbind_resptype ypbind_status;
	union {
		u_int ypbind_error;
		ypbind_binding ypbind_bindinfo;
	} ypbind_resp_u;
};
typedef struct ypbind_resp ypbind_resp;

/* Detailed failure reason codes for response field ypbind_error*/
#define YPBIND_ERR_ERR 1
#define YPBIND_ERR_NOSERV 2
#define YPBIND_ERR_RESC 3

/*
 * Request data structure for ypbind "Set domain" procedure.
 */

struct ypbind_oldsetdom {
	char ypoldsetdom_domain[YPMAXDOMAIN];
	ypbind_binding ypoldsetdom_binding;
};
typedef struct ypbind_oldsetdom ypbind_oldsetdom;
#define ypoldsetdom_addr ypoldsetdom_binding.ypbind_binding_addr
#define ypoldsetdom_port ypoldsetdom_binding.ypbind_binding_port

struct ypbind_setdom {
	domainname ypsetdom_domain;
	ypbind_binding ypsetdom_binding;
	u_int ypsetdom_vers;
};
typedef struct ypbind_setdom ypbind_setdom;

/*
 * NIS binding protocol
 */

#define YPBINDPROG    100007
#define YPBINDOLDVERS 1
#define YPBINDVERS    2


#define YPBINDPROC_OLDNULL 0
extern  bool_t ypbindproc_oldnull_1_svc(void *, void *, struct svc_req *);
#define YPBINDPROC_OLDDOMAIN 1
extern  bool_t ypbindproc_olddomain_1_svc(domainname *, ypbind_resp *, struct svc_req *);
#define YPBINDPROC_OLDSETDOM 2
extern  bool_t ypbindproc_oldsetdom_1_svc(ypbind_oldsetdom *, void *, struct svc_req *);
extern int ypbindprog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);


#define YPBINDPROC_NULL 0
extern  bool_t ypbindproc_null_2_svc(void *, void *, struct svc_req *);
#define YPBINDPROC_DOMAIN 1
extern  bool_t ypbindproc_domain_2_svc(domainname *, ypbind_resp *, struct svc_req *);
#define YPBINDPROC_SETDOM 2
extern  bool_t ypbindproc_setdom_2_svc(ypbind_setdom *, void *, struct svc_req *);
extern int ypbindprog_2_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

/* the xdr functions */

extern  bool_t ypbind_xdr_domainname (XDR *, domainname*);
extern  bool_t ypbind_xdr_resptype (XDR *, ypbind_resptype*);
extern  bool_t ypbind_xdr_binding (XDR *, ypbind_binding*);
extern  bool_t ypbind_xdr_resp (XDR *, ypbind_resp*);
extern  bool_t ypbind_xdr_oldsetdom (XDR *, ypbind_oldsetdom*);
extern  bool_t ypbind_xdr_setdom (XDR *, ypbind_setdom*);

#ifdef __cplusplus
}
#endif

#endif /* !__YPBIND_H__ */
