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

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.  */

#ifndef __YPBIND_H__
#define __YPBIND_H__

#include <rpc/rpc.h>
#include <rpcsvc/yp_prot.h>

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

/* Detailed failure reason codes for response field ypbind_error*/
#define YPBIND_ERR_ERR 1
#define YPBIND_ERR_NOSERV 2
#define YPBIND_ERR_RESC 3

#define YPBINDPROC_OLDNULL 0
extern  bool_t ypbindproc_oldnull_1_svc(void *, void *, struct svc_req *);
#define YPBINDPROC_OLDDOMAIN 1
extern  bool_t ypbindproc_olddomain_1_svc(domainname *, ypbind2_resp *, struct svc_req *);
#define YPBINDPROC_OLDSETDOM 2
extern  bool_t ypbindproc_oldsetdom_1_svc(ypbind_oldsetdom *, void *, struct svc_req *);
extern int ypbindprog_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);


#define YPBINDPROC_NULL 0
extern  bool_t ypbindproc_null_2_svc (void *, void *, struct svc_req *);
#define YPBINDPROC_DOMAIN 1
extern  bool_t ypbindproc_domain_2_svc (domainname *, ypbind2_resp *, struct svc_req *);
#define YPBINDPROC_SETDOM 2
extern  bool_t ypbindproc_setdom_2_svc (ypbind2_setdom *, void *, struct svc_req *);
extern int ypbindprog_2_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

extern  bool_t ypbindproc_null_3_svc (void *, void *, struct svc_req *);
extern  bool_t ypbindproc_domain_3_svc (domainname *, ypbind3_resp *, struct svc_req *);
extern  bool_t ypbindproc_setdom_3_svc (ypbind3_setdom *, void *, struct svc_req *);
extern int ypbindprog_3_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#ifdef __cplusplus
}
#endif

#endif /* !__YPBIND_H__ */
