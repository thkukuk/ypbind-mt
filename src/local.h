#ifndef _LOCAL_H
#define _LOCAL_H 1

#define BINDINGDIR "/var/yp/binding"

extern int broken_server;
extern int port;
extern int ping_interval;

extern void find_domain (const char *domain, ypbind_resp *result);
extern void clear_server (void);
extern void add_server (const char *__domain, const char *__host);
extern void change_binding (const char *__domain, ypbind_binding *binding);

extern void *test_bindings (void *param);

extern void do_binding (void);

extern void ypbindprog_1 (struct svc_req *rqstp, register SVCXPRT *transp);
extern void ypbindprog_2 (struct svc_req *rqstp, register SVCXPRT *transp);

#if !defined (HAVE___NSS_CONFIGURE_LOOKUP)
/* the res_gethost* functions are not in standard header files */
extern struct hostent *res_gethostbyname(const char *);
extern struct hostent *res_gethostbyaddr(const char *, int, int);
#endif /* HAVE___NSS_CONFIGURE_LOOKUP */

#endif
