#ifndef _LOCAL_H
#define _LOCAL_H 1

#define BINDINGDIR "/var/yp/binding"

extern int broken_server;
extern int ping_interval;
extern int use_broadcast;
extern int ypbind_port;

extern void find_domain_v2 (const char *domain, ypbind2_resp *result);
extern void find_domain_v3 (const char *domain, ypbind3_resp *result);
extern void clear_server (void);
extern int add_server (const char *__domain, const char *__host);
extern int change_binding (const char *__domain, ypbind3_binding *binding);
extern int load_config (int check_syntax);

extern void *test_bindings (void *param);
extern int check_binding (const char *domain);

#if defined(USE_DBUS_NM)
extern void *watch_dbus_nm (void *param);
extern int is_online;
extern int dbus_is_initialized;
extern int localhost_used;
extern pthread_mutex_t mutex_dbus;
extern pthread_cond_t cond_dbus;
#endif

extern void do_binding (void);

extern void ypbindprog_1 (struct svc_req *rqstp, register SVCXPRT *transp);
extern void ypbindprog_2 (struct svc_req *rqstp, register SVCXPRT *transp);
extern void ypbindprog_3 (struct svc_req *rqstp, register SVCXPRT *transp);

#if !defined (HAVE___NSS_CONFIGURE_LOOKUP)
/* the res_gethost* functions are not in standard header files */
extern struct hostent *res_gethostbyname(const char *);
extern struct hostent *res_gethostbyaddr(const char *, int, int);
#endif /* HAVE___NSS_CONFIGURE_LOOKUP */

void portmapper_disconnect (void);
int portmapper_connect (void);

#endif
