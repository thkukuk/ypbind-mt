/* Copyright (c) 1998, 1999 Thorsten Kukuk

   This file is part of ypbind-mt.

   Author: Thorsten Kukuk <kukuk@suse.de>

   The ypbind-mt are free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   ypbind-mt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public
   License along with ypbind-mt; see the file COPYING.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA. */

#define _GNU_SOURCE

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <locale.h>
#include <malloc.h>
#include <libintl.h>
#include <arpa/inet.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <rpc/pmap_prot.h>
#if defined(HAVE_RPC_CLNT_SOC_H)
#include <rpc/clnt_soc.h>
#endif /* HAVE_RPC_CLNT_SOC_H */
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#if defined(HAVE_SYS_FILIO_H)
#include <sys/filio.h>
#endif

#include "ypbind.h"
#include "log_msg.h"
#include "local.h"
#include "pthread_np.h"

#if (defined(__sun__) || defined(sun)) && defined(__svr4__)
typedef uint32_t u_int32_t;
#endif

#define _(String) gettext (String)

#define YPPROG ((u_long)100004)
#define YPVERS ((u_long)2)
#define YPPROC_DOMAIN ((u_long)1)
#define YPPROC_DOMAIN_NONACK ((u_long)2)

#define _MAXSERVER 10

struct bound_server
{
  char *host;
  sa_family_t family;
  struct in_addr addr;
  u_short port;
};

struct binding
{
  char domain[YPMAXDOMAIN + 1];
  int active; /* index into server, -2 means ypset */
  bool_t use_broadcast;
  struct bound_server server[_MAXSERVER];
  struct bound_server ypset;
  CLIENT *client_handle;
};

static struct binding *domainlist = NULL;
static int max_domains = 0;
static pthread_rdwr_t domainlock = PTHREAD_RDWR_INITIALIZER;
static pthread_mutex_t search_lock = PTHREAD_MUTEX_INITIALIZER;

static void do_broadcast (struct binding *bind);
static void ping_all (struct binding *bind);

void
change_binding (const char *domain, ypbind_binding *binding)
{
  int i;

  pthread_rdwr_rlock_np (&domainlock);

  for (i = 0; i < max_domains; ++i)
    {
      if (strcmp (domainlist[i].domain, domain) == 0)
	{
	  struct sockaddr_in addr;
	  struct timeval timeout;
	  int sock;

	  pthread_rdwr_runlock_np (&domainlock);
	  pthread_rdwr_wlock_np (&domainlock);

	  if (domainlist[i].client_handle != NULL)
	    clnt_destroy (domainlist[i].client_handle);
	  domainlist[i].active = -2;
	  memcpy(&(domainlist[i].ypset.addr),
		 &(binding->ypbind_binding_addr),
		 sizeof (struct in_addr));
	  memcpy(&(domainlist[i].ypset.port),
		 &(binding->ypbind_binding_port),
		 sizeof (unsigned short int));
	  domainlist[i].ypset.family = AF_INET;

	  sock = RPC_ANYSOCK;
	  timeout.tv_sec = 1;
	  timeout.tv_usec = 0;
	  memset (&addr, 0, sizeof (struct sockaddr_in));
	  memcpy (&addr.sin_addr, &domainlist[i].ypset.addr,
		  sizeof (struct in_addr));
	  memcpy (&addr.sin_port, &domainlist[i].ypset.port,
		  sizeof (unsigned short int));
	  addr.sin_family = domainlist[i].ypset.family;

	  if ((domainlist[i].client_handle =
	       clntudp_create(&addr, YPPROG, YPVERS, timeout, &sock)) == NULL)
	    {
	      domainlist[i].active = -1;
	    }
	  pthread_rdwr_wunlock_np (&domainlock);
	  return;
	}
    }

  pthread_rdwr_runlock_np (&domainlock);
  return;
}

void
find_domain (const char *domain, ypbind_resp *result)
{
  int i, second;

  pthread_rdwr_rlock_np (&domainlock);

  second = 0; /* Try only once to find a new server for a unbounded domain */
  i = 0;
  while (i < max_domains)
    {
      if (strcmp (domainlist[i].domain, domain) == 0)
	{
	  if (domainlist[i].active >= 0)
	    {
	      result->ypbind_status = YPBIND_SUCC_VAL;
	      memcpy (&result->ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr,
		      &domainlist[i].server[domainlist[i].active].addr,
		      sizeof (struct in_addr));
	      memcpy (&result->ypbind_resp_u.ypbind_bindinfo.ypbind_binding_port,
		      &domainlist[i].server[domainlist[i].active].port,
		      sizeof (unsigned short int));
	      if (debug_flag)
		log_msg (LOG_DEBUG, "YPBINDPROC_DOMAIN: server '%s', port %d",
			 inet_ntoa(domainlist[i].server[domainlist[i].active].addr),
			 ntohs(domainlist[i].server[domainlist[i].active].port));
	      break;
	    }
	  else if (domainlist[i].active == -2)
	    {
	      result->ypbind_status = YPBIND_SUCC_VAL;
	      memcpy (&result->ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr,
		      &domainlist[i].ypset.addr, sizeof (struct in_addr));
	      memcpy (&result->ypbind_resp_u.ypbind_bindinfo.ypbind_binding_port,
		      &domainlist[i].ypset.port,
		      sizeof (unsigned short int));
	      if (debug_flag)
		log_msg (LOG_DEBUG,
			 "YPBINDPROC_DOMAIN: server '%s', port %d",
			 inet_ntoa(domainlist[i].ypset.addr),
			 ntohs(domainlist[i].ypset.port));
	      break;
	    }
	  else
	    {
	      if (second)
		{
		  second = 0;
		  break;
		}
	      /* Look, if we could find a new server for this domain.
		 But only, if the other thread is searching already */
	      pthread_rdwr_runlock_np (&domainlock);
	      if (pthread_mutex_trylock (&search_lock) == 0)
		{
		  if (debug_flag)
		    log_msg (LOG_DEBUG, "trylock = success");
		  if (domainlist[i].use_broadcast)
		    do_broadcast (&domainlist[i]);
		  else
		    ping_all (&domainlist[i]);
		  pthread_mutex_unlock (&search_lock);
		  ++second;
		  continue;
		}
	      else
		return;
	      pthread_rdwr_rlock_np (&domainlock);
	    }
	}
      ++i;
    }

  pthread_rdwr_runlock_np (&domainlock);

  return;
}

static void
close_bindingfile (const char *domain)
{
  char path[strlen (BINDINGDIR) + strlen (domain) + 10];

  sprintf (path, "%s/%s.1", BINDINGDIR, domain);
  unlink (path);
  sprintf (path, "%s/%s.2", BINDINGDIR, domain);
  unlink (path);
}

#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

static void
update_bindingfile (struct binding *entry)
{
  /* The calling functions must hold a lock ! */
  unsigned short int sport = port;
  struct iovec iov[2];
  struct ypbind_resp ybres;
  char path1[MAXPATHLEN + 1], path2[MAXPATHLEN + 1];
  int fd1, fd2, len;

  sprintf (path1, "%s/%s.1", BINDINGDIR, entry->domain);
  sprintf (path2, "%s/%s.2", BINDINGDIR, entry->domain);

  if ((fd1 = open(path1, O_CREAT | O_RDWR | O_TRUNC, FILE_MODE )) == -1)
    return;

  if ((fd2 = open(path2, O_CREAT | O_RDWR | O_TRUNC, FILE_MODE )) == -1)
    {
      close (fd1);
      unlink (path1);
      return;
    }

  iov[0].iov_base = (caddr_t) &sport;
  iov[0].iov_len = sizeof (sport);
  iov[1].iov_base = (caddr_t) &ybres;
  iov[1].iov_len = sizeof ybres;

  memset(&ybres, 0, sizeof (ybres));
  ybres.ypbind_status = YPBIND_SUCC_VAL;
  if (entry->active >= 0)
    {
      memcpy (&ybres.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr,
	      &entry->server[entry->active].addr, sizeof (struct in_addr));
      memcpy (&ybres.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_port,
	      &entry->server[entry->active].port, sizeof (unsigned short int));
    }
  else
    {
      memcpy (&ybres.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr,
	      &entry->ypset.addr, sizeof (struct in_addr));
      memcpy (&ybres.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_port,
	      &entry->ypset.port, sizeof (unsigned short int));
    }

  len = iov[0].iov_len + iov[1].iov_len;
  if (writev (fd1, iov, 2) != len )
    {
      log_msg (LOG_ERR, "writev (fd1): %s", strerror (errno));
      unlink (path1);
    }
  close (fd1);

  if (writev (fd2, iov, 2) != len )
    {
      log_msg (LOG_ERR, "writev (fd2): %s", strerror (errno));
      unlink (path2);
    }
  close (fd2);
}

void
clear_server (void)
{
  int i, j;

  pthread_rdwr_wlock_np (&domainlock);

  if (domainlist != NULL)
    {
      for (i = 0; i < max_domains; ++i)
	{
	  for (j = 0; j < _MAXSERVER; ++j)
	    {
	      if (domainlist[i].server[j].host != NULL)
		free (domainlist[i].server[j].host);
	    }
	  if (domainlist[i].ypset.host != NULL)
	    free (domainlist[i].ypset.host);
	  if (domainlist[i].client_handle != NULL)
	    clnt_destroy (domainlist[i].client_handle);
	}
      free (domainlist);
    }
  domainlist = NULL;
  max_domains = 0;

  pthread_rdwr_wunlock_np (&domainlock);
}

static int
get_entry (const char *domain, struct binding **entry)
{
  int i;

  *entry = NULL;

  for (i = 0; i < max_domains; ++i)
    {
      if (strcmp (domainlist[i].domain, domain) == 0)
	*entry = &domainlist[i];
    }

  if (!(*entry))
    {
      ++max_domains;
      domainlist = realloc (domainlist, max_domains * sizeof (struct binding));
      if (domainlist == NULL)
	{
	  log_msg (LOG_ERR, _("Not enough memory !"));
	  exit (1);
	}
      strcpy (domainlist[max_domains - 1].domain, domain);
      domainlist[max_domains - 1].ypset.host = NULL;
      domainlist[max_domains - 1].active = (-1);
      domainlist[max_domains - 1].use_broadcast = FALSE;
      memset (domainlist[max_domains - 1].server, 0,
	      (_MAXSERVER * sizeof (struct bound_server)));
      *entry = &domainlist[max_domains - 1];
    }

  return 0;
}

void
add_server (const char *domain, const char *host)
{
  struct binding *entry;
  int active;

  if (domain == NULL)
    {
      log_msg (LOG_ERR,
	       _("internal error: add_server called with NULL domain."));
      abort ();
    }

  pthread_rdwr_wlock_np (&domainlock);

  get_entry (domain, &entry);

  if (host == NULL)
    {
      entry->use_broadcast = TRUE;

      if (debug_flag)
	log_msg (LOG_DEBUG,
		 _("add_server() domain: %s, broadcast, slot: 0"),
		 domain);
    }
  else
    {
      /* find empty slot */
      for (active = 0; active < _MAXSERVER; ++active)
	if (entry->server[active].host == NULL)
	  break;

      /* There is no empty slot */
      if (entry->server[active].host != NULL)
	goto exit;

      if (debug_flag)
	log_msg (LOG_DEBUG,
		 _("add_server() domain: %s, host: %s, %sbroadcast, slot: %d"),
		 domain, host ? host : _("unknown"), (host == NULL) ? "" :
		 _("no"), active);

      if (host != NULL)
	{
	  struct hostent *hent;
#if defined (HAVE___NSS_CONFIGURE_LOOKUP)
	  struct hostent hostbuf;
	  size_t hstbuflen;
	  char *hsttmpbuf;
	  int herr;
#endif
	  entry->server[active].host = strdup(host);
#if defined (HAVE___NSS_CONFIGURE_LOOKUP)
	  hstbuflen = 1024;
	  hsttmpbuf = alloca (hstbuflen);
	  while (gethostbyname_r (entry->server[active].host,
				  &hostbuf, hsttmpbuf, hstbuflen,
				  &hent, &herr) < 0)
	    if (herr == NETDB_INTERNAL || errno == ERANGE)
	      {
		/* Enlarge the buffer.  */
		hstbuflen *= 2;
		hsttmpbuf = alloca (hstbuflen);
	      }
	    else
	      break;
#else
#if defined(HAVE_RES_GETHOSTBYNAME)
	  hent = res_gethostbyname (entry->server[active].host);
#elif defined(HAVE__DNS_GETHOSTBYNAME)
	  hent = _dns_gethostbyname (entry->server[active].host);
#else
	  hent = gethostbyname (entry->server[active].host);
#endif
#endif
	  if (!hent)
	    {
	      switch (h_errno)
		{
		case HOST_NOT_FOUND:
		  log_msg (LOG_ERR, _("Unknown host: %s"),
			   entry->server[active].host);
		  break;
		case TRY_AGAIN:
		  log_msg (LOG_ERR, _("Host name lookup failure"));
		  break;
		case NO_DATA:
		  log_msg (LOG_ERR, _("No address associated with name: %s"),
			   entry->server[active].host);
		  break;
		case NO_RECOVERY:
		  log_msg (LOG_ERR, _("Unknown server error"));
		  break;
		default:
		  log_msg (LOG_ERR, _("gethostbyname: Unknown error"));
		  break;
		}
	      return;
	    }
	  if (hent->h_addr_list[0] == NULL)
	    return;
	  entry->server[active].family = hent->h_addrtype;
	  /* XXX host could have multiple interfaces */
	  memcpy (&entry->server[active].addr, hent->h_addr_list[0],
		  hent->h_length);
	}
      else
	entry->server[active].host = NULL;
    }

 exit:
  pthread_rdwr_wunlock_np (&domainlock);
  return;
}

static struct binding *in_use = NULL;

static bool_t
eachresult (bool_t *out, struct sockaddr_in *addr)
{
  struct timeval timeout;
  int sock;

  if (*out)
    {
      if(debug_flag)
        {
#if defined (HAVE___NSS_CONFIGURE_LOOKUP)
	  struct hostent hostbuf, *host;
	  size_t hstbuflen;
	  char *hsttmpbuf;
	  int herr;

	  hstbuflen = 1024;
	  hsttmpbuf = alloca (hstbuflen);
	  while (gethostbyaddr_r ((char *) &addr->sin_addr.s_addr,
				  sizeof (addr->sin_addr.s_addr), AF_INET,
				  &hostbuf, hsttmpbuf, hstbuflen,
				  &host, &herr) < 0)
	    if (herr == NETDB_INTERNAL || errno == ERANGE)
	      {
		/* Enlarge the buffer.  */
		hstbuflen *= 2;
		hsttmpbuf = alloca (hstbuflen);
	      }
	    else
	      break;
#else
          struct hostent *host;

#if defined(HAVE_RES_GETHOSTBYNAME)
          host = res_gethostbyaddr((char *) &addr->sin_addr.s_addr,
				   sizeof(addr->sin_addr.s_addr), AF_INET);
#elif defined (HAVE__DNS_GETHOSTBYNAME)
          host = _dns_gethostbyaddr((char *) &addr->sin_addr.s_addr,
				    sizeof(addr->sin_addr.s_addr), AF_INET);
#else
          host = gethostbyaddr((char *) &addr->sin_addr.s_addr,
			       sizeof(addr->sin_addr.s_addr), AF_INET);
#endif
#endif /* HAVE___NSS_CONFIGURE_LOOKUP */
	  if (host != NULL)
	    log_msg (LOG_DEBUG, _("Answer for domain '%s' from server '%s'"),
		     in_use->domain, host->h_name);
	  else
	    log_msg (LOG_DEBUG,
		     _("Answer for domain '%s' from unknown server '%s'"),
		     in_use->domain, inet_ntoa (addr->sin_addr));
        }

      if (!broken_server && (ntohs(addr->sin_port) >= IPPORT_RESERVED))
	{
          log_msg (LOG_ERR, _("Answer for domain '%s' from '%s' on illegal port."),
		   in_use->domain, inet_ntoa (addr->sin_addr));
          return 0;
        }

      memcpy(&(in_use->server[0].addr), &addr->sin_addr,
	     sizeof (struct in_addr));
      memcpy(&(in_use->server[0].port), &addr->sin_port,
	     sizeof (unsigned short int));

      sock = RPC_ANYSOCK;
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      in_use->client_handle =
	clntudp_create(addr, YPPROG, YPVERS, timeout, &sock);

      if (in_use->client_handle == NULL)
	return 0;

      in_use->active = 0;

      return 1;
    }
  else
    {
      return 0;
    }
}

static void
do_broadcast (struct binding *bind)
{
  char *domain = bind->domain;
  bool_t out;
  enum clnt_stat status;

  pthread_rdwr_wlock_np (&domainlock);
  bind->active = -1;
  pthread_rdwr_wunlock_np (&domainlock);

  in_use = bind; /* global variable for eachresult */
  status = clnt_broadcast (YPPROG, YPVERS, YPPROC_DOMAIN_NONACK,
			   (xdrproc_t) ypbind_xdr_domainname, (void *)&domain,
			   (xdrproc_t) xdr_bool, (void *)&out,
			   (resultproc_t) eachresult);

  if (status != RPC_SUCCESS)
    {
      close_bindingfile(bind->domain);
      log_msg (LOG_ERR, "broadcast: %s.", clnt_sperrno(status));
    }
  else
    {
      pthread_rdwr_rlock_np (&domainlock);
      update_bindingfile (bind);
      pthread_rdwr_runlock_np (&domainlock);
    }
}

#if USE_BROADCAST

static struct timeval timeout = { 1, 0 };
static struct timeval tottimeout = { 1, 0 };

/*
 * Find the mapped port for program,version.
 * Calls the pmap service remotely to do the lookup.
 * Returns 0 if no map exists.
 */
static u_short
__pmap_getport (struct sockaddr_in *address, u_long program, u_long version,
		u_int protocol)
{
  u_short port = 0;
  int sock = -1;
  register CLIENT *client;
  struct pmap parms;

  address->sin_port = htons(PMAPPORT);

  client =
    clntudp_bufcreate (address, PMAPPROG, PMAPVERS, timeout, &sock,
		       RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
  if (client != (CLIENT *)NULL)
    {
      parms.pm_prog = program;
      parms.pm_vers = version;
      parms.pm_prot = protocol;
      parms.pm_port = 0;  /* not needed or used */
      if (CLNT_CALL(client, PMAPPROC_GETPORT, (xdrproc_t) xdr_pmap,
		    (caddr_t) &parms, (xdrproc_t) xdr_u_short,
		    (caddr_t) &port, tottimeout) != RPC_SUCCESS)
	{
	  rpc_createerr.cf_stat = RPC_PMAPFAILURE;
	  clnt_geterr(client, &rpc_createerr.cf_error);
	}
      else if (port == 0)
	{
	  rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
	}
      CLNT_DESTROY(client);
    }
  if (sock != -1)
    close(sock);
  address->sin_port = 0;
  return port;
}


/* Private data kept per client handle, from sunrpc/clnt_udp.c */
struct cu_data
  {
    int cu_sock;
    bool_t cu_closeit;
    struct sockaddr_in cu_raddr;
    int cu_rlen;
    struct timeval cu_wait;
    struct timeval cu_total;
    struct rpc_err cu_error;
    XDR cu_outxdrs;
    u_int cu_xdrpos;
    u_int cu_sendsz;
    char *cu_outbuf;
    u_int cu_recvsz;
    char cu_inbuf[1];
  };

/* This is the function, which should find the fastest server */
struct findserv_req
{
  u_int32_t xid;
  u_int server_nr;
  struct sockaddr_in sin;
};

static void
ping_all (struct binding *bind)
{
  const struct timeval TIMEOUT50 = {5, 0};
  const struct timeval TIMEOUT00 = {0, 0};
  CLIENT *clnt;
  struct findserv_req **pings;
  struct sockaddr_in sin, *any = NULL;
  int found = -1;
  u_int32_t xid_seed, xid_lookup;
  int sock, dontblock = 1;
  bool_t clnt_res;
  u_long i, pings_count = 0;
  struct cu_data *cu;
  char *domain = bind->domain;

  pthread_rdwr_wlock_np (&domainlock);
  bind->active = -1;
  pthread_rdwr_wunlock_np (&domainlock);

  pings = malloc (sizeof (struct findserv_req *) * _MAXSERVER);
  if (pings == NULL)
    return;
  xid_seed = (u_int32_t) (time (NULL) ^ getpid ());

  for (i = 0; bind->server[i].host; ++i)
    {
      if (debug_flag)
	log_msg (LOG_DEBUG, _("ping host '%s', domain '%s'"),
		 bind->server[i].host, bind->domain);

      memset (&sin, 0, sizeof (struct sockaddr_in));
      memcpy (&sin.sin_addr, &(bind->server[i].addr), sizeof (struct in_addr));
      sin.sin_family = bind->server[i].family;
      sin.sin_port =
	htons (__pmap_getport (&sin, YPPROG, YPVERS, IPPROTO_UDP));
      bind->server[i].port = sin.sin_port;
      if (sin.sin_port == 0)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG, _("host '%s' doesn't answer."),
		     bind->server[i].host);
	  continue;
	}

      pings[pings_count] = calloc (1, sizeof (struct findserv_req));
      memcpy (&pings[pings_count]->sin, &sin, sizeof(struct sockaddr_in));
      any = &pings[pings_count]->sin;
      pings[pings_count]->xid = xid_seed;
      pings[pings_count]->server_nr = i;
      ++xid_seed;
      ++pings_count;
    }

  /* Make sure at least one server was assigned */
  if (pings_count == 0)
    {
      free (pings);
      return;
    }

  /* Create RPC handle */
  sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  clnt = clntudp_create (any, YPPROG, YPVERS, TIMEOUT50, &sock);
  if (clnt == NULL)
    {
      close (sock);
      for (i = 0; i < pings_count; ++i)
        free (pings[i]);
      free (pings);
      return;
    }
  clnt->cl_auth = authunix_create_default ();
  cu = (struct cu_data *) clnt->cl_private;
  clnt_control (clnt, CLSET_TIMEOUT, (char *) &TIMEOUT00);
  ioctl (sock, FIONBIO, &dontblock);

  /* Send to all servers the YPPROC_DOMAIN_NONACK */
  for (i = 0; i < pings_count; ++i)
    {
      /* clntudp_call() will increment, subtract one */
      *((u_int32_t *) (cu->cu_outbuf)) = pings[i]->xid - 1;
      memcpy (&(cu->cu_raddr), &pings[i]->sin, sizeof (struct sockaddr_in));
      memset(&clnt_res, 0, sizeof (clnt_res));
      /* Transmit to YPPROC_DOMAIN_NONACK, return immediately. */
      clnt_call (clnt, YPPROC_DOMAIN_NONACK, (xdrproc_t) ypbind_xdr_domainname,
		 (caddr_t) &domain, (xdrproc_t) xdr_bool, (caddr_t) &clnt_res,
		 TIMEOUT00);
    }
  /* Receive reply from YPPROC_DOMAIN_NONACK asynchronously */
  memset ((char *) &clnt_res, 0, sizeof (clnt_res));
  clnt_call (clnt, YPPROC_DOMAIN_NONACK, (xdrproc_t) NULL, (caddr_t) NULL,
             (xdrproc_t) xdr_bool, (caddr_t) &clnt_res, TIMEOUT00);

  xid_lookup = *((u_int32_t *) (cu->cu_inbuf));
  close (sock);
  for (i = 0; i < pings_count; ++i)
    {
      if (pings[i]->xid == xid_lookup)
        {
	  pthread_rdwr_wlock_np (&domainlock);
          bind->active = pings[i]->server_nr;

	  sock = RPC_ANYSOCK;
	  bind->client_handle =
	    clntudp_create (&(pings[i]->sin),
			    YPPROG, YPVERS, TIMEOUT50, &sock);
	  /* XXX Missing NULL check here */
	  pthread_rdwr_wunlock_np (&domainlock);
	  pthread_rdwr_rlock_np (&domainlock);
	  update_bindingfile (bind);
	  pthread_rdwr_runlock_np (&domainlock);
	  if (debug_flag)
	    log_msg (LOG_DEBUG,
		     _("Answer for domain '%s' from server '%s'"),
		     domain, bind->server[bind->active].host);
          found = 1;
        }
    }

  auth_destroy (clnt->cl_auth);
  clnt_destroy (clnt);

  for (i = 0; i < pings_count; ++i)
    free (pings[i]);
  free (pings);

  if (!found)
    close_bindingfile(bind->domain);

  return;
}

#else /* Don't send a ping to all server at the same time */

static void
ping_all (struct binding *bind)
{
  char *domain = bind->domain;
  struct sockaddr_in server_addr;
  int sock;
  bool_t out;
  enum clnt_stat status;
  struct timeval timeout;
  CLIENT *clnt_handlep = NULL;
  int i = 0;

  pthread_rdwr_wlock_np (&domainlock);
  bind->active = -1;
  pthread_rdwr_wunlock_np (&domainlock);

  while (bind->server[i].host != NULL)
    {

      if (debug_flag)
        log_msg (LOG_DEBUG, _("ping host '%s', domain '%s'"),
                 bind->server[i].host, bind->domain);


      memset((char *)&server_addr, 0, sizeof server_addr);
      server_addr.sin_family = bind->server[i].family;
      server_addr.sin_port = htons(0);
      sock = RPC_ANYSOCK;
      memcpy (&server_addr.sin_addr, &bind->server[i].addr,
	      sizeof (struct in_addr));
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      clnt_handlep = clntudp_create (&server_addr, YPPROG, YPVERS,
				     timeout, &sock);
      if (NULL != clnt_handlep)
	break;

      if (clnt_handlep == NULL)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG,
		     _("clnt_create for server '%s' (domain '%s') failed"),
		     bind->server[i], domain);
	  ++i;
	  continue;
	}

      timeout.tv_sec = 5;
      timeout.tv_usec = 0;
      status = clnt_call(clnt_handlep, YPPROC_DOMAIN,
                         (xdrproc_t) ypbind_xdr_domainname, (caddr_t) &domain,
                         (xdrproc_t) xdr_bool, (caddr_t) &out, timeout);
      if (RPC_SUCCESS != status)
        {
          log_msg (LOG_ERR, "%s", clnt_sperror(clnt_handlep,
					       bind->server[i].host));
          clnt_destroy(clnt_handlep);
	  ++i;
	  continue;
        }
      else if (out != TRUE)
        {
          log_msg (LOG_ERR, _("domain '%s' not served by '%s'"),
                   domain, bind->server[i].host);
          clnt_destroy(clnt_handlep);
	  ++i;
	  continue;
        }
      else
        {
	  memcpy (&(bind->server[i].port), &server_addr.sin_port,
		  sizeof (unsigned short int));
          bind->client_handle = clnt_handlep;
          pthread_rdwr_wlock_np (&domainlock);
          bind->active = i;
          pthread_rdwr_wunlock_np (&domainlock);
          pthread_rdwr_rlock_np (&domainlock);
          update_bindingfile (bind);
          pthread_rdwr_runlock_np (&domainlock);
          return;
        }

      ++i;
      if (i == _MAXSERVER)
        {
          close_bindingfile(bind->domain);
          return;
        }
    }
}

#endif

void
do_binding (void)
{
  int i;

  pthread_mutex_lock (&search_lock);
  for (i = 0; i < max_domains; ++i)
    {
      if (domainlist[i].use_broadcast)
	do_broadcast (&domainlist[i]);
      else
	ping_all (&domainlist[i]);
    }
  pthread_mutex_unlock (&search_lock);
}

/* This thread will send an ping to all NIS server marked as active. If
   a server doesn't answer or tell us, that he doesn't serv this domain
   any longer, we mark it as inactive and try to find a new server */
void *
test_bindings (void *param)
{
  static int success = 0;
  int i;

  do_binding ();

  if (ping_interval < 1)
    pthread_exit (&success);

  while (1)
    {
      sleep (ping_interval);

      pthread_rdwr_rlock_np (&domainlock);

      if (debug_flag)
	log_msg (LOG_DEBUG, _("Pinging all active server."));

      for (i = 0; i < max_domains; ++i)
	{
	  char *domain = domainlist[i].domain;
	  bool_t out;
	  enum clnt_stat status;
	  struct timeval timeout;

	  if (domainlist[i].active != -1)
	    {
	      timeout.tv_sec = 3;
	      timeout.tv_usec = 0;
	      status =
		clnt_call(domainlist[i].client_handle,
			  YPPROC_DOMAIN, (xdrproc_t) ypbind_xdr_domainname,
			  (caddr_t) &domain, (xdrproc_t) xdr_bool, (caddr_t) &out,
			  timeout);
	      if (status != RPC_SUCCESS || out != TRUE)
		{
		  if (debug_flag)
		    {
		      if (domainlist[i].use_broadcast)
			log_msg (LOG_DEBUG,
				 _("Server for domain '%s' doesn't answer."),
				 domain);
		      else
			{
			  if (domainlist[i].active == -2)
			    log_msg (LOG_DEBUG,
				     _("Server '%s' for domain '%s' doesn't answer."),
				     inet_ntoa(domainlist[i].ypset.addr),
				     domain);
			  else
			    log_msg (LOG_DEBUG,
				     _("Server '%s' for domain '%s' doesn't answer."),
				     domainlist[i].server[domainlist[i].active].host,
				     domain);
			}
		    }

		  /* We have the read lock, but we need the write lock for
		     changes :-( */
		  pthread_rdwr_runlock_np (&domainlock);
		  pthread_rdwr_wlock_np (&domainlock);
		  clnt_destroy (domainlist[i].client_handle);
		  domainlist[i].client_handle = NULL;
		  if (domainlist[i].active == -2)
		    {
		      if (domainlist[i].ypset.host != NULL)
			free (domainlist[i].ypset.host);
		      domainlist[i].ypset.host = NULL;
		    }
		  domainlist[i].active = -1;
		  close_bindingfile (domain);
		  /* And give the write lock away, search a new host and get
		     the read lock again */
		  pthread_rdwr_wunlock_np (&domainlock);
		  pthread_mutex_lock (&search_lock);
		  if (domainlist[i].use_broadcast)
		    do_broadcast (&domainlist[i]);
		  else
		    ping_all (&domainlist[i]);
		  pthread_mutex_unlock (&search_lock);
		  pthread_rdwr_rlock_np (&domainlock);
		}
	    }
	  else
	    {
	      pthread_rdwr_runlock_np (&domainlock);
	      pthread_mutex_lock (&search_lock);
	      if (domainlist[i].use_broadcast)
		do_broadcast (&domainlist[i]);
	      else
		ping_all (&domainlist[i]);
	      pthread_mutex_unlock (&search_lock);
	      pthread_rdwr_rlock_np (&domainlock);
	    }
	}
      pthread_rdwr_runlock_np (&domainlock);
    }
}
