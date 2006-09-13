/* Copyright (c) 1998-2006 Thorsten Kukuk
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
#include <stdlib.h>
#include <string.h>
#include <locale.h>
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
#include <sys/socket.h>
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

#define _MAXSERVER 30

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

static void do_broadcast (struct binding *list);
static int ping_all (struct binding *list);

static void
remove_bindingfile (const char *domain_name)
{
  char path[strlen (BINDINGDIR) + strlen (domain_name) + 10];

  sprintf (path, "%s/%s.1", BINDINGDIR, domain_name);
  unlink (path);
  sprintf (path, "%s/%s.2", BINDINGDIR, domain_name);
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
  int fd, len;

  sprintf (path1, "%s/%s.1", BINDINGDIR, entry->domain);
  sprintf (path2, "%s/%s.2", BINDINGDIR, entry->domain);

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
  else if (entry->active == -2) /* ypset was used */
    {
      memcpy (&ybres.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_addr,
	      &entry->ypset.addr, sizeof (struct in_addr));
      memcpy (&ybres.ypbind_resp_u.ypbind_bindinfo.ypbind_binding_port,
	      &entry->ypset.port, sizeof (unsigned short int));
    }
  else
    {
       /* This should not happen. Remove binding files which means,
          libc will query ypbind direct. */
       unlink (path1);
       unlink (path2);
       log_msg (LOG_ERR, "INTERNAL ERROR: update_bindingfile called without valid data!");
       return;
    }

  len = iov[0].iov_len + iov[1].iov_len;

  if ((fd = open(path1, O_CREAT | O_RDWR | O_TRUNC, FILE_MODE )) != -1)
    {
      if (writev (fd, iov, 2) != len )
        {
          log_msg (LOG_ERR, "writev (%s): %s", path1, strerror (errno));
          unlink (path1);
        }
      close (fd);
    }
  else
    log_msg (LOG_ERR, "open(%s): %s", path1, strerror (errno));

  if ((fd = open(path2, O_CREAT | O_RDWR | O_TRUNC, FILE_MODE )) != -1)
    {
      if (writev (fd, iov, 2) != len )
        {
          log_msg (LOG_ERR, "writev (%s): %s", path2, strerror (errno));
          unlink (path2);
        }
      close (fd);
    }
  else
    log_msg (LOG_ERR, "open(%s): %s", path2, strerror (errno));
}

/* this is called from the RPC thread (ypset). */
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
	      remove_bindingfile (domain);
	    }
	  pthread_rdwr_wunlock_np (&domainlock);
	  pthread_rdwr_rlock_np (&domainlock);
	  update_bindingfile (&domainlist[i]);
	  pthread_rdwr_runlock_np (&domainlock);

	  return;
	}
    }

  pthread_rdwr_runlock_np (&domainlock);
  return;
}

void
find_domain (const char *domain, ypbind_resp *result)
{
  int i, count = 0;

  if (domainlist == NULL)
    return;

  pthread_rdwr_rlock_np (&domainlock);

  for (i = 0; i < max_domains; ++i)
    if (strcmp (domainlist[i].domain, domain) == 0)
      break;

  if ( i >= max_domains)
    {
      pthread_rdwr_runlock_np (&domainlock);
      return;
    }

 again:
  ++count;
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
    }
  else
    {
      /* Look, if we could find a new server for this domain.
	 But only, if the other thread is not searching already */
      pthread_rdwr_runlock_np (&domainlock);

      if (count > 2) /* No more than 2 tries.  */
	return;

      if (pthread_mutex_trylock (&search_lock) == 0)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG, "trylock = success");
	  if (!ping_all (&domainlist[i]) &&
	      domainlist[i].use_broadcast)
	    do_broadcast (&domainlist[i]);
	}
      else
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG, "trylock = failed");
	  /* Another thread has the lock, ugly hack to wait
	     until this thread is finished with search.  */
	  pthread_mutex_lock (&search_lock);
	}
      pthread_mutex_unlock (&search_lock);
      /* Get the read lock again for next run. */
      pthread_rdwr_rlock_np (&domainlock);
      goto again;
    }

  pthread_rdwr_runlock_np (&domainlock);

  return;
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
	  if (domainlist[i].active != -1)
	    {
	      remove_bindingfile (domainlist[i].domain);
	      for (j = 0; j < _MAXSERVER; ++j)
		{
		  if (domainlist[i].server[j].host != NULL)
		    free (domainlist[i].server[j].host);
		}
	      if (domainlist[i].ypset.host != NULL)
		free (domainlist[i].ypset.host);
	      if (domainlist[i].client_handle != NULL)
		clnt_destroy (domainlist[i].client_handle);
	      domainlist[i].active = -1;
	    }
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

int
add_server (const char *domain, const char *host, int check_syntax)
{
  struct binding *entry;
  int active;
  int res = 0;

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
      res = 1;

      if (debug_flag)
	log_msg (LOG_DEBUG,
		 _("add_server() domain: %s, broadcast"),
		 domain);
    }
  else
    {
      struct hostent *hent;
#if defined (HAVE___NSS_CONFIGURE_LOOKUP)
      struct hostent hostbuf;
      size_t hstbuflen;
      char *hsttmpbuf;
      int herr;
      int error;
#endif

      /* find empty slot */
      for (active = 0; active < _MAXSERVER; ++active)
	if (entry->server[active].host == NULL)
	  break;

      /* There is no empty slot */
      if (entry->server[active].host != NULL)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG,
		     _("add_server() domain: %s, host: %s, NO SLOT FREE!"),
		     domain, host);
	  goto exit;
	}

      if (debug_flag)
	log_msg (LOG_DEBUG,
		 _("add_server() domain: %s, host: %s, slot: %d"),
		 domain, host, active);

#if defined (HAVE___NSS_CONFIGURE_LOOKUP)
      hstbuflen = 1024;
      hsttmpbuf = alloca (hstbuflen);
      while ((error= gethostbyname_r (host, &hostbuf, hsttmpbuf, hstbuflen,
				      &hent, &herr)) != 0)
	if (herr == NETDB_INTERNAL || (error == -1 && errno == ERANGE)
	    || error == ERANGE)
	  {
	    /* Enlarge the buffer.  */
	    hstbuflen *= 2;
	    hsttmpbuf = alloca (hstbuflen);
	  }
	else
	  break;
#elif defined(HAVE_RES_GETHOSTBYNAME)
      hent = res_gethostbyname (host);
#elif defined(HAVE__DNS_GETHOSTBYNAME)
      hent = _dns_gethostbyname (host);
#else
      hent = gethostbyname (host);
#endif
      if (!hent)
	{
	  switch (h_errno)
	    {
	    case HOST_NOT_FOUND:
	      if (check_syntax)
		fprintf (stderr, "%s %s\n", _("Unknown host:"), host);
	      else
		log_msg (LOG_ERR, "%s %s", _("Unknown host:"), host);
	      break;
	    case TRY_AGAIN:
	      if (check_syntax)
		fprintf (stderr, "%s\n", _("Host name lookup failure"));
	      else
		log_msg (LOG_ERR, _("Host name lookup failure"));
	      break;
	    case NO_DATA:
	      if (check_syntax)
		fprintf (stderr, "%s %s\n",
			 _("No address associated with name:"), host);
	      else
		log_msg (LOG_ERR, "%s %s",
			 _("No address associated with name:"), host);
	      break;
	    case NO_RECOVERY:
	      if (check_syntax)
		fprintf (stderr, "%s\n", _("Unknown server error"));
	      else
		log_msg (LOG_ERR, _("Unknown server error"));
	      break;
	    default:
	      if (check_syntax)
		fprintf (stderr, "%s\n", _("gethostbyname: Unknown error"));
	      else
		log_msg (LOG_ERR, _("gethostbyname: Unknown error"));
	      break;
	    }
	  goto exit;
	}
      if (hent->h_addr_list[0] == NULL)
	goto exit;

      entry->server[active].host = strdup (host);
      entry->server[active].family = hent->h_addrtype;
      /* XXX host could have multiple interfaces. We should
	 try to use the interface on the local network.
	 If there is none, use the first one. */
      memcpy (&entry->server[active].addr, hent->h_addr_list[0],
	      hent->h_length);
      res = 1;
    }

 exit:
  pthread_rdwr_wunlock_np (&domainlock);
  return res;
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
	  int error;

	  hstbuflen = 1024;
	  hsttmpbuf = alloca (hstbuflen);
	  while ((error = gethostbyaddr_r ((char *) &addr->sin_addr.s_addr,
					   sizeof (addr->sin_addr.s_addr),
					   AF_INET, &hostbuf, hsttmpbuf,
					   hstbuflen, &host, &herr)) < 0)
	    if (herr == NETDB_INTERNAL || (error == -1 && errno == ERANGE)
		|| error == ERANGE)
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
          log_msg (LOG_ERR,
		   _("Answer for domain '%s' from '%s' on illegal port %d."),
		   in_use->domain, inet_ntoa (addr->sin_addr),
		   ntohs (addr->sin_port));
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
do_broadcast (struct binding *list)
{
  char *domain;
  bool_t out;
  enum clnt_stat status;

  /* Get readlock and create a local copy of the domainname.
     Else a SIGHUP could delete the data and we will dereference
     invalid data.  */
  pthread_rdwr_rlock_np (&domainlock);
  domain = strdupa (list->domain);
  pthread_rdwr_runlock_np (&domainlock);

  if (debug_flag)
    log_msg (LOG_DEBUG, _("do_broadcast() for domain '%s' is called"),
	     domain);

  /* Get a writer lock for the domain list, since we modify one
     entry.  */
  pthread_rdwr_wlock_np (&domainlock);
  list->active = -1;
  pthread_rdwr_wunlock_np (&domainlock);

  /* Get a reader lock while we do the broadcast. Normally we would
     need the writer lock, since we modify the data. But in this case,
     the broadcast timeout is too long and we would block all queries.
     Since we don't change pointers and all data is always valid, we
     only acquire the reader lock. */
  pthread_rdwr_rlock_np (&domainlock);

  in_use = list; /* global variable for eachresult */

  status = clnt_broadcast (YPPROG, YPVERS, YPPROC_DOMAIN_NONACK,
			   (xdrproc_t) ypbind_xdr_domainname, (void *)&domain,
			   (xdrproc_t) xdr_bool, (void *)&out,
			   (resultproc_t) eachresult);


  if (status != RPC_SUCCESS)
    {
      remove_bindingfile (domain);
      log_msg (LOG_ERR, "broadcast: %s.", clnt_sperrno (status));
    }
  else
    update_bindingfile (list);

  pthread_rdwr_runlock_np (&domainlock);

  if (debug_flag)
    log_msg (LOG_DEBUG, _("leave do_broadcast() for domain '%s'"),
	     domain);
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
  u_short rport = 0;
  int sock = -1;
  CLIENT *client;
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
		    (caddr_t) &rport, tottimeout) != RPC_SUCCESS)
	{
	  rpc_createerr.cf_stat = RPC_PMAPFAILURE;
	  clnt_geterr(client, &rpc_createerr.cf_error);
	}
      else if (rport == 0)
	{
	  rpc_createerr.cf_stat = RPC_PROGNOTREGISTERED;
	}
      CLNT_DESTROY(client);
    }
  if (sock != -1)
    close(sock);
  address->sin_port = 0;
  return rport;
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

/* This function sends a ping to every known ypserver. It returns 0,
   if no running server is found, 1 else. */
static int
ping_all (struct binding *list)
{
  const struct timeval TIMEOUT50 = {5, 0};
  const struct timeval TIMEOUT00 = {0, 0};
  CLIENT *clnt;
  struct findserv_req **pings;
  struct sockaddr_in s_in, *any = NULL;
  int found = -1;
  u_int32_t xid_seed, xid_lookup;
  int sock, dontblock = 1;
  bool_t clnt_res;
  u_long i, pings_count = 0;
  struct cu_data *cu;
  char *domain = list->domain;

  if (list->server[0].host == NULL) /* There is no known server */
    return 0;

  pthread_rdwr_wlock_np (&domainlock);
  list->active = -1;
  pthread_rdwr_wunlock_np (&domainlock);

  pings = malloc (sizeof (struct findserv_req *) * _MAXSERVER);
  if (pings == NULL)
    return 0;
  xid_seed = (u_int32_t) (time (NULL) ^ getpid ());

  for (i = 0; i < _MAXSERVER && list->server[i].host; ++i)
    {
      if (debug_flag)
	log_msg (LOG_DEBUG, _("ping host '%s', domain '%s'"),
		 list->server[i].host, list->domain);

      memset (&s_in, 0, sizeof (struct sockaddr_in));
      memcpy (&s_in.sin_addr, &(list->server[i].addr),
	      sizeof (struct in_addr));
      s_in.sin_family = list->server[i].family;
      s_in.sin_port =
	htons (__pmap_getport (&s_in, YPPROG, YPVERS, IPPROTO_UDP));
      if (!broken_server && ntohs (s_in.sin_port) >= IPPORT_RESERVED)
	{
          log_msg (LOG_ERR,
		   _("Answer for domain '%s' from '%s' on illegal port %d."),
		   list->domain, list->server[i].host,
		   ntohs (s_in.sin_port));
	  continue;
        }
      list->server[i].port = s_in.sin_port;
      if (s_in.sin_port == 0)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG, _("host '%s' doesn't answer."),
		     list->server[i].host);
	  continue;
	}

      pings[pings_count] = calloc (1, sizeof (struct findserv_req));
      memcpy (&pings[pings_count]->sin, &s_in, sizeof(struct sockaddr_in));
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
      return 0;
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
      return 0;
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

	  sock = RPC_ANYSOCK;
	  list->client_handle =
	    clntudp_create (&(pings[i]->sin),
			    YPPROG, YPVERS, TIMEOUT50, &sock);
	  if (list->client_handle == NULL)
	    {
	      /* NULL should not happen, we have got an answer from the server. */
	      log_msg (LOG_DEBUG,
		       _("Server '%s' for domain '%s' answered ping but failed to bind"),
		       list->server[list->active].host, domain);
	    }
	  else
	    {
	      list->active = pings[i]->server_nr;
	      pthread_rdwr_wunlock_np (&domainlock);
	      pthread_rdwr_rlock_np (&domainlock);
	      update_bindingfile (list);
	      pthread_rdwr_runlock_np (&domainlock);
	      if (debug_flag)
		log_msg (LOG_DEBUG,
			 _("Answer for domain '%s' from server '%s'"),
			 domain, list->server[list->active].host);
	      found = 1;
	    }
        }
    }

  auth_destroy (clnt->cl_auth);
  clnt_destroy (clnt);

  for (i = 0; i < pings_count; ++i)
    free (pings[i]);
  free (pings);

  if (!found)
    remove_bindingfile (list->domain);

  return found;
}

#else /* Don't send a ping to all server at the same time */

static int
ping_all (struct binding *list)
{
  char *domain = list->domain;
  struct sockaddr_in server_addr;
  int sock;
  bool_t out;
  enum clnt_stat status;
  struct timeval timeout;
  CLIENT *clnt_handlep = NULL;
  int i = 0;

  if (list->server[0].host == NULL) /* There is no known server */
    return 0;

  pthread_rdwr_wlock_np (&domainlock);
  list->active = -1;
  pthread_rdwr_wunlock_np (&domainlock);

  while (list->server[i].host != NULL && i < _MAXSERVER)
    {

      if (debug_flag)
        log_msg (LOG_DEBUG, _("ping host '%s', domain '%s'"),
                 list->server[i].host, list->domain);


      memset((char *)&server_addr, 0, sizeof server_addr);
      server_addr.sin_family = list->server[i].family;
      server_addr.sin_port = htons(0);
      sock = RPC_ANYSOCK;
      memcpy (&server_addr.sin_addr, &list->server[i].addr,
	      sizeof (struct in_addr));
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      clnt_handlep = clntudp_create (&server_addr, YPPROG, YPVERS,
				     timeout, &sock);

      if (clnt_handlep == NULL)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG,
		     _("clnt_create for server '%s' (domain '%s') failed"),
		     list->server[i].host, domain);
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
					       list->server[i].host));
          clnt_destroy(clnt_handlep);
	  ++i;
	  continue;
        }
      else if (out != TRUE)
        {
          log_msg (LOG_ERR, _("domain '%s' not served by '%s'"),
                   domain, list->server[i].host);
          clnt_destroy(clnt_handlep);
	  ++i;
	  continue;
        }
      else
        {
	  memcpy (&(list->server[i].port), &server_addr.sin_port,
		  sizeof (unsigned short int));
          list->client_handle = clnt_handlep;
          pthread_rdwr_wlock_np (&domainlock);
          list->active = i;
          pthread_rdwr_wunlock_np (&domainlock);
          pthread_rdwr_rlock_np (&domainlock);
          update_bindingfile (list);
          pthread_rdwr_runlock_np (&domainlock);
          return 1;
        }

      ++i;
      if (i == _MAXSERVER)
        {
          remove_bindingfile(list->domain);
          return 0;
        }
    }
  return 0;
}

#endif

void
do_binding (void)
{
  int i;

  pthread_mutex_lock (&search_lock);
  for (i = 0; i < max_domains; ++i)
    {
      if (!ping_all (&domainlist[i]) && domainlist[i].use_broadcast)
	do_broadcast (&domainlist[i]);
    }
  pthread_mutex_unlock (&search_lock);
}

/* This thread will send an ping to all NIS server marked as active. If
   a server doesn't answer or tell us, that he doesn't serv this domain
   any longer, we mark it as inactive and try to find a new server */
void *
test_bindings (void *param __attribute__ ((unused)))
{
  static int success = 0;
  int lastcheck = 0;

#ifdef USE_DBUS_NM
  if (is_online)
#endif
    do_binding ();

  if (ping_interval < 1)
    pthread_exit (&success);

  while (1)
    {
      sleep (ping_interval);

      /* Check, if ping_interval was changed through a SIGHUP.  */
      if (ping_interval < 1)
	pthread_exit (&success);

      lastcheck += ping_interval;
      if (lastcheck >= 900) /* 900 = 15min. */
	lastcheck = 0;

#if USE_DBUS_NM
      if (is_online)

#endif
	lastcheck = test_bindings_once (lastcheck, NULL);
    } /* end while() endless loop */
}

int
test_bindings_once (int lastcheck, const char *req_domain)
{
  int i;

  /* Since we need the write lock later, getting the read lock here is
     not enough. During the time, where we wait for the write lock, the
     other thread can modify our data. */
  pthread_rdwr_wlock_np (&domainlock);

  if (debug_flag)
    {
      if (lastcheck)
	log_msg (LOG_DEBUG, _("Pinging all active servers."));
      else
	log_msg (LOG_DEBUG, _("Checking for new fastest server."));
    }

  for (i = 0; i < max_domains; ++i)
    {
      char *domain = domainlist[i].domain;
      bool_t out = TRUE;
      enum clnt_stat status = RPC_SUCCESS;

      if (req_domain && strcmp (domain, req_domain) != 0)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG, _("Requested domain %s, found %s, ignored."),
		     req_domain, domain);
	  continue;
	}

      /* We should never run into this. For debugging.  */
      if (domainlist[i].client_handle == NULL && domainlist[i].active != -1)
	{
	  log_msg (LOG_ERR, "ALERT: active=%d, but client_handle is NULL!",
		   domainlist[i].active);
	  domainlist[i].active = -1;
	}

      if (domainlist[i].active != -1)
	{
	  /* The binding is in use, check if it is still valid and
	     the fastest one. */
	  if (lastcheck != 0)
	    {
	      /* Check only if the current binding is still valid. */
	      struct timeval time_out;

	      time_out.tv_sec = 3;
	      time_out.tv_usec = 0;
	      status =
		clnt_call(domainlist[i].client_handle,
			  YPPROC_DOMAIN, (xdrproc_t) ypbind_xdr_domainname,
			  (caddr_t) &domain, (xdrproc_t) xdr_bool,
			  (caddr_t) &out, time_out);
	    }

	  /* time to search a new fastest server, but only if the current
	     one was not set with ypset. We search in every case if the
	     above check fails and the current data is not longer valid. */
	  if ((lastcheck == 0 && domainlist[i].active != -2)
	      || status != RPC_SUCCESS || out != TRUE)
	    {
	      /* The current binding is not valid or it is time to search
		 for a new, fast server. */
	      if (debug_flag && lastcheck != 0)
		{
		  /* Current active binding is not longer valid, print
		     the old binding for debugging. */
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
	      /* We can destroy the client_handle since we are the
		 only thread who uses it. */
	      /* client_handle can be NULL? */
	      if (domainlist[i].client_handle == NULL)
		{
		  log_msg (LOG_ERR, "ALERT: client_handle=NULL, active=%d, lastcheck=%d, domain=%s",
			   domainlist[i].active, lastcheck, domain);
		}
	      else
		clnt_destroy (domainlist[i].client_handle);
	      domainlist[i].client_handle = NULL;
	      if (domainlist[i].active == -2)
		{
		  /* We can give this free, server does not answer any
		     longer. */
		  if (domainlist[i].ypset.host != NULL)
		    free (domainlist[i].ypset.host);
		  domainlist[i].ypset.host = NULL;
		}
	      domainlist[i].active = -1;
	      lastcheck = 0; /* If we need a new server before the TTL expires,
				reset it. */
	      /* And give the write lock away, search a new host and get
		 the write lock again. */
	      pthread_rdwr_wunlock_np (&domainlock);
	      pthread_mutex_lock (&search_lock);
	      if (!ping_all (&domainlist[i]) &&
		  domainlist[i].use_broadcast)
		do_broadcast (&domainlist[i]);
	      pthread_mutex_unlock (&search_lock);
	      pthread_rdwr_wlock_np (&domainlock);
	    }
	}
      else
	{
	  /* there is no binding for this domain, try to find a new
	     server */
	  pthread_rdwr_wunlock_np (&domainlock);
	  pthread_mutex_lock (&search_lock);
	  if (!ping_all (&domainlist[i]) && domainlist[i].use_broadcast)
	    do_broadcast (&domainlist[i]);
	  pthread_mutex_unlock (&search_lock);
	  pthread_rdwr_wlock_np (&domainlock);
	}
    } /* end for () all domains */

  pthread_rdwr_wunlock_np (&domainlock);

  return lastcheck;
}
