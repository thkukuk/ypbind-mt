/* Copyright (c) 1998-2009, 2011, 2012, 2013, 2014 Thorsten Kukuk
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
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "ypbind.h"
#include "log_msg.h"
#include "local.h"
#include "pthread_np.h"

extern int verbose_flag;

#define _(String) gettext (String)

#define _MAXSERVER 30

struct binding
{
  char domain[YPMAXDOMAIN + 1];
  int active; /* index into server, -2 means ypset */
  bool_t use_broadcast;
  struct ypbind3_binding *server[_MAXSERVER];
  struct ypbind3_binding *ypset;
};

static const char *
get_server_str (struct ypbind3_binding *ypb3)
{
  if (ypb3->ypbind_servername != NULL)
    return ypb3->ypbind_servername;
  else
    {
      static char buf[INET6_ADDRSTRLEN];

      return taddr2ipstr (ypb3->ypbind_nconf, ypb3->ypbind_svcaddr,
			  buf, sizeof (buf));
    }

}

static const char *
bound_host (struct binding *bptr)
{
  if (bptr->active >= 0)
    return get_server_str (bptr->server[bptr->active]);
  else if (bptr->active == -2)
    return get_server_str (bptr->ypset);
  else
    return "Unknown Host";
}

static struct binding *domainlist = NULL;
static int max_domains = 0;
static pthread_rdwr_t domainlock = PTHREAD_RDWR_INITIALIZER;
static pthread_mutex_t search_lock = PTHREAD_MUTEX_INITIALIZER;

static void do_broadcast (struct binding *list);
static int ping_all (struct binding *list);

#ifdef USE_DBUS_NM
/* We have localhost defined in one of the domains.
 * If so, we don't need to be connected to outer network. */
void
check_localhost()
{
  int i, s;
  localhost_used = 0;
  for (i = 0; i < max_domains; ++i)
    {
      for (s = 0; s < _MAXSERVER; ++s)
        {
	  if (domainlist[i].server[s].host == NULL)
	    break;
          if (strncmp(inet_ntoa(domainlist[i].server[s].addr), "127", 3) == 0)
            {
       	      localhost_used = 1;
      	      return;
            }
        }
    }
}
#endif

static void
ypbind3_binding_free (struct ypbind3_binding *ypb)
{
  if (ypb == NULL)
    return;
  /* XXX netdir_free ((char *)ypb->ypbind_svcaddr, ND_ADDR); */
  free (ypb->ypbind_servername);
  freenetconfigent (ypb->ypbind_nconf);
  free (ypb);
}

static struct ypbind3_binding *
ypbind3_binding_dup (struct ypbind3_binding *src)
{
#define copy_str(source, dest) \
  if (source != NULL) \
    { \
      dest = strdup (source); \
      if (dest == NULL) \
        { \
          ypbind3_binding_free (dst); \
          return NULL; \
	} \
    }

  struct ypbind3_binding *dst;
  int i;

  dst = calloc(1, sizeof (struct ypbind3_binding));
  if (dst == NULL)
    return NULL;

  dst->ypbind_nconf = calloc (1, sizeof (struct netconfig));
  if (dst->ypbind_nconf == NULL)
    {
      ypbind3_binding_free (dst);
      return NULL;
    }
  dst->ypbind_svcaddr = calloc(1, sizeof (struct netbuf));
  if (dst->ypbind_svcaddr == NULL)
    {
      ypbind3_binding_free (dst);
      return NULL;
    }
  dst->ypbind_hi_vers = src->ypbind_hi_vers;
  dst->ypbind_lo_vers = src->ypbind_lo_vers;
  if (src->ypbind_servername)
    dst->ypbind_servername =
      strdup(src->ypbind_servername);

  copy_str (src->ypbind_nconf->nc_netid, dst->ypbind_nconf->nc_netid);
  dst->ypbind_nconf->nc_semantics = src->ypbind_nconf->nc_semantics;
  dst->ypbind_nconf->nc_flag = src->ypbind_nconf->nc_flag;
  copy_str (src->ypbind_nconf->nc_protofmly, dst->ypbind_nconf->nc_protofmly);
  copy_str (src->ypbind_nconf->nc_proto, dst->ypbind_nconf->nc_proto);
  copy_str (src->ypbind_nconf->nc_device, dst->ypbind_nconf->nc_device);
  dst->ypbind_nconf->nc_nlookups = src->ypbind_nconf->nc_nlookups;

  dst->ypbind_nconf->nc_lookups = calloc (src->ypbind_nconf->nc_nlookups,
					  sizeof (char *));
  if (dst->ypbind_nconf->nc_lookups == NULL)
    {
      ypbind3_binding_free (dst);
      return NULL;
    }
  for (i = 0; i < src->ypbind_nconf->nc_nlookups; i++)
    dst->ypbind_nconf->nc_lookups[i] =
      src->ypbind_nconf->nc_lookups[i] ?
      strdup (src->ypbind_nconf->nc_lookups[i]) : NULL;

  for (i = 0; i < 8; i++)
    dst->ypbind_nconf->nc_unused[i] = src->ypbind_nconf->nc_unused[i];

  dst->ypbind_svcaddr->maxlen = src->ypbind_svcaddr->maxlen;
  dst->ypbind_svcaddr->len = src->ypbind_svcaddr->len;
  dst->ypbind_svcaddr->buf = malloc(src->ypbind_svcaddr->maxlen);
  if (dst->ypbind_svcaddr->buf == NULL)
    {
      ypbind3_binding_free (dst);
      return NULL;
    }
  memcpy (dst->ypbind_svcaddr->buf, src->ypbind_svcaddr->buf,
	  src->ypbind_svcaddr->len);

  return dst;
}


static struct ypbind2_resp
convert_v3_to_respv2 (struct ypbind3_binding *ypb3)
{
  struct sockaddr_in *sin;
  struct ypbind2_resp resp;

  memset (&resp, '\0', sizeof (resp));

  resp.ypbind_status = YPBIND_SUCC_VAL;

  sin = (struct sockaddr_in *)
    ypb3->ypbind_svcaddr->buf;
  if (sin->sin_family == AF_INET)
    {
      resp.ypbind2_addr = sin->sin_addr;
      resp.ypbind2_port = sin->sin_port;
    }
  else
    {
      resp.ypbind_status = YPBIND_FAIL_VAL;
      resp.ypbind2_error = YPBIND_ERR_NOSERV;
    }

  return resp;
}

static void
remove_bindingfile (struct binding *entry)
{
  const char *domain_name = entry->domain;
  char path[strlen (BINDINGDIR) + strlen (domain_name) + 10];

  sprintf (path, "%s/%s.1", BINDINGDIR, domain_name);
  unlink (path);
  sprintf (path, "%s/%s.2", BINDINGDIR, domain_name);
  unlink (path);
  sprintf (path, "%s/%s.3", BINDINGDIR, domain_name);
  unlink (path);
}

#define FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

/* XXX Add binding file version 3 */
static void
update_bindingfile (struct binding *entry)
{
  /* The calling functions must hold a lock ! */
  unsigned short int sport = port;
  struct iovec iov[2];
  struct ypbind2_resp ypbres2;
  char path1[MAXPATHLEN + 1];
  char path2[MAXPATHLEN + 1];
  char path3[MAXPATHLEN + 1];
  int fd, len;

  sprintf (path1, "%s/%s.1", BINDINGDIR, entry->domain);
  sprintf (path2, "%s/%s.2", BINDINGDIR, entry->domain);
  sprintf (path3, "%s/%s.3", BINDINGDIR, entry->domain);

  if (entry->active >= 0)
      ypbres2 = convert_v3_to_respv2 (entry->server[entry->active]);
  else if (entry->active == -2) /* ypset was used */
    ypbres2 = convert_v3_to_respv2 (entry->ypset);
  else
    {
       /* This should not happen. Remove binding files which means,
          libc will query ypbind direct. */
       unlink (path1);
       unlink (path2);
       unlink (path3);
       log_msg (LOG_ERR, "INTERNAL ERROR: update_bindingfile called without valid data!");
       return;
    }

  iov[0].iov_base = (caddr_t) &sport;
  iov[0].iov_len = sizeof (sport);
  iov[1].iov_base = (caddr_t) &ypbres2;
  iov[1].iov_len = sizeof ypbres2;

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
#ifdef USE_DBUS_NM
  check_localhost();
#endif
}

/* this is called from the RPC thread (ypset). */
void
change_binding (const char *domain, ypbind3_binding *binding)
{
  int i;

  pthread_rdwr_rlock_np (&domainlock);

  for (i = 0; i < max_domains; ++i)
    {
      if (strcmp (domainlist[i].domain, domain) == 0)
	{
	  pthread_rdwr_runlock_np (&domainlock);
	  pthread_rdwr_wlock_np (&domainlock);

	  domainlist[i].ypset = ypbind3_binding_dup (binding);
	  domainlist[i].active = -2;

	  pthread_rdwr_wunlock_np (&domainlock);

	  pthread_rdwr_rlock_np (&domainlock);
	  update_bindingfile (&domainlist[i]);
	  pthread_rdwr_runlock_np (&domainlock);

	  if (verbose_flag)
	    {
	      log_msg (LOG_NOTICE, "NIS server set to '%s'"
		       " for domain '%s'",
		       bound_host(&domainlist[i]), domainlist[i].domain);
	    }
	  if (logfile_flag && (logfile_flag & LOG_SERVER_CHANGES))
	    {
	      log2file ("NIS server for domain '%s' set to '%s' ",
			domainlist[i].domain,
			bound_host(&domainlist[i]));
	    }

	  return;
	}
    }

  pthread_rdwr_runlock_np (&domainlock);
  return;
}

void
find_domain_v3 (const char *domain, ypbind3_resp *result)
{
  int i, count = 0;

  if (domainlist == NULL)
    return;

  pthread_rdwr_rlock_np (&domainlock);

  for (i = 0; i < max_domains; ++i)
    if (strcmp (domainlist[i].domain, domain) == 0)
      break;

  if (i >= max_domains)
    {
      pthread_rdwr_runlock_np (&domainlock);
      return;
    }

 again:
  ++count;
  if (domainlist[i].active >= 0)
    {
      result->ypbind_status = YPBIND_SUCC_VAL;
      result->ypbind_respbody.ypbind_bindinfo =
	ypbind3_binding_dup (domainlist[i].server[domainlist[i].active]);

#if 0 /* XXX */
      if (debug_flag)
	log_msg (LOG_DEBUG, "YPBINDPROC_DOMAIN: server '%s', port %d",
		 inet_ntoa(domainlist[i].server[domainlist[i].active].addr),
		 ntohs(domainlist[i].server[domainlist[i].active].port));
#endif
    }
  else if (domainlist[i].active == -2)
    {
      result->ypbind_status = YPBIND_SUCC_VAL;
      result->ypbind_respbody.ypbind_bindinfo =
	ypbind3_binding_dup (domainlist[i].ypset);

#if 0 /* XXX */
      if (debug_flag)
	log_msg (LOG_DEBUG,
		 "YPBINDPROC_DOMAIN: server '%s', port %d",
		 inet_ntoa(domainlist[i].ypset.addr),
		 ntohs(domainlist[i].ypset.port));
#endif
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
find_domain_v2 (const char *domain, ypbind2_resp *result)
{
  struct ypbind3_resp res3;

  memset (&res3, '\0', sizeof (struct ypbind3_resp));

  find_domain_v3 (domain, &res3);

  if (res3.ypbind_status == YPBIND_SUCC_VAL)
    {
      *result = convert_v3_to_respv2 (res3.ypbind_respbody.ypbind_bindinfo);
      ypbind3_binding_free (res3.ypbind_respbody.ypbind_bindinfo);
    }
  else
    {
      result->ypbind_status = res3.ypbind_status;
      result->ypbind_respbody.ypbind_error = res3.ypbind_respbody.ypbind_error;
    }

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
	      remove_bindingfile (&domainlist[i]);
	      for (j = 0; j < _MAXSERVER; ++j)
		{
		  if (domainlist[i].server[j] != NULL)
		    {
		      ypbind3_binding_free (domainlist[i].server[j]);
		      domainlist[i].server[j] = NULL;
		    }
		}
	      if (domainlist[i].ypset != NULL)
		{
		  ypbind3_binding_free (domainlist[i].ypset);
		  domainlist[i].ypset = NULL;
		}
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
      domainlist[max_domains - 1].ypset = NULL;
      domainlist[max_domains - 1].active = (-1);
      domainlist[max_domains - 1].use_broadcast = FALSE;
      memset (domainlist[max_domains - 1].server, 0,
	      (_MAXSERVER * sizeof (struct ypbind3_binding *)));
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
      /* find empty slot */
      for (active = 0; active < _MAXSERVER; ++active)
	if (entry->server[active] == NULL)
	  break;

      /* There is no empty slot */
      if (active >= _MAXSERVER)
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

#if 0 /* XXX create ypbind3_binding for host. */
      entry->server[active].host = strdup (host);
      entry->server[active].family = hent->h_addrtype;
#ifdef USE_DBUS_NM
      check_localhost();
#endif
      res = 1;
#endif
    }

 exit:
  pthread_rdwr_wunlock_np (&domainlock);
  return res;
}

static struct binding *in_use = NULL;

static bool_t
eachresult (bool_t *out, struct netbuf *nbuf, struct netconfig *nconf)
{
  if (*out)
    {
      struct ypbind3_binding ypb3;
      if(debug_flag)
        {
	  char hostbuf[MAXHOSTNAMELEN];

	  log_msg (LOG_DEBUG,
		   _("Answer for domain '%s' from server '%s'"),
		   in_use->domain, taddr2host (nconf, nbuf,
					       hostbuf, sizeof (hostbuf)));
        }

#if 0 /* XXX check how to get the port */
      if (!broken_server && (ntohs(addr->sin_port) >= IPPORT_RESERVED))
	{
          log_msg (LOG_ERR,
		   _("Answer for domain '%s' from '%s' on illegal port %d."),
		   in_use->domain, inet_ntoa (addr->sin_addr),
		   ntohs (addr->sin_port));
          return 0;
        }
#endif

      ypb3.ypbind_nconf = nconf;
      ypb3.ypbind_svcaddr = nbuf;
      ypb3.ypbind_servername = NULL;
      ypb3.ypbind_hi_vers = YPVERS;
      ypb3.ypbind_lo_vers = YPVERS;
      in_use->server[0] = ypbind3_binding_dup (&ypb3);
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

  status = rpc_broadcast (YPPROG, YPVERS, YPPROC_DOMAIN_NONACK,
			  (xdrproc_t) xdr_domainname, (void *)&domain,
			  (xdrproc_t) xdr_bool, (void *)&out,
			  (resultproc_t) eachresult, "udp");

  if (status != RPC_SUCCESS)
    {
      remove_bindingfile (list);
      log_msg (LOG_ERR, "broadcast: %s.", clnt_sperrno (status));
    }
  else
    update_bindingfile (list);

  pthread_rdwr_runlock_np (&domainlock);

  if (debug_flag)
    log_msg (LOG_DEBUG, _("leave do_broadcast() for domain '%s'"),
	     domain);
}


static int
ping_all (struct binding *list)
{
  bool_t out;
  enum clnt_stat status;
  struct timeval timeout;
  CLIENT *clnt_handlep = NULL;
  int i = 0;
  int old_active = list->active;

  if (list->server[0] == NULL) /* There is no known server */
    return 0;

  pthread_rdwr_wlock_np (&domainlock);
  list->active = -1;
  pthread_rdwr_wunlock_np (&domainlock);

  while (list->server[i] != NULL && i < _MAXSERVER)
    {
      char buf[INET6_ADDRSTRLEN];
      const char *host;

      if (list->server[i]->ypbind_servername != 0)
	host = list->server[i]->ypbind_servername;
      else
	host = taddr2ipstr (list->server[i]->ypbind_nconf,
			    list->server[i]->ypbind_svcaddr,
			    buf, sizeof (buf));

      if (debug_flag)
        log_msg (LOG_DEBUG, _("ping host '%s', domain '%s'"),
		 host, list->domain);

      timeout.tv_sec = 1;
      timeout.tv_usec = 0;


      clnt_handlep = clnt_create (host, YPPROG, YPVERS, "udp");

      if (clnt_handlep == NULL)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG,
		     _("clnt_create for server '%s' (domain '%s') failed"),
		     host, list->domain);
	  ++i;
	  continue;
	}

      timeout.tv_sec = 5;
      timeout.tv_usec = 0;
      status = clnt_call(clnt_handlep, YPPROC_DOMAIN,
                         (xdrproc_t) xdr_domainname, (caddr_t) &domain,
                         (xdrproc_t) xdr_bool, (caddr_t) &out, timeout);
      if (RPC_SUCCESS != status)
        {
          log_msg (LOG_ERR, "%s", clnt_sperror (clnt_handlep, host));
          clnt_destroy (clnt_handlep);
	  ++i;
	  continue;
        }
      else if (out != TRUE)
        {
          log_msg (LOG_ERR, _("domain '%s' not served by '%s'"),
                   domain, host);
          clnt_destroy (clnt_handlep);
	  ++i;
	  continue;
        }
      else
        {
          clnt_destroy (clnt_handlep);
          pthread_rdwr_wlock_np (&domainlock);
          list->active = i;
          pthread_rdwr_wunlock_np (&domainlock);
          pthread_rdwr_rlock_np (&domainlock);
          update_bindingfile (list);
          pthread_rdwr_runlock_np (&domainlock);
	  if (debug_flag)
	    log_msg (LOG_DEBUG,
		     _("Answer for domain '%s' from server '%s'"),
		     domain, host);

	  if (logfile_flag && (logfile_flag & LOG_SERVER_CHANGES) &&
	      old_active != list->active)
	    {
	      if (old_active == -1)
		log2file ("NIS server for domain '%s' set to '%s'",
			  domain, host);
	      else
		log2file ("NIS server for domain '%s' changed from '%s' to '%s'",
			  domain, get_server_str (list->server[old_active]),
			  host);
	    }

          return 1;
        }

      ++i;
      if (i == _MAXSERVER)
        {
          remove_bindingfile(list);
          return 0;
        }
    }
  return 0;
}


void
do_binding (void)
{
  int i;

  pthread_mutex_lock (&search_lock);
  for (i = 0; i < max_domains; ++i)
    {
      int active = domainlist[i].active;

      if (!ping_all (&domainlist[i]) && domainlist[i].use_broadcast)
	do_broadcast (&domainlist[i]);
      if (verbose_flag &&
	  domainlist[i].active >= 0 && active != domainlist[i].active)
	{
	  log_msg (LOG_NOTICE, "NIS server is '%s' for domain '%s'",
		   bound_host(&domainlist[i]), domainlist[i].domain);
    	}
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
  if (is_online || localhost_used)
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
      if (lastcheck >= rebind_interval) /* default 900 = 15min. */
	lastcheck = 0;

#if USE_DBUS_NM
      if (is_online || localhost_used)

#endif
	lastcheck = test_bindings_once (lastcheck, NULL);
    } /* end while() endless loop */
}

int
test_bindings_once (int lastcheck, const char *req_domain)
{
  int i, active;

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

      active = domainlist[i].active;

      if (domainlist[i].active != -1)
	{
	  /* The binding is in use, check if it is still valid*/
	  if (lastcheck != 0)
	    {
	      CLIENT *client_handle =
		clnt_create (bound_host (&domainlist[i]),
			     YPPROG, YPVERS, "udp");
	      if (client_handle == NULL)
		{
		  if (verbose_flag)
		    log_msg (LOG_NOTICE,
			     "NIS server '%s' for domain '%s' not reachable",
			     bound_host(&domainlist[i]),
			     domainlist[i].domain);
		  status = RPC_CANTSEND;
		}
	      else
		{
		  /* Check only if the current binding is still valid. */
		  struct timeval time_out;

		  time_out.tv_sec = 3;
		  time_out.tv_usec = 0;
		  status =
		    clnt_call(client_handle, YPPROC_DOMAIN,
			      (xdrproc_t) xdr_domainname,
			      (caddr_t) &domain,
			      (xdrproc_t) xdr_bool,
			      (caddr_t) &out, time_out);
		  if (verbose_flag && status != RPC_SUCCESS)
		    log_msg (LOG_NOTICE,
			     "NIS server '%s' not responding for domain '%s'",
			     bound_host(&domainlist[i]),
			     domainlist[i].domain);
		  clnt_destroy (client_handle);
		}
	    }
	  /* time to search a new fastest server, but only if the current
	     one was not set with ypset. We search in every case if the
	     above check fails and the current data is not longer valid. */
	  if ((lastcheck == 0 && domainlist[i].active != -2)
	      || status != RPC_SUCCESS || out != TRUE)
	    {
	      /* The current binding is not valid or it is time to search
		 for a new, fast server. */

	      if (domainlist[i].active == -2)
		{
		  /* We can give this free, server does not answer any
		     longer. */
		  if (domainlist[i].ypset != NULL)
		    ypbind3_binding_free (domainlist[i].ypset);
		  domainlist[i].ypset = NULL;
		}
	      lastcheck = 0; /* If we need a new server before the TTL expires,
				reset it. */
	      /* And give the write lock away, search a new host and get
		 the write lock again. */
	      pthread_rdwr_wunlock_np (&domainlock);
	      pthread_mutex_lock (&search_lock);
	      if (domainlist[i].use_broadcast)
		do_broadcast (&domainlist[i]);
	      else
		ping_all (&domainlist[i]);
	      pthread_mutex_unlock (&search_lock);
	      pthread_rdwr_wlock_np (&domainlock);
	    }
	}
      else /* domainlist[i].active == -1 */
	{
	  /* there is no binding for this domain, try to find a new
	     server */
	  pthread_rdwr_wunlock_np (&domainlock);
	  pthread_mutex_lock (&search_lock);
	  if (domainlist[i].use_broadcast)
	    do_broadcast (&domainlist[i]);
	  else
	    ping_all (&domainlist[i]);
	  pthread_mutex_unlock (&search_lock);
	  pthread_rdwr_wlock_np (&domainlock);
	}
      if (verbose_flag &&
          domainlist[i].active >= 0 && active != domainlist[i].active)
	{
	  log_msg (LOG_NOTICE, "NIS server is '%s' for domain '%s'",
	      bound_host(&domainlist[i]), domainlist[i].domain);
	}
    } /* end for () all domains */

  pthread_rdwr_wunlock_np (&domainlock);

  return lastcheck;
}
