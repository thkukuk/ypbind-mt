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
  int active; /* index into server, -2 means "other" */
  bool_t use_broadcast;
  struct ypbind3_binding *server[_MAXSERVER];
  struct ypbind3_binding *other;
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
    return get_server_str (bptr->other);
  else
    return "Unknown Host";
}

static struct binding *domainlist = NULL;
static int max_domains = 0;
static pthread_rdwr_t domainlock = PTHREAD_RDWR_INITIALIZER;
static pthread_mutex_t search_lock = PTHREAD_MUTEX_INITIALIZER;

static void do_broadcast (struct binding *list);
static int search_ypserver (struct binding *list);

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

static void
update_bindingfile (struct binding *entry)
{
  /* The calling functions must hold a lock ! */
  unsigned short int sport = ypbind_port;
  struct iovec iov[2];
  struct ypbind2_resp ypbres2;
  struct ypbind3_binding *ypb3;
  char path1[MAXPATHLEN + 1];
  char path2[MAXPATHLEN + 1];
  char path3[MAXPATHLEN + 1];
  int fd, len;
  FILE *fp;

  if (debug_flag)
    log_msg (LOG_DEBUG, "Update binding file for '%s' with '%s'",
	     entry->domain, bound_host (entry));

  /* XXX check length of path vs MAXPATHLEN */
  snprintf (path1, MAXPATHLEN, "%s/%s.1", BINDINGDIR, entry->domain);
  snprintf (path2, MAXPATHLEN, "%s/%s.2", BINDINGDIR, entry->domain);
  snprintf (path3, MAXPATHLEN, "%s/%s.3", BINDINGDIR, entry->domain);

  if (entry->active >= 0)
    ypb3 = entry->server[entry->active];
  else if (entry->active == -2) /* ypset/broadcast was used */
    ypb3 = entry->other;
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

  ypbres2 = convert_v3_to_respv2 (ypb3);
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
    log_msg (LOG_ERR, "open (%s): %s", path1, strerror (errno));

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
    log_msg (LOG_ERR, "open (%s): %s", path2, strerror (errno));

  /* Write binding information for version 3 protocol */
  if ((fp = fopen (path3, "wce")) == NULL)
    log_msg (LOG_ERR, "fopen (%s): %s", path3, strerror (errno));
  else
    {
      XDR xdrs;
      bool_t status;

      xdrstdio_create (&xdrs, fp, XDR_ENCODE);
      status = xdr_ypbind3_binding (&xdrs, ypb3);
      if (!status)
	{
	  log_msg (LOG_ERR, "write of %s failed!", path3);
	  unlink (path3);
	}
      xdr_destroy (&xdrs);
      fclose (fp);
    }

#ifdef USE_DBUS_NM
  check_localhost();
#endif
}

/* this is called from the RPC thread (ypset). */
int
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

	  if (domainlist[i].other != NULL)
	    __ypbind3_binding_free (domainlist[i].other);

	  domainlist[i].other = __ypbind3_binding_dup (binding);
	  domainlist[i].active = -2;

	  pthread_rdwr_wunlock_np (&domainlock);

	  pthread_rdwr_rlock_np (&domainlock);
	  if (verbose_flag || debug_flag)
	    log_msg (LOG_NOTICE, "NIS server for domain '%s' set to '%s'",
		     domainlist[i].domain, bound_host(&domainlist[i]));

	  update_bindingfile (&domainlist[i]);
	  pthread_rdwr_runlock_np (&domainlock);

	  return 0;
	}
    }

  pthread_rdwr_runlock_np (&domainlock);

  if (i >= max_domains)
    {
      log_msg (LOG_ERR, "ERROR: Domain '%s' not managed by us!", domain);
      return 1;
    }

  return 0;
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
	__ypbind3_binding_dup (domainlist[i].server[domainlist[i].active]);

      if (debug_flag)
	log_msg (LOG_DEBUG, "YPBINDPROC_DOMAIN: server '%s', port %d",
		 get_server_str (domainlist[i].server[domainlist[i].active]),
		 taddr2port (domainlist[i].server[domainlist[i].active]->ypbind_nconf,
			     domainlist[i].server[domainlist[i].active]->ypbind_svcaddr));
    }
  else if (domainlist[i].active == -2)
    {
      result->ypbind_status = YPBIND_SUCC_VAL;
      result->ypbind_respbody.ypbind_bindinfo =
	__ypbind3_binding_dup (domainlist[i].other);

      if (debug_flag)
	log_msg (LOG_DEBUG,
		 "YPBINDPROC_DOMAIN: server '%s', port %d",
		 get_server_str (domainlist[i].other),
		 taddr2port (domainlist[i].other->ypbind_nconf,
			     domainlist[i].other->ypbind_svcaddr));
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
	  if (!search_ypserver (&domainlist[i]) &&
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
      __ypbind3_binding_free (res3.ypbind_respbody.ypbind_bindinfo);
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
		      __ypbind3_binding_free (domainlist[i].server[j]);
		      domainlist[i].server[j] = NULL;
		    }
		}
	      if (domainlist[i].other != NULL)
		{
		  __ypbind3_binding_free (domainlist[i].other);
		  domainlist[i].other = NULL;
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
      domainlist[max_domains - 1].other = NULL;
      domainlist[max_domains - 1].active = (-1);
      domainlist[max_domains - 1].use_broadcast = FALSE;
      memset (domainlist[max_domains - 1].server, 0,
	      (_MAXSERVER * sizeof (struct ypbind3_binding *)));
      *entry = &domainlist[max_domains - 1];
    }

  return 0;
}

int
add_server (const char *domain, const char *host)
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

      entry->server[active] = __host2ypbind3_binding (host);
#ifdef USE_DBUS_NM
      check_localhost();
#endif
      res = 1;
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
	  char namebuf6[INET6_ADDRSTRLEN];

	  log_msg (LOG_DEBUG,
		   _("Answer for domain '%s' from server '%s'"),
		   in_use->domain, taddr2ipstr (nconf, nbuf,
						namebuf6, sizeof (namebuf6)));
        }

      if (!broken_server && (taddr2port (nconf, nbuf) >= IPPORT_RESERVED))
	{
	  char namebuf6[INET6_ADDRSTRLEN];

          log_msg (LOG_ERR,
		   _("Answer for domain '%s' from '%s' on illegal port %d."),
		   in_use->domain, taddr2ipstr (nconf, nbuf,
						namebuf6, sizeof (namebuf6)),
		   taddr2port (nconf, nbuf));
          return 0;
        }

      ypb3.ypbind_nconf = nconf;
      ypb3.ypbind_svcaddr = nbuf;
      ypb3.ypbind_servername = '\0';
      ypb3.ypbind_hi_vers = YPVERS;
      ypb3.ypbind_lo_vers = YPVERS;
      in_use->other = __ypbind3_binding_dup (&ypb3);
      in_use->active = -2;

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
  if (list->other != NULL)
    {
      __ypbind3_binding_free (list->other);
      list->other = NULL;
    }
  pthread_rdwr_wunlock_np (&domainlock);

  /* Get a reader lock while we do the broadcast. Normally we would
     need the writer lock, since we modify the data. But in this case,
     the broadcast timeout is too long and we would block all queries.
     Since we don't change pointers and all data is always valid, we
     only acquire the reader lock. */
  pthread_rdwr_rlock_np (&domainlock);

  in_use = list; /* global variable for eachresult */

  status = rpc_broadcast (YPPROG, YPVERS, YPPROC_DOMAIN_NONACK,
			  (xdrproc_t) xdr_domainname, (caddr_t) &domain,
			  (xdrproc_t) xdr_bool, (caddr_t) &out,
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
    log_msg (LOG_DEBUG, _("leave do_broadcast() for domain '%s'"), domain);
}

/* Go through the list of known server and look, which ones answers */
static int
search_ypserver (struct binding *list)
{
  int i = 0;
  int old_active = list->active;

  if (list->server[0] == NULL) /* There is no known server */
    return 0;

  pthread_rdwr_wlock_np (&domainlock);
  list->active = -1;
  pthread_rdwr_wunlock_np (&domainlock);

  while (list->server[i] != NULL && i < _MAXSERVER)
    {
      bool_t has_domain;
      struct timeval timeout;
      CLIENT *clnt_handlep = NULL;
      enum clnt_stat status;
      char ipbuf[INET6_ADDRSTRLEN];
      const char *host;
      char *domain = strdupa (list->domain);

      if (list->server[i]->ypbind_servername != 0)
	host = list->server[i]->ypbind_servername;
      else
	host = taddr2ipstr (list->server[i]->ypbind_nconf,
			    list->server[i]->ypbind_svcaddr,
			    ipbuf, sizeof (ipbuf));

      if (debug_flag)
        log_msg (LOG_DEBUG, _("ping host '%s', domain '%s'"),
		 host, list->domain);

      timeout.tv_sec = 1;
      timeout.tv_usec = 0;
      clnt_handlep = clnt_create_timed (host, YPPROG, YPVERS, "udp", &timeout);

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
      status = clnt_call (clnt_handlep, YPPROC_DOMAIN,
			  (xdrproc_t) xdr_domainname, &domain,
			  (xdrproc_t) xdr_bool, (caddr_t) &has_domain, timeout);

      if (status != RPC_SUCCESS)
        {
          log_msg (LOG_ERR, "%s", clnt_sperror (clnt_handlep, host));
          clnt_destroy (clnt_handlep);
	  ++i;
	  continue;
        }
      else if (has_domain != TRUE)
        {
          log_msg (LOG_ERR, _("domain '%s' not served by '%s'"),
                   list->domain, host);
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
	  if (debug_flag && old_active != list->active)
	    {
	      if (old_active == -1)
		log_msg (LOG_DEBUG, "NIS server for domain '%s' set to '%s'",
			 list->domain, host);
	      else
		log_msg (LOG_DEBUG,
			 "NIS server for domain '%s' changed from '%s' to '%s'",
			 list->domain, get_server_str (list->server[old_active]),
			 host);
	    }
	  else if (debug_flag)
	    log_msg (LOG_DEBUG,
		     _("Answer for domain '%s' from server '%s'"),
		     list->domain, host);

          update_bindingfile (list);
          pthread_rdwr_runlock_np (&domainlock);

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

      if (!search_ypserver (&domainlist[i]) && domainlist[i].use_broadcast)
	do_broadcast (&domainlist[i]);
      if (verbose_flag &&
	  domainlist[i].active >= 0 && active != domainlist[i].active)
	{
	  log_msg (LOG_NOTICE, "NIS server for domain '%s' is '%s'",
		   domainlist[i].domain, bound_host(&domainlist[i]));
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

#ifdef USE_DBUS_NM
      if (is_online || localhost_used)

#endif
        check_binding (NULL);
    } /* end while() endless loop */
}

int
check_binding (const char *req_domain)
{
  int i, old_active;
  int found_domain = 0;

  /* Since we need the write lock later, getting the read lock here is
     not enough. During the time, where we wait for the write lock, the
     other thread can modify our data. */
  pthread_rdwr_wlock_np (&domainlock);

  if (debug_flag)
    {
      if (req_domain)
	log_msg (LOG_DEBUG, _("Ping active server for '%s'"), req_domain);
      else
	log_msg (LOG_DEBUG, _("Ping active servers for all domains."));
    }

  for (i = 0; i < max_domains; ++i)
    {
      char *domain = domainlist[i].domain;
      bool_t has_domain = TRUE;
      enum clnt_stat status = RPC_SUCCESS;

      if (req_domain && strcmp (domain, req_domain) != 0)
	  continue;

      found_domain = 1;

      old_active = domainlist[i].active;

      if (domainlist[i].active != -1)
	{
	  const struct timeval TIMEOUT50 = {5, 0};
	  /* The binding is in use, check if it is still valid*/
	  CLIENT *client_handle = clnt_create_timed (bound_host (&domainlist[i]),
						     YPPROG, YPVERS, "udp", &TIMEOUT50);
	  if (client_handle == NULL)
	    {
	      if (verbose_flag || debug_flag)
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
	      status = clnt_call (client_handle, YPPROC_DOMAIN,
				  (xdrproc_t) xdr_domainname,
				  (caddr_t) &domain,
				  (xdrproc_t) xdr_bool,
				  (caddr_t) &has_domain, time_out);
	      if ((debug_flag || verbose_flag) && status != RPC_SUCCESS)
		log_msg (LOG_NOTICE,
			 "NIS server '%s' not responding for domain '%s'",
			 bound_host(&domainlist[i]),
			 domainlist[i].domain);
	      else if (status == RPC_SUCCESS && has_domain != TRUE)
		log_msg (LOG_ERR,
			 "NIS server '%s' does not support domain '%s'",
			 bound_host(&domainlist[i]),
			 domainlist[i].domain);

	      clnt_destroy (client_handle);
	    }
	  /* We need to search a new server */
	  if (status != RPC_SUCCESS || has_domain != TRUE)
	    {
	      /* The current binding is not valid or it is time to search
		 for a new, fast server. */

	      if (domainlist[i].active == -2)
		{
		  /* We can give this free, server does not answer any
		     longer. */
		  if (domainlist[i].other != NULL)
		    __ypbind3_binding_free (domainlist[i].other);
		  domainlist[i].other = NULL;
		}
	      domainlist[i].active = -1;
	    }
	}

      if (domainlist[i].active == -1)
	{
	  /* there is no binding for this domain, try to find a new
	     server */
	  pthread_rdwr_wunlock_np (&domainlock);
	  pthread_mutex_lock (&search_lock);
	  if (domainlist[i].use_broadcast)
	    do_broadcast (&domainlist[i]);
	  else
	    search_ypserver (&domainlist[i]);
	  pthread_mutex_unlock (&search_lock);
	  pthread_rdwr_wlock_np (&domainlock);
	}

      if (verbose_flag &&
          domainlist[i].active >= 0 && old_active != domainlist[i].active)
	{
	  log_msg (LOG_NOTICE, "NIS server for domain '%s' is '%s'",
		   domainlist[i].domain, bound_host(&domainlist[i]));
	}
    } /* end for () all domains */

  pthread_rdwr_wunlock_np (&domainlock);

  if (found_domain == 0)
    {
      if (!req_domain)
	log_msg (LOG_ERR, "ERROR? No single known domain!");

      if (debug_flag && req_domain)
	log_msg (LOG_DEBUG, "domain '%s' not known", req_domain);

      return 1;
    }

  return 0;
}
