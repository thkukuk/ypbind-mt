/* Copyright (c) 1998 - 2009, 2011, 2013, 2014 Thorsten Kukuk
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

#define _POSIX_PTHREAD_SEMANTICS /* for Solaris threads */

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <libintl.h>
#include <rpc/rpc.h>
#include <rpc/nettype.h>
#include <rpc/rpc_com.h>
#include <rpcsvc/yp_prot.h>
#include <pthread.h>
#include <nss.h>
#include <paths.h>
#if USE_SD_NOTIFY
#include <systemd/sd-daemon.h>
#endif

#include "ypbind.h"
#include "log_msg.h"
#include "local.h"

#define _(String) gettext (String)

#ifndef _PATH_VARRUN
#define _PATH_VARRUN "/etc/"
#endif
#ifndef _YPBIND_PIDFILE
#define _YPBIND_PIDFILE _PATH_VARRUN"ypbind.pid"
#endif

#define DEFAULT_CONFIG_FILE "/etc/yp.conf"
#define DEFAULT_RUNTIME_CONFIG "/run/yp.conf"

const char *configfile;
int ypset = SET_NO;
int use_broadcast = 0;
int broken_server = 0;
int foreground_flag = 0;
int ping_interval = 300;
int local_only = 0;
int ypbind_port = -1;
static char domain[1025];
static int lock_fd;
static int pid_is_written = 0;
static pthread_mutex_t mutex_pid = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond_pid = PTHREAD_COND_INITIALIZER;

static void
unlink_bindingdir (void)
{
  DIR *dird;
  char path[MAXPATHLEN];
  struct dirent *dirp;

  /* blow away everything in BINDINGDIR (if it exists) */
  if ((dird = opendir (BINDINGDIR)) != NULL)
    {
      while ((dirp = readdir (dird)) != NULL)
	if (strcmp (dirp->d_name, ".") &&
	    strcmp (dirp->d_name, ".."))
	  {
	    snprintf (path, MAXPATHLEN, "%s/%s", BINDINGDIR, dirp->d_name);
	    unlink (path);
	  }
      closedir (dird);
    }
}

/* Load or check syntax of the config file (/etc/yp.conf)  */
int
load_config (int check_syntax)
{
  FILE *fp;
  char *buf = NULL;
  size_t buflen = 0;
  int have_entries = 0; /* # of entries we found in config file */
  int bad_entries = 0;

  if (configfile)
    {
      fp = fopen (configfile, "r");
      if (NULL == fp)
	return 1;
    }
  else
  {
    configfile = DEFAULT_CONFIG_FILE;
    fp = fopen (configfile, "r");
    if (NULL == fp)
      {
	configfile = DEFAULT_RUNTIME_CONFIG;
	fp = fopen (DEFAULT_RUNTIME_CONFIG, "r");
	if (NULL == fp)
	  {
	    configfile = DEFAULT_CONFIG_FILE;
	    return 1;
	  }
      }
  }

  if (debug_flag)
    log_msg (LOG_DEBUG, "parsing config file");

  while (!feof (fp))
    {
      char tmpserver[81], tmpdomain[YPMAXDOMAIN + 1];
      int count;
      char *tmp, *cp;
      ssize_t n = getline (&buf, &buflen, fp);
      cp = buf;

      if (n < 1)
	break;

      tmp = strchr (cp, '#');  /* remove comments */
      if (tmp)
	*tmp = '\0';
      while (isspace ((int)*cp))    /* remove spaces and tabs */
        ++cp;
      if (*cp == '\0')        /* ignore empty lines */
        continue;

      if (cp[strlen (cp) - 1] == '\n')
	cp[strlen (cp) - 1] = '\0';

      if (debug_flag)
        log_msg (LOG_DEBUG, "%s %s", _("Trying entry:"), cp);

      if (check_syntax)
	printf ("%s %s\n", _("Trying entry:"), cp);

      if (strncmp (cp, "domain", 6) == 0 && isspace ((int)cp[6]))
	{
	  /* We have
	     domain <domain> server <host|ip>
	     or
	     domain <domain> broadcast
	  */

	  if (strstr (cp, "server") != NULL)
	    {
	      count = sscanf (cp, "domain %64s server %80s", tmpdomain,
			      tmpserver);
	      if (count == 2)
		{
		  if (debug_flag)
		    log_msg (LOG_DEBUG, _("parsed domain '%s' server '%s'"),
			     tmpdomain, tmpserver);
		  if (add_server (tmpdomain, tmpserver))
		    ++have_entries;
		  else
		    ++bad_entries;

		  continue;
		}
	    }
	  if (strstr (cp, "broadcast") != NULL)
	    {
	      count = sscanf (cp, "domain %s broadcast", tmpdomain);
	      if (count == 1)
		{
		  if (debug_flag)
		    log_msg (LOG_DEBUG, _("parsed domain '%s' broadcast"),
			     tmpdomain);
		  if (add_server (tmpdomain, NULL))
		    ++have_entries;
		  else
		    ++bad_entries;

		  continue;
		}
	    }
	}
      else if (strncmp (cp, "ypserver", 8) == 0 && isspace ((int)cp[8]))
	{
	  /* We have
	     ypserver <host|ip> */

	  count = sscanf (cp, "ypserver %80s", tmpserver);
	  if (count == 1)
	    {
	      if (debug_flag)
		log_msg (LOG_DEBUG, _("parsed ypserver %s"), tmpserver);
	      if (add_server (domain, tmpserver))
		++have_entries;
	      else
		++bad_entries;
	    }
	  else
	    ++bad_entries;
          continue;
	}
      else if (strncmp (cp, "broadcast", 9) == 0 &&
	       (isspace ((int)cp[9]) || cp[9] == '\0'))
	{
	  /* We have
	     broadcast  */

	  if (debug_flag)
	    log_msg (LOG_DEBUG, _("parsed broadcast"));
	  if (add_server (domain, NULL))
	    ++have_entries;
	  else
	    ++bad_entries;
	  continue;
	}
      if (check_syntax)
	{
	  fprintf (stderr, _("Entry \"%s\" is not valid!\n"), cp);
	  ++bad_entries;
	}
      else
	log_msg (LOG_ERR, _("Entry \"%s\" is not valid, ignore it!"), cp);
    }
  fclose (fp);

  if (buf)
    free (buf);

  if (check_syntax)
    {
      if (bad_entries)
	{
	  fprintf (stderr, _("Bad entries found.\n"));
	  return 1;
	}
      if (!have_entries)
	{
	  fprintf (stderr, _("No entry found.\n"));
	  return 1;
	}
    }

  if (!have_entries)
    {
      if (debug_flag)
        log_msg (LOG_DEBUG, _("No entry found."));
      return 1;
    }

  return 0;
}


/* Load the configuration, exiting if there's an error */
static void
load_config_or_exit(void)
{
  if (load_config (0) != 0)
    {
      fputs (_("No NIS server and no -broadcast option specified.\n"),
	     stderr);
      fprintf (stderr,
	       _("Add a NIS server to the %s configuration file,\n"),
	       DEFAULT_CONFIG_FILE);
      fputs (_("or start ypbind with the -broadcast option.\n"),
	     stderr);
      exit (1);
    }
}


/* Create a pidfile on startup */
static void
create_pidfile (void)
{
  struct flock lock;
  int left, written;
  pid_t pid;
  char pbuf[15], *ptr;
  int flags;

  lock_fd = open (_YPBIND_PIDFILE, O_CREAT | O_RDWR,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (lock_fd < 0)
    {
      log_msg (LOG_ERR, _("cannot create pidfile %s"), _YPBIND_PIDFILE);
      return;
    }

  /* Make sure file gets correctly closed when process finished.  */
  flags = fcntl (lock_fd, F_GETFD, 0);
  if (flags == -1)
    {
      /* Cannot get file flags.  */
      close (lock_fd);
      return;
    }
  flags |= FD_CLOEXEC;          /* Close on exit.  */
  if (fcntl (lock_fd, F_SETFD, flags) < 0)
    {
      /* Cannot set new flags.  */
      close (lock_fd);
      return;
    }

  lock.l_type = F_WRLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = 0;

  /* Is the pidfile locked by another ypserv ? */
  if (fcntl (lock_fd, F_GETLK, &lock) < 0)
    {
      if (errno != ENOLCK)
	{
	  log_msg (LOG_ERR, _("fcntl error: %s"), strerror (errno));
	  /* XXX look, which pid is in pidfile */
	}
      pid = 0;
    }
  else  if (lock.l_type == F_UNLCK)
    pid = 0;		   /* false, region is not locked by another proc */
  else
    pid = lock.l_pid;	   /* true, return pid of lock owner */

  if (pid != 0)
    {
      log_msg (LOG_ERR, _("ypbind-mt already running (pid %d) - exiting"),
	       pid);
      exit (1);
    }

  /* write lock */
  lock.l_type = F_WRLCK;
  lock.l_start = 0;
  lock.l_whence = SEEK_SET;
  lock.l_len = 0;
  if (fcntl (lock_fd, F_SETLK, &lock) != 0)
    log_msg (LOG_ERR, _("cannot lock pidfile"));
  sprintf (pbuf, "%ld\n", (long) getpid ());
  left = strlen (pbuf);
  ptr = pbuf;
  while (left > 0)
    {
      if ((written = write (lock_fd, ptr, left)) <= 0)
	return;			/* error */
      left -= written;
      ptr += written;
    }



  return;
}

/* Thread for handling signals */
static void *
sig_handler (void *v_param  __attribute__ ((unused)))
{
  struct flock lock;
  sigset_t sigs_to_catch;
  int caught;

  /* Create pid file in sig handler thread. Due the broken
     thread signal handling with Linux the pid must be the
     one of the thread handler */
  create_pidfile ();

  /* Signal the main thread that we have the pid file created
     and no other ypbind is running. So we can continue and
     unset bogus portmap information and register ourself */
  pthread_mutex_lock(&mutex_pid);
  pid_is_written = 1;
  pthread_cond_broadcast(&cond_pid);
  pthread_mutex_unlock(&mutex_pid);

  sigemptyset (&sigs_to_catch);
  sigaddset (&sigs_to_catch, SIGCHLD);
  sigaddset (&sigs_to_catch, SIGTERM);
  sigaddset (&sigs_to_catch, SIGINT);
  sigaddset (&sigs_to_catch, SIGQUIT);
  sigaddset (&sigs_to_catch, SIGSEGV);
  sigaddset (&sigs_to_catch, SIGHUP);
  sigaddset (&sigs_to_catch, SIGPIPE);

  while (1)
    {
      int ret = sigwait (&sigs_to_catch, &caught);
      if (ret != 0)
	{
	  if (ret != EINTR)
	    log_msg (LOG_ERR, _("sigwait failed: ret=%d."), ret);
	  continue;
	}
      switch (caught)
	{
	case SIGCHLD:
	  log_msg (LOG_ERR, _("SIGCHLD arrived, what should I do ?"));
	  break;
	case SIGTERM:
	case SIGINT:
	case SIGQUIT:
	case SIGSEGV:
	  /* Clean up if we quit the program. */
	  if (debug_flag)
	    log_msg (LOG_DEBUG, _("Signal (%d) for quitting program arrived."),
		     caught);
	  portmapper_disconnect ();
	  /* unlock pidfile */
	  lock.l_type = F_UNLCK;
	  lock.l_start = 0;
	  lock.l_whence = SEEK_SET;
	  lock.l_len = 0;
	  if (fcntl (lock_fd, F_SETLK, &lock) != 0)
	    log_msg (LOG_ERR, _("cannot unlock pidfile"));
	  close (lock_fd);
	  unlink (_YPBIND_PIDFILE);
	  unlink_bindingdir ();
	  if (logfile_flag)
	    {
	      log_msg (LOG_DEBUG, "Stopping %s-%s", PACKAGE, VERSION);
	      close_logfile ();
	    }
	  exit (0);
	  break;
	case SIGHUP:
	  /* Reload config file */
	  if (debug_flag)
	    log_msg (LOG_DEBUG, _("SIGHUP arrived, reloading config file."));
	  clear_server ();

	  if (use_broadcast)
	    add_server (domain, NULL);
	  else
	    load_config (0);

	  if (ping_interval < 1)
	    do_binding ();
	  break;
	case SIGPIPE:
	  if (debug_flag)
	    log_msg (LOG_DEBUG, _("Ignoring SIGPIPE."));
	  break;
	default:
	  log_msg (LOG_ERR, _("Unknown signal: %d"), caught);
	  break;
	}
    }
}
int verbose_flag;

static void
usage (int ret)
{
  FILE *output;

  if (ret)
    output = stderr;
  else
    output = stdout;

  fputs (_("Usage:\n"), output);
  fputs (_("\typbind [-broadcast | -ypset | -ypsetme] [-f configfile]\n\t  [-no-ping] [-broken-server] [-local-only] [-i ping-interval]\n\t  [-debug] [-verbose] [-n | -foreground]\n"), output);
  fputs (_("\typbind -c [-f configfile]\n"), output);
  fputs (_("\typbind --version\n"), output);
  exit (ret);
}


void
portmapper_disconnect (void)
{
  rpcb_unset (YPBINDPROG, YPBINDVERS_1, NULL);
  rpcb_unset (YPBINDPROG, YPBINDVERS_2, NULL);
  rpcb_unset (YPBINDPROG, YPBINDVERS, NULL);
}

/*
 * Quick check to see if rpcbind is up.  Tries to connect over
 * local transport.
 */
static bool_t
__rpcbind_is_up (void)
{
  struct netconfig *nconf;
  struct sockaddr_un sun;
  int sock;

  nconf = getnetconfigent ("local");
  if (nconf == NULL)
    return FALSE;

  memset (&sun, 0, sizeof sun);
  sock = socket (AF_LOCAL, SOCK_STREAM, 0);
  if (sock < 0)
    return FALSE;
  sun.sun_family = AF_LOCAL;
  strncpy (sun.sun_path, _PATH_RPCBINDSOCK, sizeof(sun.sun_path));

  if (connect (sock, (struct sockaddr *)&sun, SUN_LEN(&sun)) < 0)
    {
      close (sock);
      return FALSE;
    }

  close (sock);
  return TRUE;
}


static int
portmapper_register (void)
{
  struct netconfig *nconf;
  void *nc_handle;
  int connmaxrec = RPC_MAXDATASIZE;

  if (!__rpcbind_is_up()) {
    log_msg (LOG_ERR, "terminating: rpcbind is not running");
    return 1;
  }

  /* Set non-blocking mode and maximum record size for
     connection oriented RPC transports. */
  if (!rpc_control(RPC_SVC_CONNMAXREC_SET, &connmaxrec))
    log_msg (LOG_ERR, "unable to set maximum RPC record size");

  portmapper_disconnect ();

  nc_handle = __rpc_setconf ("netpath");   /* open netconfig file */
  if (nc_handle == NULL)
    {
      log_msg(LOG_ERR, "could not read /etc/netconfig, exiting..");
      return 1;
    }

  while ((nconf = __rpc_getconf (nc_handle)))
    {
      SVCXPRT *xprt;
      struct sockaddr *sa;
      struct sockaddr_in sin;
      struct sockaddr_in6 sin6;
      int sock;
      sa_family_t family; /* AF_INET, AF_INET6 */
      int type; /* SOCK_DGRAM (udp), SOCK_STREAM (tcp) */
      int proto; /* IPPROTO_UDP, IPPROTO_TCP */

      if (debug_flag)
	log_msg (LOG_DEBUG, "Register ypbind for %s,%s",
		 nconf->nc_protofmly, nconf->nc_proto);

      if (strcmp (nconf->nc_protofmly, "inet6") == 0)
	family = AF_INET6;
      else if (strcmp (nconf->nc_protofmly, "inet") == 0)
	family = AF_INET;
      else
	continue; /* we don't support nconf->nc_protofmly */

      if (strcmp (nconf->nc_proto, "udp") == 0)
	{
	  type = SOCK_DGRAM;
	  proto = IPPROTO_UDP;
	}
      else if (strcmp (nconf->nc_proto, "tcp") == 0)
	{
	  type = SOCK_STREAM;
	  proto = IPPROTO_TCP;
	}
      else
	continue; /* We don't support nconf->nc_proto */

      if ((sock = socket (family, type, proto)) < 0)
	{
	  log_msg (LOG_ERR, _("Cannot create socket for %s,%s: %s"),
		   nconf->nc_protofmly, nconf->nc_proto,
		   strerror (errno));
	  continue;
	}

      if (family == AF_INET6)
	{
	  /* Disallow v4-in-v6 to allow host-based access checks */
	  int i;

	  if (setsockopt (sock, IPPROTO_IPV6, IPV6_V6ONLY,
			  &i, sizeof(i)) == -1)
	    {
	      log_msg (LOG_ERR,
		       "ERROR: cannot disable v4-in-v6 on %s6 socket",
		       nconf->nc_proto);
	      return 1;
	    }
	}

      switch (family)
	{
	case AF_INET:
	  memset (&sin, 0, sizeof(sin));
	  sin.sin_family = AF_INET;
	  if (local_only)
	    sin.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
	  if (ypbind_port > 0)
	    sin.sin_port = htons (ypbind_port);
	  sa = (struct sockaddr *)(void *)&sin;
	  break;
	case AF_INET6:
	  memset (&sin6, 0, sizeof (sin6));
	  sin6.sin6_family = AF_INET6;
	  if (local_only)
	    sin6.sin6_addr = in6addr_any;
	  if (ypbind_port > 0)
	    sin6.sin6_port = htons (ypbind_port);
	  sa = (struct sockaddr *)(void *)&sin6;
	  break;
	default:
	  log_msg (LOG_ERR, _("Unsupported address family %d"), family);
	  return -1;
	}

      if (bindresvport_sa (sock, sa) == -1)
	{
	  if (ypbind_port > 0 && local_only)
	    log_msg (LOG_ERR, _("Cannot bind to reserved port %d and localhostonly (%s)"),
		     ypbind_port, strerror (errno));
	  else if (ypbind_port > 0)
	    log_msg (LOG_ERR, _("Cannot bind to reserved port %d (%s)"),
		     ypbind_port, strerror (errno));
	  else if (local_only)
	    log_msg (LOG_ERR, _("Cannot bind to localhost only (%s)"),
		     strerror (errno));
	  else
	    log_msg (LOG_ERR, _("bindresvport failed: %s"),
		     strerror (errno));
	  return 1;
	}

      if (type == SOCK_STREAM)
	{
	  listen (sock, SOMAXCONN);
	  xprt = svc_vc_create (sock, 0, 0);
	}
      else
	xprt = svc_dg_create (sock, 0, 0);

      if (xprt == NULL)
	{
	  log_msg (LOG_ERR, "terminating: cannot create rpcbind handle");
	  return 1;
	}

      rpcb_unset (YPBINDPROG, YPBINDVERS, nconf);
      if (!svc_reg (xprt, YPBINDPROG, YPBINDVERS, ypbindprog_3, nconf))
	{
	  log_msg (LOG_ERR,
		   _("unable to register (YPBINDPROG, 3) for %s, %s."),
		   nconf->nc_protofmly, nconf->nc_proto);
	  continue;
	}

      if (family == AF_INET)
	{
	  rpcb_unset (YPBINDPROG, YPBINDVERS_2, nconf);
	  if (!svc_reg (xprt, YPBINDPROG, YPBINDVERS_2,
			ypbindprog_2, nconf))
	    {
	      log_msg (LOG_INFO,
		       _("unable to register (YPBINDPROG, 2) [%s]"),
		       nconf->nc_netid);
	      continue;
	    }

	  rpcb_unset (YPBINDPROG, YPBINDVERS_1, nconf);
	  if (!svc_reg (xprt, YPBINDPROG, YPBINDVERS_1,
			ypbindprog_1, nconf))
	    {
	      log_msg (LOG_ERR,
		       _("unable to register (YPBINDPROG, 1)."));
	      continue;
	    }
	}
    }
  __rpc_endconf (nc_handle);

  return 0;
}

int
main (int argc, char **argv)
{
  int i;
  sigset_t sigs_to_block;
  pthread_t sig_thread, ping_thread;
  struct stat st;
  int configcheck_only = 0;

  setlocale (LC_MESSAGES, "");
  setlocale (LC_CTYPE, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  /* Parse commandline. */
  for (i = 1; i < argc; i++)
    {
      if (strcmp ("--version", argv[i]) == 0)
        {
          fprintf (stdout, "ypbind (%s) %s\n", PACKAGE, VERSION);
          exit (0);
        }
      else if (strcmp ("-ypset", argv[i]) == 0)
	ypset = SET_YPSET;
      else if (strcmp ("-ypsetme", argv[i]) == 0)
	ypset = SET_YPSETME;
      else if (strcmp ("-d", argv[i]) == 0 ||
	       strcmp ("-debug", argv[i]) == 0)
        debug_flag = 1;
      else if (strcmp ("-n", argv[i]) == 0 ||
	       strcmp ("-foreground", argv[i]) == 0)
        foreground_flag = 1;
      else if (strcmp ("-v", argv[i]) == 0 ||
	       strcmp ("-verbose", argv[i]) == 0)
        verbose_flag = 1;
      else if (strcmp ("-broken-server", argv[i]) == 0 ||
	       strcmp ("-broken_server", argv[i]) == 0)
        broken_server = 1;
      else if (strcmp ("-no-ping", argv[i]) == 0 ||
	       strcmp ("-no_ping", argv[i]) == 0)
	ping_interval = 0;
      else if (strcmp ("-broadcast", argv[i]) == 0)
	use_broadcast = 1;
      else if (strcmp ("-local-only", argv[i]) == 0 ||
	       strcmp ("-local_only", argv[i]) == 0)
	local_only = 1;
      else if (strcmp ("-f", argv[i]) == 0)
	{
	  if (i+1 == argc || argv[i+1][0] == '-')
	    usage (1);
	  ++i;
	  configfile = argv[i];
	}
      else if (strcmp ("-p", argv[i]) == 0)
	{
	  if (i+1 == argc || argv[i+1][0] == '-')
	    usage (1);
	  ++i;
	  ypbind_port = atoi (argv[i]);
	}
      else if (strcmp ("-ping-interval", argv[i]) == 0 ||
	       strcmp ("-ping_interval", argv[i]) == 0 ||
	       strcmp ("-i", argv[i]) == 0)
	{
	  if (i+1 == argc || argv[i+1][0] == '-')
	    usage (1);
	  ++i;
	  ping_interval = atoi (argv[i]);
	}
      else if (strcmp ("-c", argv[i]) == 0)
	configcheck_only = 1;
      else if (strcmp ("-log", argv[i]) == 0)
	{
	  logfile_flag = 1;
	  debug_flag = 1;
	}
      else if (strcmp ("--help", argv[i]) == 0)
        usage (0);
      else
	usage (1);
    }

  domain[0] = '\0';
  if (getdomainname (domain, sizeof(domain)) ||
      domain[0] == '\0' || strcmp(domain, "(none)") == 0)
    {
      if (configcheck_only)
	{
	  fputs (_("ERROR: domainname not set.\n"), stderr);
	}
      else
	{
	  fputs (_("domainname not set - aborting.\n"), stderr);
	  exit (1);
	}
    }

  if (configcheck_only)
    {
      if (load_config (1) != 0)
	{
	  fprintf (stderr, _("Config file %s is not ok.\n"), configfile);
	  exit (1);
	}
      else
	{
	  fprintf (stdout, _("Config file %s is ok.\n"), configfile);
	  exit (0);
	}
    }

  if (getuid() != 0)
    {
      fputs (_("ypbind must be run as root\n"), stderr);
      exit (1);
    }

  if (stat ("/var/yp", &st) == -1)
    if (mkdir ("/var/yp", (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH |
			   S_IXUSR | S_IXGRP | S_IXOTH )) < 0)
      {
	fprintf (stderr, _("Could not create %s: %s\n"),
		 "/var/yp", strerror (errno));
	exit (1);
      }

  if (stat (BINDINGDIR, &st) == -1)
    if (mkdir (BINDINGDIR, (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH |
			    S_IXUSR | S_IXGRP | S_IXOTH)) < 0)
      {
	fprintf (stderr, _("Could not create %s: %s\n"),
		 BINDINGDIR, strerror (errno));
	exit (1);
      }
  /* Change current directory to bindingdir */
  if (chdir (BINDINGDIR) < 0)
    {
      fprintf (stderr, _("Could not change to directory %s: %s\n"),
	       BINDINGDIR, strerror (errno));
      exit (1);
    }

  if (!use_broadcast)
    load_config_or_exit ();
  else
    add_server (domain, NULL);

  unlink_bindingdir ();

  openlog ("ypbind", LOG_PID, LOG_DAEMON);

  if (debug_flag)
    {
      log_msg (LOG_DEBUG, "[Welcome to ypbind-mt, version %s]\n", VERSION);
      log_msg (LOG_DEBUG, "ping interval is %d seconds\n", ping_interval);
    }
  else if (! foreground_flag)
    {
      int j;

      if ((j = fork()) > 0)
        exit(0);

      if (j < 0)
        {
          log_msg (LOG_ERR, "Cannot fork: %s\n", strerror (errno));
          exit (-1);
        }

      if (setsid() == -1)
        {
          log_msg (LOG_ERR, "Cannot setsid: %s\n", strerror (errno));
          exit (-1);
        }

      if ((j = fork()) > 0)
        exit(0);

      if (j < 0)
        {
          log_msg (LOG_ERR, "Cannot fork: %s\n", strerror (errno));
          exit (-1);
        }

      for (j = 0; j < getdtablesize (); ++j)
        close (j);
      errno = 0;

      umask (0);
      j = open ("/dev/null", O_RDWR);
      if (j < 0)
        {
          log_msg (LOG_ERR, "Cannot open /dev/null: %s\n", strerror (errno));
          exit (-1);
        }
      /* two dups: stdin, stdout, stderr */
      if (dup (j) == -1)
	{
          log_msg (LOG_ERR, "Cannot dup file handle: %s\n", strerror (errno));
          exit (-1);
	}
      if (dup (j) == -1)
	{
          log_msg (LOG_ERR, "Cannot dup file handle: %s\n", strerror (errno));
          exit (-1);
	}
    }

#if defined(HAVE___NSS_CONFIGURE_LOOKUP)
  /* We only use /etc/hosts and DNS query to avoid deadlocks */
  __nss_configure_lookup ("hosts", "files dns");
#endif /* HAVE___NSS_CONFIGURE_LOOKUP */

  sigemptyset (&sigs_to_block);
  sigaddset (&sigs_to_block, SIGCHLD);
  sigaddset (&sigs_to_block, SIGTERM);
  sigaddset (&sigs_to_block, SIGINT);
  sigaddset (&sigs_to_block, SIGQUIT);
  sigaddset (&sigs_to_block, SIGSEGV);
  sigaddset (&sigs_to_block, SIGHUP);
  sigaddset (&sigs_to_block, SIGPIPE);
  if (pthread_sigmask (SIG_BLOCK, &sigs_to_block, NULL) != 0)
    {
      log_msg (LOG_ERR, _("Could not block signals."));
      exit (1);
    }

  pthread_create (&sig_thread, NULL, &sig_handler, NULL);

  /* wait until signal thread has created the pid file */
  pthread_mutex_lock(&mutex_pid);
  while (pid_is_written < 1)
    {
      pthread_cond_wait(&cond_pid, &mutex_pid);
    }
  pthread_mutex_unlock(&mutex_pid);

  if (logfile_flag)
    log_msg (LOG_DEBUG, "Starting %s-%s", PACKAGE, VERSION);

  portmapper_disconnect ();
  if (portmapper_register () != 0)
    {
      portmapper_disconnect ();
      exit (1);
    }

  pthread_create (&ping_thread, NULL, &test_bindings, NULL);

#if USE_SD_NOTIFY
  {
    /*
     * If we use systemd as an init process we may want to give it
     * a message, that ypbind daemon is ready to accept connections.
     * At this time, sockets for receiving connections are already
     * created, so we can say we're ready now.
     */
    int result;
    result = sd_notifyf(0, "READY=1\n"
                           "STATUS=Processing requests...\n"
                           "MAINPID=%lu", (unsigned long) getpid());

    /*
     * Return code from sd_notifyf can be ignored, as per sd_notifyf(3).
     * However, if we use systemd's native unit file, we need to send
     * this message to let systemd know that daemon is ready.
     * Thus, we want to know that the call had some issues.
     */
    if (result < 0)
      log_msg (LOG_ERR, _("sd_notifyf failed: %s"), strerror(-result));
  }
#endif

  svc_run ();
  log_msg (LOG_ERR, _("svc_run returned."));
  unlink (_YPBIND_PIDFILE);
  exit (1);
  /* NOTREACHED */
}
