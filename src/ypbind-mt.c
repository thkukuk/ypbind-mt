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

#define _GNU_SOURCE /* for GLIBC */
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
#if defined(HAVE_RPC_SVC_SOC_H)
#include <rpc/svc_soc.h>
#endif /* HAVE_RPC_SVC_SOC_H */
#include <rpcsvc/ypclnt.h>
#include <rpc/pmap_clnt.h>
#include <pthread.h>
#if defined(HAVE_NSS_H)
#include <nss.h>
#endif

#include "ypbind.h"
#include "log_msg.h"
#include "local.h"

#define _(String) gettext (String)

#if USE_PIDFILE
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#ifndef _PATH_VARRUN
#define _PATH_VARRUN "/etc/"
#endif
#ifndef _YPBIND_PIDFILE
#define _YPBIND_PIDFILE _PATH_VARRUN"ypbind.pid"
#endif
#endif /* USE_PIDFILE */

char *domain = NULL;
const char *configfile = "/etc/yp.conf";
int ypset = SET_NO;
int use_broadcast = 0;
int broken_server = 0;
int ping_interval = 20;
int port = -1;
#if USE_PIDFILE
static int lock_fd;
#endif /* USE_PIDFILe */

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

/* Load the config file (/etc/yp.conf)  */
static int
load_config (int do_add)
{
  FILE *fp;
  char *buf = NULL;
  size_t buflen = 0;
  int have_entries = 0; /* # of entries we found in config file */

  fp = fopen (configfile, "r");
  if (NULL == fp)
    return 1;

  if (debug_flag)
    log_msg (LOG_DEBUG, "parsing config file");

  while (!feof (fp))
    {
      char tmpserver[81], tmpdomain[YPMAXDOMAIN + 1];
      int count;
      char *tmp, *cp;
#if defined(HAVE_GETLINE)
      ssize_t n = getline (&buf, &buflen, fp);
#elif defined (HAVE_GETDELIM)
      ssize_t n = getdelim (&buf, &buflen, '\n', fp);
#else
      ssize_t n;

      if (buf == NULL)
        {
          buflen = 8096;
          buf = malloc (buflen);
        }
      buf[0] = '\0';
      fgets (buf, buflen - 1, fp);
      if (buf != NULL)
        n = strlen (buf);
      else
        n = 0;
#endif /* HAVE_GETLINE / HAVE_GETDELIM */
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
        log_msg (LOG_DEBUG, _("Trying entry: %s"), cp);

      if (strncmp (cp, "domain", 6) == 0 && isspace ((int)cp[6]))
	{
	  /* We have
	     domain <domain> server <host|ip>
	     or
	     domain <domain> broadcast */

	  count = sscanf (cp, "domain %64s server %80s", tmpdomain,
			  tmpserver);
	  if (count == 2)
	    {
	      if (debug_flag)
		log_msg (LOG_DEBUG, _("parsed domain '%s' server '%s'"),
			 tmpdomain, tmpserver);
	      ++have_entries;
	      if (do_add)
		add_server (tmpdomain, tmpserver);
	      continue;
	    }
	  count = sscanf (cp, "domain %s broadcast", tmpdomain);
	  if (count == 1)
	    {
	      if (debug_flag)
		log_msg (LOG_DEBUG, _("parsed domain '%s' broadcast"),
			 tmpdomain);
	      if (do_add)
		add_server (tmpdomain, NULL);
	      ++have_entries;
	      continue;
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
	      if (do_add)
		add_server (domain, tmpserver);
	      ++have_entries;
	      continue;
	    }
	}
      log_msg (LOG_ERR, _("Entry \"%s\" is not valid, ignore it!"), cp);
    }
  fclose (fp);

  if (buf)
    free (buf);

  if (!have_entries)
    {
      if (debug_flag)
        log_msg (LOG_DEBUG, _("No entry found."));
      return 1;
    }

  return 0;
}

#if USE_PIDFILE
/* Create a pidfile on startup */
static void
create_pidfile (void)
{
  struct flock lock;
  int left, written;
  pid_t pid;
  char pbuf[10], *ptr;
  int flags;

  lock_fd = open (_YPBIND_PIDFILE, O_CREAT | O_RDWR,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (lock_fd < 0)
    log_msg (LOG_ERR, _("cannot create pidfile %s"), _YPBIND_PIDFILE);

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
#endif /* USE_PIDFILE */

/* Thread for handling signals */
static void *
sig_handler (void *v_param  __attribute__ ((unused)))
{
#if USE_PIDFILE
  struct flock lock;
#endif /* USE_PIDFILE */
  sigset_t sigs_to_catch;
  int caught;

  sigemptyset (&sigs_to_catch);
  sigaddset (&sigs_to_catch, SIGCHLD);
  sigaddset (&sigs_to_catch, SIGTERM);
  sigaddset (&sigs_to_catch, SIGINT);
  sigaddset (&sigs_to_catch, SIGQUIT);
  sigaddset (&sigs_to_catch, SIGSEGV);
  sigaddset (&sigs_to_catch, SIGHUP);

  while (1)
    {
      sigwait (&sigs_to_catch, &caught);
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
	  pmap_unset (YPBINDPROG, YPBINDVERS);
	  pmap_unset (YPBINDPROG, YPBINDOLDVERS);
#if USE_PIDFILE
	  /* unlock pidfile */
	  lock.l_type = F_UNLCK;
	  lock.l_start = 0;
	  lock.l_whence = SEEK_SET;
	  lock.l_len = 0;
	  if (fcntl (lock_fd, F_SETLK, &lock) != 0)
	    log_msg (LOG_ERR, _("cannot unlock pidfile"));
	  close (lock_fd);
	  unlink (_YPBIND_PIDFILE);
#endif /* USE_PIDFILE */
	  unlink_bindingdir ();
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
	    load_config (1);

	  if (ping_interval < 1)
	    do_binding ();
	  break;
	default:
	  log_msg (LOG_ERR, _("Unknown signal: %d"), caught);
	  break;
	}
    }
}

static void
usage (void)
{
  fputs (_("Usage:\n"), stderr);
  fputs (_("\typbind [-broadcast | -ypset | -ypsetme] [-p port] [-f configfile]\n\t  [-no-ping] [-broken-server] [-debug]\n"), stderr);
  fputs (_("\typbind -c [-f configfile]\n"), stderr);
  fputs (_("\typbind --version\n"), stderr);
  exit (1);
}

int
main (int argc, char **argv)
{
  SVCXPRT *transp;
  int sock, result, i;
  sigset_t sigs_to_block;
  struct sockaddr_in socket_address;
  pthread_t sig_thread, ping_thread;
  struct stat st;
  int configcheck_only = 0;

  setlocale (LC_MESSAGES, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  /* Parse commandline. */
  for (i = 1; i < argc; i++)
    {
      if (strcmp ("--version", argv[i]) == 0)
        {
          fprintf (stderr, "ypbind (%s) %s\n", PACKAGE, VERSION);
          exit (1);
        }
      else if (strcmp ("-ypset", argv[i]) == 0)
	ypset = SET_YPSET;
      else if (strcmp ("-ypsetme", argv[i]) == 0)
	ypset = SET_YPSETME;
      else if (strcmp ("-d", argv[i]) == 0 ||
	       strcmp ("-debug", argv[i]) == 0)
        debug_flag = 1;
      else if (strcmp ("-broken-server", argv[i]) == 0 ||
	       strcmp ("-broken_server", argv[i]) == 0)
        broken_server = 1;
      else if (strcmp ("-no-ping", argv[i]) == 0 ||
	       strcmp ("-no_ping", argv[i]) == 0)
	ping_interval = 0;
      else if (strcmp ("-broadcast", argv[i]) == 0)
	use_broadcast = 1;
      else if (strcmp ("-f", argv[i]) == 0)
	{
	  if (i+1 == argc || argv[i+1][0] == '-')
	    usage ();
	  ++i;
	  configfile = argv[i];
	}
      else if (strcmp ("-p", argv[i]) == 0)
	{
	  if (i+1 == argc || argv[i+1][0] == '-')
	    usage ();
	  ++i;
	  port = atoi (argv[i]);
	}
      else if (strcmp ("-c", argv[i]) == 0)
	configcheck_only = 1;
      else
	usage ();
    }

  if (configcheck_only)
    {
      debug_flag = 1;
      if (load_config (0) != 0)
	exit (1);
      else
	{
	  fprintf (stdout, _("Config file %s is ok.\n"), configfile);
	  exit (0);
	}
    }

  if (yp_get_default_domain (&domain) || domain == NULL ||
      domain[0] == '\0' || strcmp(domain, "(none)") == 0)
    {
      fputs (_("domainname not set - aborting.\n"), stderr);
      exit (1);
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
    {
      if (load_config (1) != 0)
	{
	  fputs (_("No NIS server and no -broadcast option specified.\n"), stderr);
	  fprintf (stderr,
		   _("Add a NIS server to the %s configuration file,\n"),
		   configfile);
	  fputs (_("or start ypbind with the -broadcast option.\n"), stderr);
	  exit (1);
	}
    }
  else
    add_server (domain, NULL);

  unlink_bindingdir ();

  openlog ("ypbind", LOG_PID, LOG_DAEMON);

  if (debug_flag)
    log_msg (LOG_DEBUG, "[Welcome to ypbind-mt, version %s]\n", VERSION);
  else
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
      dup (j);
      dup (j);
    }

#if defined(HAVE___NSS_CONFIGURE_LOOKUP)
  /* We only use /etc/hosts and DNS query to avoid deadlocks */
  __nss_configure_lookup ("hosts", "files dns");
#endif /* HAVE___NSS_CONFIGURE_LOOKUP */

#if USE_PIDFILE
  create_pidfile ();
#endif /* USE_PIDFILE */

  sigemptyset (&sigs_to_block);
  sigaddset (&sigs_to_block, SIGCHLD);
  sigaddset (&sigs_to_block, SIGTERM);
  sigaddset (&sigs_to_block, SIGINT);
  sigaddset (&sigs_to_block, SIGQUIT);
  sigaddset (&sigs_to_block, SIGSEGV);
  sigaddset (&sigs_to_block, SIGHUP);
  if (pthread_sigmask (SIG_BLOCK, &sigs_to_block, NULL) != 0)
    {
      log_msg (LOG_ERR, _("Could not block signals."));
      exit (1);
    }

  pthread_create (&sig_thread, NULL, &sig_handler, NULL);

  pmap_unset (YPBINDPROG, YPBINDOLDVERS);
  pmap_unset (YPBINDPROG, YPBINDVERS);

  if (port >= 0)
    {
      sock = socket (AF_INET, SOCK_DGRAM, 0);
      if (sock < 0)
	{
	  log_msg (LOG_ERR, _("Cannot create UDP: %s"), strerror (errno));
	  exit (1);
	}

      memset ((char *) &socket_address, 0, sizeof (socket_address));
      socket_address.sin_family = AF_INET;
      socket_address.sin_addr.s_addr = htonl (INADDR_ANY);
      socket_address.sin_port = htons (port);

      result = bind (sock, (struct sockaddr *) &socket_address,
		     sizeof (socket_address));
      if (result < 0)
	{
	  log_msg (LOG_ERR, _("Cannot bind UDP: %s"), strerror (errno));
	  exit (1);
	}
    }
  else
    sock = RPC_ANYSOCK;

  transp = svcudp_create (sock);
  if (transp == NULL)
    {
      log_msg (LOG_ERR, _("Cannot create udp service."));
      exit (1);
    }

  if (!svc_register (transp, YPBINDPROG, YPBINDVERS, ypbindprog_2,
		     IPPROTO_UDP))
    {
      log_msg (LOG_ERR,
	       _("Unable to register (YPBINDPROG, YPBINDVERS, udp)."));
      exit (1);
    }

  if (!svc_register (transp, YPBINDPROG, YPBINDOLDVERS, ypbindprog_1,
		     IPPROTO_UDP))
    {
      log_msg (LOG_ERR,
	       _("Unable to register (YPBINDPROG, YPBINDOLDVERS, udp)."));
      exit (1);
    }

  if (port >= 0)
    {
      sock = socket (AF_INET, SOCK_STREAM, 0);
      if (sock < 0)
	{
	  log_msg (LOG_ERR, _("Cannot create TCP: %s"), strerror (errno));
	  exit (1);
	}

      memset (&socket_address, 0, sizeof (socket_address));
      socket_address.sin_family = AF_INET;
      socket_address.sin_addr.s_addr = htonl (INADDR_ANY);
      socket_address.sin_port = htons (port);

      result = bind (sock, (struct sockaddr *) &socket_address,
		     sizeof (socket_address));
      if (result < 0)
	{
	  log_msg (LOG_ERR, _("Cannot bind TCP: %s"), strerror (errno));
	  exit (1);
	}
    }
  else
    sock = RPC_ANYSOCK;

  transp = svctcp_create (sock, 0, 0);
  if (transp == NULL)
    {
      log_msg (LOG_ERR, _("Cannot create tcp service.\n"));
      exit (1);
    }

  if (!svc_register (transp, YPBINDPROG, YPBINDVERS, ypbindprog_2,
		     IPPROTO_TCP))
    {
      log_msg (LOG_ERR, _("Unable to register (YPBINDPROG, YPBINDVERS, tcp)."));
      exit (1);
    }

  if (!svc_register (transp, YPBINDPROG, YPBINDOLDVERS, ypbindprog_1,
		     IPPROTO_TCP))
    {
      log_msg (LOG_ERR,
	       _("Unable to register (YPBINDPROG, YPBINDOLDVERS, tcp)."));
      exit (1);
    }

  pthread_create (&ping_thread, NULL, &test_bindings, NULL);

  svc_run ();
  log_msg (LOG_ERR, _("svc_run returned."));
#if USE_PIDFILE
  unlink (_YPBIND_PIDFILE);
#endif /* USE_PIDFILE */
  exit (1);
  /* NOTREACHED */
}
