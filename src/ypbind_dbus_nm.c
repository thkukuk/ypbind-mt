/* Copyright (c) 2006 Thorsten Kukuk
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

#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#ifdef USE_DBUS_NM

#define DBUS_API_SUBJECT_TO_CHANGE 1

#include <string.h>
#include <libintl.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

#ifdef HAVE_NETWORKMANAGER_NETWORKMANAGER_H
#include <NetworkManager/NetworkManager.h>
#else
#define NM_DBUS_INTERFACE "org.freedesktop.NetworkManager"
#define NM_DBUS_SERVICE   "org.freedesktop.NetworkManager"
#define NM_DBUS_PATH      "/org/freedesktop/NetworkManager"
#define NM_DBUS_SIGNAL_STATE_CHANGE "StateChange"

typedef enum NMState {
  NM_STATE_UNKNOWN = 0,
  NM_STATE_ASLEEP,
  NM_STATE_CONNECTING,
  NM_STATE_CONNECTED,
  NM_STATE_DISCONNECTED
} NMState;

#endif

#include "ypbind.h"
#include "log_msg.h"
#include "local.h"

#ifndef _
#define _(String) gettext (String)
#endif

int is_online = 0;

int dbus_is_initialized = 0;
pthread_mutex_t mutex_dbus = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_dbus = PTHREAD_COND_INITIALIZER;


static void
go_offline (void)
{
  if (is_online == 0) /* Do nothing if already offline.  */
    return;

  if (debug_flag)
    log_msg (LOG_DEBUG, _("Switch to offline mode"));
  is_online = 0;
  portmapper_disconnect ();
  clear_server ();
}

static void
go_online (void)
{
  if (is_online) /* Do nothing if already online.  */
    return;

  if (debug_flag)
    log_msg (LOG_DEBUG, _("Switch to online mode"));
  is_online = 1;

  /* Reload config file, may have changed. */
  if (debug_flag)
    log_msg (LOG_DEBUG, _("Going online, reloading config file."));
  clear_server ();

  if (use_broadcast)
    add_server (domain, NULL, 0);
  else
    load_config (0);

  if (portmapper_connect () != 0)
    {
      go_offline (); /* go offline again */
    }

  do_binding ();
}

static int dbus_init (void);


static gboolean
dbus_reconnect (gpointer user_data)
{
  gboolean status;

  status = dbus_init ();
  if (debug_flag)
    log_msg (LOG_DEBUG, "Reconnect %s",
	     status ? "successful" : "failed");
  return !status;
}

static DBusHandlerResult
dbus_filter (DBusConnection *connection,
	     DBusMessage *message, void *user_data  __attribute__((unused)))
{
  DBusHandlerResult handled = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

  if (dbus_message_is_signal (message, DBUS_INTERFACE_LOCAL,
			      "Disconnected"))
    {
      /* D-Bus system bus went away */
      log_msg (LOG_INFO, "Lost connection to D-Bus\n");
      dbus_connection_unref (connection);
      connection = NULL;
      g_timeout_add (1000, dbus_reconnect, NULL);
      handled = DBUS_HANDLER_RESULT_HANDLED;
    }
  else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE,
                                   NM_DBUS_SIGNAL_STATE_CHANGE))
    {
      NMState state = NM_STATE_UNKNOWN;

      if (dbus_message_get_args (message, NULL, DBUS_TYPE_UINT32,
                                 &state, DBUS_TYPE_INVALID))
        {
          if (state == NM_STATE_CONNECTED)
	    go_online ();
          else if (state == NM_STATE_DISCONNECTED)
	    go_offline ();
        }
      handled = DBUS_HANDLER_RESULT_HANDLED;
    }
  else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE,
				   "DeviceNoLongerActive"))
    {
      go_offline ();
      handled = DBUS_HANDLER_RESULT_HANDLED;
    }
  else if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS,
				   "NameOwnerChanged"))
    {
      if (debug_flag)
	{
	  char *service = NULL;
	  char *old_owner = NULL;
	  char *new_owner = NULL;

	  if (dbus_message_get_args (message, NULL,
				     DBUS_TYPE_STRING, &service,
				     DBUS_TYPE_STRING, &old_owner,
				     DBUS_TYPE_STRING, &new_owner,
				     DBUS_TYPE_INVALID))
	    {
	      if (strcmp (service, NM_DBUS_SERVICE) == 0)
		{
		  /* Check if it was NetworkManager who dropped off or
		     jumped on the system bus. */
		  int old_owner_good =
		    (old_owner && (strlen (old_owner) > 0));
		  int new_owner_good =
		    (new_owner && (strlen (new_owner) > 0));

		  if (!old_owner_good && new_owner_good)
		    log_msg (LOG_DEBUG,
			     "NetworkManager is on the system bus");
		  else if (old_owner_good && !new_owner_good)
		    log_msg (LOG_DEBUG,
			     "NetworkManager left the system bus");
		}
	    }
	  handled = DBUS_HANDLER_RESULT_HANDLED;
	}
    }
  else if (debug_flag)
    {
      log_msg (LOG_DEBUG, "interface: %s, object path: %s, method: %s",
	       dbus_message_get_interface(message),
	       dbus_message_get_path (message),
	       dbus_message_get_member (message));
    }

  return handled;
}

static int
check_online (DBusConnection *connection)
{
  DBusMessage *message, *reply;
  DBusError error;
  dbus_uint32_t state;

  message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH,
                                          NM_DBUS_INTERFACE, "state");
  if (!message)
    return -1;

  dbus_error_init (&error);
  reply = dbus_connection_send_with_reply_and_block (connection, message,
                                                     -1, &error);
  dbus_message_unref (message);
  if (!reply)
    return 0;

  if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &state,
                              DBUS_TYPE_INVALID))
    return -1;

  if (state != NM_STATE_CONNECTED)
    return 0;

  return 1;
}

static int
check_for_nm (DBusConnection *connection)
{

  if (dbus_bus_name_has_owner (connection, NM_DBUS_SERVICE, NULL))
    {
      if (debug_flag)
	log_msg (LOG_DEBUG, "NetworkManager is running.\n");
      return 1;
    }
  else
    {
      if (debug_flag)
	log_msg (LOG_DEBUG, "NetworkManager is not running.\n");
      return 0;
    }
}


static int
dbus_init (void)
{
  DBusConnection *connection = NULL;
  DBusError error;

  dbus_error_init (&error);

  connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
  if (connection == NULL || dbus_error_is_set (&error))
    {
      log_msg (LOG_ERR, "Connection to D-BUS system message bus failed: %s.",
               error.message);
      dbus_error_free (&error);
      connection = NULL;
      goto out;
    }

  dbus_connection_set_exit_on_disconnect (connection, FALSE);

  if (!dbus_connection_add_filter (connection, dbus_filter, NULL, NULL))
    goto out;

  dbus_bus_add_match (connection, "type='signal',"
		      "interface='" DBUS_INTERFACE_DBUS "',"
		      "sender='" DBUS_SERVICE_DBUS "'",
		      &error);
  if (dbus_error_is_set (&error))
    {
      log_msg (LOG_ERR, "Error adding match, %s: %s",
	       error.name, error.message);

      dbus_error_free (&error);
      dbus_connection_unref (connection);
      connection = NULL;
      goto out;
    }

  dbus_bus_add_match (connection,
		      "type='signal',"
		      "interface='" NM_DBUS_INTERFACE "',"
		      "sender='" NM_DBUS_SERVICE "',"
		      "path='" NM_DBUS_PATH "'", &error);
  if (dbus_error_is_set (&error))
    {
      log_msg (LOG_ERR, "Error adding match, %s: %s",
	       error.name, error.message);
      dbus_error_free (&error);
      dbus_connection_unref (connection);
      connection = NULL;
      goto out;
    }

  dbus_connection_setup_with_g_main (connection, NULL);

 out:
  if (connection)
    {
      if (!check_for_nm (connection))
	{
	  /* NetworkManager not in use.  */
	  dbus_connection_unref (connection);
	  is_online = 1;
	  return 0;
	}
      if (check_online (connection) == 1)
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG, "Are already online");
	  is_online = 1;
	}
      else
	{
	  if (debug_flag)
	    log_msg (LOG_DEBUG, "Are offline");
	  is_online = 0;
	}
      return 1;
    }
  else
    {
      if (debug_flag)
	log_msg (LOG_DEBUG, "No connection possible, assume online mode");
      is_online = 1;
      return 0;
    }
}


/* This thread handles the NetworkManager communication over DBUS */
void *
watch_dbus_nm (void *param __attribute__ ((unused)))
{
  static int status = 1;
  GMainLoop *loop;
  int dbus_init_ret;

  g_type_init ();

  dbus_init_ret = dbus_init ();

  /* Signal the main thread that we have the dbus connection
     initialized. So we can continue.  */
  pthread_mutex_lock(&mutex_dbus);
  dbus_is_initialized = 1;
  pthread_cond_broadcast(&cond_dbus);
  pthread_mutex_unlock(&mutex_dbus);

  /* Now return if no DBUS/NetworkManager is in use.  */
  if (dbus_init_ret != 1)
    {
      status = 0;
      return &status;
    }


  loop = g_main_loop_new (NULL, FALSE);

  g_main_loop_run (loop);

  return &status;
}

#endif
