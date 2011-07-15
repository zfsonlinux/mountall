/* mountall
 *
 * Copyright © 2010 Canonical Ltd.
 *
 * This file is based on initctl.c in upstart whose 
 * Author: Scott James Remnant <scott@netsplit.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif /* HAVE_CONFIG_H */


#include <dbus/dbus.h>

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>
#include <fnmatch.h>

#include <nih/macros.h>
#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/main.h>
#include <nih/option.h>
#include <nih/command.h>
#include <nih/logging.h>
#include <nih/error.h>
#include <nih/hash.h>
#include <nih/tree.h>

#include <nih-dbus/dbus_error.h>
#include <nih-dbus/dbus_proxy.h>
#include <nih-dbus/errors.h>
#include <nih-dbus/dbus_connection.h>

#include "dbus/mountall.h"

#include "com.ubuntu.Mountall.Server.h"


/* Prototypes for option and command functions */
int stop_timer_action		(NihCommand *command, char * const *args);
int restart_timer_action	(NihCommand *command, char * const *args);
int change_mount_device_action  (NihCommand *command, char * const *args);

/**
 * dest_name:
 *
 * Name on the D-Bus system bus that the message should be sent to when
 * system is TRUE.
 **/
char *dest_name = NULL;

/**
 * mountall_open:
 * @parent: parent object for new proxy.
 *
 * Opens a connection to the init daemon and returns a proxy to the manager
 * object.  If @dest_name is not NULL, a connection is instead opened to
 * the system bus and the proxy linked to the well-known name given.
 *
 * Error messages are output to standard error.
 *
 * If @parent is not NULL, it should be a pointer to another object which
 * will be used as a parent for the returned proxy.  When all parents
 * of the returned proxy are freed, the returned proxy will also be
 * freed.
 *
 * Returns: newly allocated D-Bus proxy or NULL on error.
 **/
NihDBusProxy *
mountall_open (const void *parent)
{
	DBusError       dbus_error;
	DBusConnection *connection;
	NihDBusProxy *  mountall;
	int uid = getuid ();

	dbus_error_init (&dbus_error);
	if (uid) {
		nih_error ("Need to be root to execute this command ");
		return NULL;
	}	
		
	connection = dbus_connection_open (DBUS_ADDRESS_MNTALL, &dbus_error);
	if (! connection) {
		nih_error ("%s: %s", _("Unable to connect to mountall"),
			   dbus_error.message);
		dbus_error_free (&dbus_error);
		return NULL;
	}
	dbus_error_free (&dbus_error);

	mountall = nih_dbus_proxy_new (parent, connection,
				      dest_name,
				      DBUS_PATH_MNTALL,
				      NULL, NULL);
	if (! mountall) {
		NihError *err;

		err = nih_error_get ();
		nih_error ("%s", err->message);
		nih_free (err);

		dbus_connection_unref (connection);
		return NULL;
	}
	nih_debug("Proxy for Mountall0_1.Server created!");
	mountall->auto_start = FALSE;

	/* Drop initial reference now the proxy holds one */
	dbus_connection_unref (connection);
	return mountall;
}

/**
 * stop_timer_action:
 * @command: NihCommand invoked,
 * @args: command-line arguments.
 *
 * This function is called for the "stop-timer" command.
 *
 * Returns: 1 on error and 0 on success.
 **/
int
stop_timer_action (NihCommand *  command,
		   char * const *args)
{
	nih_local NihDBusProxy *mountall = NULL;
	NihError *              err;

	nih_assert (command != NULL);
	nih_assert (args != NULL);

	if (!args[0]) {
		fprintf (stderr, _("%s: missing device name \n"), program_name);
		nih_main_suggest_help ();
		return 1;
	}
	mountall = mountall_open (NULL);
	if (! mountall)
		return 1;
	if (mountall_server_stop_timer_sync (NULL, mountall, args[0]))
		goto error;
	return 0;
error:
	err = nih_error_get ();
	nih_error ("%s", err->message);
	nih_free (err);
	return 1;
}

/**
 * restart_timer_action:
 * @command: NihCommand invoked,
 * @args: command-line arguments.
 *
 * This function is called for the "restart-timer" command.
 *
 * Returns: 1 on error and 0 on success.
 **/
int
restart_timer_action (NihCommand *  command,
		   char * const *args)
{
	nih_local NihDBusProxy *mountall = NULL;
	NihError *              err;

	nih_assert (command != NULL);
	nih_assert (args != NULL);

	if (!args[0]) {
		fprintf (stderr, _("%s: missing device name \n"), program_name);
		nih_main_suggest_help ();
		return 1;
	}
	mountall = mountall_open (NULL);
	if (! mountall)
		return 1;
	
	if (mountall_server_restart_timer_sync (NULL, mountall, args[0]))
		goto error;
	return 0;
error:
	err = nih_error_get ();
	nih_error ("%s", err->message);
	nih_free (err);
	return 1;
}

/**
 * change_mount_dev_action:
 * @command: NihCommand invoked,
 * @args: command-line arguments.
 *
 * This function is called for the "change-mount" command.
 *
 * Returns: 1 on error and 0 on success.
 **/
int
change_mount_dev_action (NihCommand *  command,
		   char * const *args)
{
	nih_local NihDBusProxy *mountall = NULL;
	NihError *              err;

	nih_assert (command != NULL);
	nih_assert (args != NULL);

	if (!args[0]) {
		fprintf (stderr, _("%s: missing device name \n"), program_name);
		nih_main_suggest_help ();
		return 1;
	}
	if (!args[1]) {
		fprintf (stderr, _("%s: missing mount point \n"), program_name);
		nih_main_suggest_help ();
		return 1;
	}
	mountall = mountall_open (NULL);
	if (! mountall)
		return 1;
	if (mountall_server_change_mount_device_sync (NULL, mountall, 
						args[0], args[1])) 
		goto error;
	return 0;
error:
	err = nih_error_get ();
	nih_error ("%s", err->message);
	nih_free (err);
	return 1;
}

/**
 * version_action:
 * @command: NihCommand invoked,
 * @args: command-line arguments.
 *
 * This function is called for the "version" command.
 *
 * Returns: command exit status.
 **/
int
version_action (NihCommand *  command,
		char * const *args)
{
	nih_local NihDBusProxy *mountall = NULL;
	nih_local char *        version = NULL;
	NihError *              err;

	nih_assert (command != NULL);
	nih_assert (args != NULL);

	mountall = mountall_open (NULL);
	if (! mountall)
		return 1;

	if (mountall_server_get_version_sync (NULL, mountall, &version) < 0)
		goto error;

	nih_message ("%s", version);

	return 0;

error:
	err = nih_error_get ();
	nih_error ("%s", err->message);
	nih_free (err);

	return 1;
}

#ifndef TEST
/**
 * options:
 *
 * Command-line options accepted for all arguments.
 **/
static NihOption options[] = {
	NIH_OPTION_LAST
};


NihOption stop_timer_options[] = {
	NIH_OPTION_LAST
};

NihOption restart_timer_options[] = {
	NIH_OPTION_LAST
};

NihOption change_mnt_dev_options[] = {
	NIH_OPTION_LAST
};

/**
 * version_options:
 *
 * Command-line options accepted for the version command.
 **/
NihOption version_options[] = {
	NIH_OPTION_LAST
};

/**
 * timer_group:
 *
 * Group of commands related to the timer
 **/
static NihCommandGroup timer_commands = { N_("Timer") };

/**
 * mounts_group:
 *
 * Group of commands related to mount devices and paths.
 **/
static NihCommandGroup mount_commands = { N_("Mounts") };


/**
 * commands:
 *
 * Commands accepts as the first non-option argument, or program name.
 **/
static NihCommand commands[] = {
	{ "stop-timer", N_("MOUNTPOINT"),
	  N_("Stop a timer associated with the specified device"),
	  N_("MOUNTPOINT is the mountpoint corresponding to a device whose "
	     "timer you want to stop"),
	  &timer_commands, stop_timer_options, stop_timer_action },

	{ "restart-timer", N_("MOUNTPOINT"),
	  N_("Restart a timer associated with the specified device"),
	  N_("MOUNTPOINT is the mountpoint corresponding to a device that "
	     "should become ready withing the default wait time or the time "
	     "specified explicitly as a command line argument to mountall") ,
	  &timer_commands, restart_timer_options, restart_timer_action },

	{ "change-mount", N_("DEVICE-NAME PATH"),
	  N_("Change the device to mount at a given mountpoint specified in "
	     "/etc/fstab" ),
	  N_("DEVICE-NAME is the name of the new device that you want to mount "
	     "PATH is the full path specified in /etc/fstab") ,
	  &mount_commands, change_mnt_dev_options, change_mount_dev_action },

	{ "version", NULL,
	  N_("Request the version of the mountall daemon."),
	  NULL,
	  NULL, version_options, version_action },

	NIH_COMMAND_LAST
};

int
main (int   argc,
      char *argv[])
{
	int ret;

	nih_main_init (argv[0]);

	ret = nih_command_parser (NULL, argc, argv, options, commands);
	if (ret < 0)
		exit (1);

	dbus_shutdown ();

	return ret;
}
#endif
