/* mountall 
 *
 * Copyright © 2010 Canonical Ltd.
 * Author: Surbhi A. Palande <surbhi.palande@ubuntu.com>
 *
 * This file is based on control.c in upstart whose
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

#include <dbus/dbus.h>

#include <nih/macros.h>
#include <nih/alloc.h>
#include <nih/string.h>
#include <nih/list.h>
#include <nih/io.h>
#include <nih/main.h>
#include <nih/logging.h>
#include <nih/error.h>
#include <nih/errors.h>

#include <nih-dbus/dbus_error.h>
#include <nih-dbus/dbus_connection.h>
#include <nih-dbus/dbus_message.h>
#include <nih-dbus/dbus_object.h>

#include "dbus/mountall.h"
#include "com.ubuntu.Mountall.Server.h"
#include "mountall.h"

extern const char *package_string;

/* Prototypes for static functions */
static int   control_server_connect (DBusServer *server, DBusConnection *conn);
static void  control_disconnected   (DBusConnection *conn);
static void  control_register_all   (DBusConnection *conn);

/**
 * control_server
 * 
 * D-Bus server listening for new direct connections.
 **/
DBusServer *control_server = NULL;


/**
 * control_server_address:
 *
 * Address on which the control server may be reached.
 **/
const char * control_server_address = DBUS_ADDRESS_MNTALL;

/**
 * control_server_open:
 *
 * Open a listening D-Bus server and store it in the control_server global.
 * New connections are permitted from the root user, and handled
 * automatically in the main loop.
 *
 * Returns: zero on success, negative value on raised error.
 **/

int
control_server_open (void)
{
	nih_assert (control_server == NULL);

	control_server = nih_dbus_server (control_server_address,
				  control_server_connect,
				  control_disconnected);
	if (! control_server)
		return -1;

	nih_debug("Mountall0_1.Server started at address: %s", control_server_address);

	return 0;
}

/**
 * control_server_connect:
 *
 * Called when a new client connects to our server and is used to register
 * objects on the new connection.
 *
 * Returns: always TRUE.
 **/
static int
control_server_connect (DBusServer     *server,
			DBusConnection *conn)
{
	nih_assert (server != NULL);
	nih_assert (server == control_server);
	nih_assert (conn != NULL);

	/* Register objects on the connection. */
	control_register_all (conn);

	nih_debug("Mountall0_1.Server::Connection from private client");

	return TRUE;
}

/**
 * control_register_all:
 * @conn: connection to register objects for.
 *
 * Registers the manager object and objects for all jobs and instances on
 * the given connection.
 **/
static void
control_register_all (DBusConnection *conn)
{
	nih_assert (conn != NULL);

	/* Register the manager object, this is the primary point of contact
	 * for clients.  We only check for success, otherwise we're happy
	 * to let this object be tied to the lifetime of the connection.
	 */
	NIH_MUST (nih_dbus_object_new (NULL, conn, DBUS_PATH_MNTALL,
				       control_interfaces, NULL));
}

/**
 * control_disconnected:
 *
 * This function is called when the connection to the D-Bus system bus,
 * or a client connection to our D-Bus server, is dropped and our reference
 * is about to be list.  We clear the connection from our current list
 * and drop the control_bus global if relevant.
 **/
static void
control_disconnected (DBusConnection *conn)
{
	nih_assert (conn != NULL);
}

/**
 * control_stop_timer:
 * @mountpoint: the mountpoint corresponding to the device for which the
 * timeout option has to be disabled.
 *
 * Implements the StopTimer method of com.ubuntu.Moutall01_Server
 * interface.
 *
 * This function is called for stopping a previously started timer for a
 * mountpoint. Stopping a timer has the effect that mountall would no longer
 * expect the corresponding device to be ready within a previously registered
 * stiplulated time period. After this call, mountall will wait endlessly till
 * the device becomes ready. Use this function only when you know that you
 * might restart the timer later or that you really want to wait endlessly
 * till the device becomes available.
 *
 * Returns 0 on success and -1 on failure.
 **/
int
control_stop_timer  (void *data, 
		     NihDBusMessage *message,
		     const char *mountpoint)
{

	nih_assert (mountpoint != NULL);
	nih_assert (message != NULL);

	return stop_dev_timer (mountpoint);
}

/**
 * control_restart_timer:
 * @mountpoint: the mountpoint corresponding to the device for which the
 * timeout option has to be disabled.
 *
 * Implements the RestartTimer method of com.ubuntu.Moutall01_Server
 * interface.
 *
 * This function is called for restarting a previously stopped timer for a
 * mountpoint. After successfully restarting a timer, mountall will expect the
 * corresponding device to become ready for mounting within the previously
 * configured timeout or the default of 30 seconds.
 *
 * Returns 0 on success and -1 on failure.
 **/
int
control_restart_timer (void *data,
		       NihDBusMessage *message,
		       const char *mountpoint)
{

	nih_assert (mountpoint != NULL);
	nih_assert (message != NULL);

	return restart_dev_timer (mountpoint);
}

/**
 * control_change_mount_device:
 * @devname: Name of the new device which you want to mount at @path.
 * @path: Complete path which matches with the one found in /etc/fstab or what
 * mountall already considers.
 *
 * Implements the ChangeMountDevice method of com.ubuntu.Moutall01_Server
 * interface.
 *
 * Call this function to change the device to mount to an existing previous
 * mountpoint.
 **/
int
control_change_mount_device (void *data, 
		       NihDBusMessage *message,
		       const char *devname,
		       const char *path)
{
	nih_assert (devname != NULL);
	nih_assert (path != NULL);

	return change_mount_device (devname, path);
}

/**
 * control_get_version:
 * @data: not used,
 * @message: D-Bus connection and message received,
 * @version: pointer for reply string.
 *
 * Implements the get method for the version property of the
 * com.ubuntu.Mountall0_1.Server interface.
 *
 * Called to obtain the version of the init daemon, which will be stored
 * as a string in @version.
 *
 * Returns: zero on success, negative value on raised error.
 **/
int
control_get_version (void *data,
	             NihDBusMessage *message,
		     char **version)
{
	nih_assert (message != NULL);
	nih_assert (version != NULL);

	*version = nih_strdup (message, package_string);
	if (!*version)
		nih_return_no_memory_error (-1);

	return 0;
}
