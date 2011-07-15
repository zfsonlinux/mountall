/* mountall 
 *
 * Copyright © 2010 Canonical Ltd.
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

#include "dbus/mountall.h"

extern DBusServer *control_server;
extern const NihDBusInterface *control_interfaces[];

int control_server_open (void);
int control_stop_timer  (void *data, NihDBusMessage *message, 
						const char *mountpoint)
	__attribute__ ((warn_unused_result));
int control_restart_timer (void *data, NihDBusMessage *message,
	       					const char *mountpoint)
	__attribute__ ((warn_unused_result));
int control_change_mount_device (void *data, NihDBusMessage *message, 
				const char *devname, const char *path)
	__attribute__ ((warn_unused_result));
int control_get_version (void *data, NihDBusMessage *message, 
						char **value)
	__attribute__ ((warn_unused_result));
