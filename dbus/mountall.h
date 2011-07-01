/* mountall.h
 *
 * Copyright © 2009 Canonical Ltd.
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

#ifndef DBUS_MNTALL_H
#define DBUS_MNTALL_H

/**
 * DBUS_PATH_MNTALL:
 *
 * The object path used by the manager object, and used as the root path
 * for all other objects.
 **/
#define DBUS_PATH_MNTALL "/com/ubuntu/Mountall/Server"


/**
 * DBUS_INTERFACE_MNTALL:
 *
 * The interface exported by the manager object.
 **/
#define DBUS_INTERFACE_MNTALL "com.ubuntu.Mountall0_1.Server"

/**
 * DBUS_ADDRESS_MNTALL:
 *
 * The address where the private D-Bus server inside Mountall can be
 * found.
 **/
#ifndef DBUS_ADDRESS_MNTALL
#define DBUS_ADDRESS_MNTALL "unix:abstract=/com/ubuntu/mountall/server/"
#endif


#endif /* DBUS_MNTALL_H */
