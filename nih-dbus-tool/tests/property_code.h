/* nih-dbus-tool
 *
 * Copyright © 2009 Scott James Remnant <scott@netsplit.com>.
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

#ifndef NIH_DBUS_TOOL_TESTS_PROPERTY_CODE_H
#define NIH_DBUS_TOOL_TESTS_PROPERTY_CODE_H

#include <nih/macros.h>

#include <dbus/dbus.h>

#include <nih-dbus/dbus_message.h>
#include <nih-dbus/dbus_object.h>
#include <nih-dbus/dbus_pending_data.h>
#include <nih-dbus/dbus_proxy.h>


typedef void (*MyGetPropertyReply) (void *data, NihDBusMessage *message,
				    const char *value);
typedef void (*MySetPropertyReply) (void *data, NihDBusMessage *message);

typedef void (*MyGetTestPropertyReply) (void *data, NihDBusMessage *message,
					const char *value);
typedef void (*MySetTestPropertyReply) (void *data, NihDBusMessage *message);


NIH_BEGIN_EXTERN

int              my_com_netsplit_Nih_Test_property_get (NihDBusObject *object,
							NihDBusMessage *message,
							DBusMessageIter *iter)
	__attribute__ ((warn_unused_result));
int              my_com_netsplit_Nih_Test_property_set (NihDBusObject *object,
							NihDBusMessage *message,
							DBusMessageIter *iter)
	__attribute__ ((warn_unused_result));

DBusPendingCall *my_get_test_property (NihDBusProxy *proxy,
				       MyGetTestPropertyReply handler,
				       NihDBusErrorHandler error_handler,
				       void *data, int timeout)
	__attribute__ ((warn_unused_result));

void             my_com_netsplit_Nih_Test_property_get_notify (DBusPendingCall *pending_call,
							       NihDBusPendingData *pending_data);

DBusPendingCall *my_set_test_property (NihDBusProxy *proxy,
				       const char *value,
				       MySetTestPropertyReply handler,
				       NihDBusErrorHandler error_handler,
				       void *data, int timeout)
	__attribute__ ((warn_unused_result));

void             my_com_netsplit_Nih_Test_property_set_notify (DBusPendingCall *pending_call,
							       NihDBusPendingData *pending_data);

int              my_get_property_sync (const void *parent,
				       NihDBusProxy *proxy, char **value)
	__attribute__ ((warn_unused_result));
int              my_set_property_sync (const void *parent,
				       NihDBusProxy *proxy, const char *value)
	__attribute__ ((warn_unused_result));

NIH_END_EXTERN

#endif /* NIH_DBUS_TOOL_TESTS_PROPERTY_CODE_H */
