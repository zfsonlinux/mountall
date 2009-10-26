int
my_set_property_sync (const void *      parent,
                      NihDBusProxy *    proxy,
                      const MyProperty *value)
{
	DBusMessage *   method_call;
	DBusMessageIter iter;
	DBusMessageIter variter;
	DBusError       error;
	DBusMessage *   reply;
	const char *    interface;
	const char *    property;
	DBusMessageIter value_iter;
	const char *    value_item0;
	uint32_t        value_item1;

	nih_assert (proxy != NULL);
	nih_assert (value != NULL);

	/* Construct the method call message. */
	method_call = dbus_message_new_method_call (proxy->name, proxy->path, "org.freedesktop.DBus.Properties", "Set");
	if (! method_call)
		nih_return_no_memory_error (-1);

	dbus_message_set_auto_start (method_call, proxy->auto_start);

	dbus_message_iter_init_append (method_call, &iter);

	interface = "com.netsplit.Nih.Test";
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &interface)) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (-1);
	}

	property = "property";
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &property)) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (-1);
	}

	if (! dbus_message_iter_open_container (&iter, DBUS_TYPE_VARIANT, "(su)", &variter)) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (-1);
	}

	/* Marshal a structure onto the message */
	if (! dbus_message_iter_open_container (&variter, DBUS_TYPE_STRUCT, NULL, &value_iter)) {
		dbus_message_iter_abandon_container (&iter, &variter);
		dbus_message_unref (method_call);
		nih_return_no_memory_error (-1);
	}

	value_item0 = value->item0;

	/* Marshal a char * onto the message */
	if (! dbus_message_iter_append_basic (&value_iter, DBUS_TYPE_STRING, &value_item0)) {
		dbus_message_iter_abandon_container (&variter, &value_iter);
		dbus_message_iter_abandon_container (&iter, &variter);
		dbus_message_unref (method_call);
		nih_return_no_memory_error (-1);
	}

	value_item1 = value->item1;

	/* Marshal a uint32_t onto the message */
	if (! dbus_message_iter_append_basic (&value_iter, DBUS_TYPE_UINT32, &value_item1)) {
		dbus_message_iter_abandon_container (&variter, &value_iter);
		dbus_message_iter_abandon_container (&iter, &variter);
		dbus_message_unref (method_call);
		nih_return_no_memory_error (-1);
	}

	if (! dbus_message_iter_close_container (&variter, &value_iter)) {
		dbus_message_iter_abandon_container (&iter, &variter);
		dbus_message_unref (method_call);
		nih_return_no_memory_error (-1);
	}

	if (! dbus_message_iter_close_container (&iter, &variter)) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (-1);
	}

	/* Send the message, and wait for the reply. */
	dbus_error_init (&error);

	reply = dbus_connection_send_with_reply_and_block (proxy->connection, method_call, -1, &error);
	if (! reply) {
		dbus_message_unref (method_call);

		if (dbus_error_has_name (&error, DBUS_ERROR_NO_MEMORY)) {
			nih_error_raise_no_memory ();
		} else {
			nih_dbus_error_raise (error.name, error.message);
		}

		dbus_error_free (&error);
		return -1;
	}

	/* Check the reply has no arguments */
	dbus_message_unref (method_call);
	dbus_message_iter_init (reply, &iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INVALID) {
		dbus_message_unref (reply);
		nih_return_error (-1, NIH_DBUS_INVALID_ARGS,
		                  _(NIH_DBUS_INVALID_ARGS_STR));
	}

	dbus_message_unref (reply);

	return 0;
}
