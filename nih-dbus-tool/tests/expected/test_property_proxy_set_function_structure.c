DBusPendingCall *
my_set_test_property (NihDBusProxy *         proxy,
                      const MyTestProperty * value,
                      MySetTestPropertyReply handler,
                      NihDBusErrorHandler    error_handler,
                      void *                 data,
                      int                    timeout)
{
	DBusMessage *       method_call;
	DBusMessageIter     iter;
	DBusMessageIter     variter;
	DBusPendingCall *   pending_call;
	NihDBusPendingData *pending_data;
	const char *        interface;
	const char *        property;
	DBusMessageIter     value_iter;
	const char *        value_item0;
	uint32_t            value_item1;

	nih_assert (proxy != NULL);
	nih_assert (value != NULL);
	nih_assert ((handler == NULL) || (error_handler != NULL));

	/* Construct the method call message. */
	method_call = dbus_message_new_method_call (proxy->name, proxy->path, "org.freedesktop.DBus.Properties", "Set");
	if (! method_call)
		nih_return_no_memory_error (NULL);

	dbus_message_set_auto_start (method_call, proxy->auto_start);

	dbus_message_iter_init_append (method_call, &iter);

	interface = "com.netsplit.Nih.Test";
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &interface)) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	property = "test_property";
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &property)) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	if (! dbus_message_iter_open_container (&iter, DBUS_TYPE_VARIANT, "(su)", &variter)) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	/* Marshal a structure onto the message */
	if (! dbus_message_iter_open_container (&variter, DBUS_TYPE_STRUCT, NULL, &value_iter)) {
		dbus_message_iter_abandon_container (&iter, &variter);
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	value_item0 = value->item0;

	/* Marshal a char * onto the message */
	if (! dbus_message_iter_append_basic (&value_iter, DBUS_TYPE_STRING, &value_item0)) {
		dbus_message_iter_abandon_container (&variter, &value_iter);
		dbus_message_iter_abandon_container (&iter, &variter);
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	value_item1 = value->item1;

	/* Marshal a uint32_t onto the message */
	if (! dbus_message_iter_append_basic (&value_iter, DBUS_TYPE_UINT32, &value_item1)) {
		dbus_message_iter_abandon_container (&variter, &value_iter);
		dbus_message_iter_abandon_container (&iter, &variter);
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	if (! dbus_message_iter_close_container (&variter, &value_iter)) {
		dbus_message_iter_abandon_container (&iter, &variter);
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	if (! dbus_message_iter_close_container (&iter, &variter)) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	/* Handle a fire-and-forget message */
	if (! error_handler) {
		dbus_message_set_no_reply (method_call, TRUE);
		if (! dbus_connection_send (proxy->connection, method_call, NULL)) {
			dbus_message_unref (method_call);
			nih_return_no_memory_error (NULL);
		}

		dbus_message_unref (method_call);
		return (DBusPendingCall *)TRUE;
	}

	/* Send the message and set up the reply notification. */
	pending_data = nih_dbus_pending_data_new (NULL, proxy->connection,
	                                          (NihDBusReplyHandler)handler,
	                                          error_handler, data);
	if (! pending_data) {
		dbus_message_unref (method_call);
		nih_return_no_memory_error (NULL);
	}

	pending_call = NULL;
	if (! dbus_connection_send_with_reply (proxy->connection, method_call,
	                                       &pending_call, timeout)) {
		dbus_message_unref (method_call);
		nih_free (pending_data);
		nih_return_no_memory_error (NULL);
	}

	dbus_message_unref (method_call);

	NIH_MUST (dbus_pending_call_set_notify (pending_call, (DBusPendingCallNotifyFunction)my_com_netsplit_Nih_Test_test_property_set_notify,
	                                        pending_data, (DBusFreeFunction)nih_discard));

	return pending_call;
}
