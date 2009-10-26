int
my_emit_signal (DBusConnection *connection,
                const char *    origin_path)
{
	DBusMessage *   signal;
	DBusMessageIter iter;

	nih_assert (connection != NULL);
	nih_assert (origin_path != NULL);

	/* Construct the message. */
	signal = dbus_message_new_signal (origin_path, "com.netsplit.Nih.Test", "Signal");
	if (! signal)
		return -1;

	dbus_message_iter_init_append (signal, &iter);

	/* Send the signal, appending it to the outgoing queue. */
	if (! dbus_connection_send (connection, signal, NULL)) {
		dbus_message_unref (signal);
		return -1;
	}

	dbus_message_unref (signal);

	return 0;
}
