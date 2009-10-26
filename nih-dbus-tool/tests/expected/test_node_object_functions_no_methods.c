int
my_test_emit_bounce (DBusConnection *connection,
                     const char *    origin_path,
                     uint32_t        height,
                     int32_t         velocity)
{
	DBusMessage *   signal;
	DBusMessageIter iter;

	nih_assert (connection != NULL);
	nih_assert (origin_path != NULL);

	/* Construct the message. */
	signal = dbus_message_new_signal (origin_path, "com.netsplit.Nih.Test", "Bounce");
	if (! signal)
		return -1;

	dbus_message_iter_init_append (signal, &iter);

	/* Marshal a uint32_t onto the message */
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_UINT32, &height)) {
		dbus_message_unref (signal);
		return -1;
	}

	/* Marshal a int32_t onto the message */
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_INT32, &velocity)) {
		dbus_message_unref (signal);
		return -1;
	}

	/* Send the signal, appending it to the outgoing queue. */
	if (! dbus_connection_send (connection, signal, NULL)) {
		dbus_message_unref (signal);
		return -1;
	}

	dbus_message_unref (signal);

	return 0;
}


int
my_test_emit_exploded (DBusConnection *connection,
                       const char *    origin_path)
{
	DBusMessage *   signal;
	DBusMessageIter iter;

	nih_assert (connection != NULL);
	nih_assert (origin_path != NULL);

	/* Construct the message. */
	signal = dbus_message_new_signal (origin_path, "com.netsplit.Nih.Test", "Exploded");
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


static int
my_com_netsplit_Nih_Test_colour_get (NihDBusObject *  object,
                                     NihDBusMessage * message,
                                     DBusMessageIter *iter)
{
	DBusMessageIter variter;
	char *          value;

	nih_assert (object != NULL);
	nih_assert (message != NULL);
	nih_assert (iter != NULL);

	/* Call the handler function */
	if (my_test_get_colour (object->data, message, &value) < 0)
		return -1;

	/* Append a variant onto the message to contain the property value. */
	if (! dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "s", &variter)) {
		nih_error_raise_no_memory ();
		return -1;
	}

	/* Marshal a char * onto the message */
	if (! dbus_message_iter_append_basic (&variter, DBUS_TYPE_STRING, &value)) {
		dbus_message_iter_abandon_container (iter, &variter);
		nih_error_raise_no_memory ();
		return -1;
	}

	/* Finish the variant */
	if (! dbus_message_iter_close_container (iter, &variter)) {
		nih_error_raise_no_memory ();
		return -1;
	}

	return 0;
}

static int
my_com_netsplit_Nih_Test_colour_set (NihDBusObject *  object,
                                     NihDBusMessage * message,
                                     DBusMessageIter *iter)
{
	DBusMessageIter variter;
	const char *    value_dbus;
	char *          value;

	nih_assert (object != NULL);
	nih_assert (message != NULL);
	nih_assert (iter != NULL);

	/* Recurse into the variant */
	if (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_VARIANT) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Invalid arguments to colour property");
		return -1;
	}

	dbus_message_iter_recurse (iter, &variter);

	/* Demarshal a char * from the message */
	if (dbus_message_iter_get_arg_type (&variter) != DBUS_TYPE_STRING) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Invalid arguments to colour property");
		return -1;
	}

	dbus_message_iter_get_basic (&variter, &value_dbus);

	value = nih_strdup (message, value_dbus);
	if (! value) {
		nih_error_raise_no_memory ();
		return -1;
	}

	dbus_message_iter_next (&variter);

	dbus_message_iter_next (iter);

	if (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_INVALID) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Invalid arguments to colour property");
		return -1;
	}

	/* Call the handler function */
	if (my_test_set_colour (object->data, message, value) < 0)
		return -1;

	return 0;
}


static int
my_com_netsplit_Nih_Test_size_get (NihDBusObject *  object,
                                   NihDBusMessage * message,
                                   DBusMessageIter *iter)
{
	DBusMessageIter variter;
	uint32_t        value;

	nih_assert (object != NULL);
	nih_assert (message != NULL);
	nih_assert (iter != NULL);

	/* Call the handler function */
	if (my_test_get_size (object->data, message, &value) < 0)
		return -1;

	/* Append a variant onto the message to contain the property value. */
	if (! dbus_message_iter_open_container (iter, DBUS_TYPE_VARIANT, "u", &variter)) {
		nih_error_raise_no_memory ();
		return -1;
	}

	/* Marshal a uint32_t onto the message */
	if (! dbus_message_iter_append_basic (&variter, DBUS_TYPE_UINT32, &value)) {
		dbus_message_iter_abandon_container (iter, &variter);
		nih_error_raise_no_memory ();
		return -1;
	}

	/* Finish the variant */
	if (! dbus_message_iter_close_container (iter, &variter)) {
		nih_error_raise_no_memory ();
		return -1;
	}

	return 0;
}


static int
my_com_netsplit_Nih_Test_touch_set (NihDBusObject *  object,
                                    NihDBusMessage * message,
                                    DBusMessageIter *iter)
{
	DBusMessageIter variter;
	int             value;

	nih_assert (object != NULL);
	nih_assert (message != NULL);
	nih_assert (iter != NULL);

	/* Recurse into the variant */
	if (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_VARIANT) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Invalid arguments to touch property");
		return -1;
	}

	dbus_message_iter_recurse (iter, &variter);

	/* Demarshal a int from the message */
	if (dbus_message_iter_get_arg_type (&variter) != DBUS_TYPE_BOOLEAN) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Invalid arguments to touch property");
		return -1;
	}

	dbus_message_iter_get_basic (&variter, &value);

	dbus_message_iter_next (&variter);

	dbus_message_iter_next (iter);

	if (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_INVALID) {
		nih_dbus_error_raise_printf (DBUS_ERROR_INVALID_ARGS,
		                             "Invalid arguments to touch property");
		return -1;
	}

	/* Call the handler function */
	if (my_test_set_touch (object->data, message, value) < 0)
		return -1;

	return 0;
}


int
my_foo_emit_new_result (DBusConnection *connection,
                        const char *    origin_path)
{
	DBusMessage *   signal;
	DBusMessageIter iter;

	nih_assert (connection != NULL);
	nih_assert (origin_path != NULL);

	/* Construct the message. */
	signal = dbus_message_new_signal (origin_path, "com.netsplit.Nih.Foo", "NewResult");
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
