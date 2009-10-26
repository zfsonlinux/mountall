static DBusHandlerResult
my_com_netsplit_Nih_Test_Poke_method (NihDBusObject * object,
                                      NihDBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessage *   reply;
	uint32_t        address;
	char *          value;
	const char *    value_dbus;

	nih_assert (object != NULL);
	nih_assert (message != NULL);

	/* Iterate the arguments to the message and demarshal into arguments
	 * for our own function call.
	 */
	dbus_message_iter_init (message->message, &iter);

	/* Demarshal a uint32_t from the message */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_UINT32) {
		reply = dbus_message_new_error (message->message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid arguments to Poke method");
		if (! reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (! dbus_connection_send (message->connection, reply, NULL)) {
			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_message_iter_get_basic (&iter, &address);

	dbus_message_iter_next (&iter);

	/* Demarshal a char * from the message */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING) {
		reply = dbus_message_new_error (message->message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid arguments to Poke method");
		if (! reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (! dbus_connection_send (message->connection, reply, NULL)) {
			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_message_iter_get_basic (&iter, &value_dbus);

	value = nih_strdup (message, value_dbus);
	if (! value) {
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_iter_next (&iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INVALID) {
		reply = dbus_message_new_error (message->message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid arguments to Poke method");
		if (! reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (! dbus_connection_send (message->connection, reply, NULL)) {
			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Call the handler function */
	nih_error_push_context ();
	if (my_test_poke (object->data, message, address, value) < 0) {
		NihError *err;

		err = nih_error_get ();
		if (err->number == ENOMEM) {
			nih_free (err);
			nih_error_pop_context ();

			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		} else if (err->number == NIH_DBUS_ERROR) {
			NihDBusError *dbus_err = (NihDBusError *)err;

			reply = NIH_MUST (dbus_message_new_error (message->message, dbus_err->name, err->message));
			nih_free (err);
			nih_error_pop_context ();

			NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			reply = NIH_MUST (dbus_message_new_error (message->message, DBUS_ERROR_FAILED, err->message));
			nih_free (err);
			nih_error_pop_context ();

			NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
	}
	nih_error_pop_context ();

	/* If the sender doesn't care about a reply, don't bother wasting
	 * effort constructing and sending one.
	 */
	if (dbus_message_get_no_reply (message->message))
		return DBUS_HANDLER_RESULT_HANDLED;

	do {
		__label__ enomem;

		/* Construct the reply message. */
		reply = dbus_message_new_method_return (message->message);
		if (! reply)
			goto enomem;

		dbus_message_iter_init_append (reply, &iter);
	enomem: __attribute__ ((unused));
	} while (! reply);

	/* Send the reply, appending it to the outgoing queue. */
	NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

	dbus_message_unref (reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}


static DBusHandlerResult
my_com_netsplit_Nih_Test_Peek_method (NihDBusObject * object,
                                      NihDBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessage *   reply;
	uint32_t        address;

	nih_assert (object != NULL);
	nih_assert (message != NULL);

	/* Iterate the arguments to the message and demarshal into arguments
	 * for our own function call.
	 */
	dbus_message_iter_init (message->message, &iter);

	/* Demarshal a uint32_t from the message */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_UINT32) {
		reply = dbus_message_new_error (message->message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid arguments to Peek method");
		if (! reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (! dbus_connection_send (message->connection, reply, NULL)) {
			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_message_iter_get_basic (&iter, &address);

	dbus_message_iter_next (&iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INVALID) {
		reply = dbus_message_new_error (message->message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid arguments to Peek method");
		if (! reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (! dbus_connection_send (message->connection, reply, NULL)) {
			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Call the handler function */
	nih_error_push_context ();
	if (my_test_peek (object->data, message, address) < 0) {
		NihError *err;

		err = nih_error_get ();
		if (err->number == ENOMEM) {
			nih_free (err);
			nih_error_pop_context ();

			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		} else if (err->number == NIH_DBUS_ERROR) {
			NihDBusError *dbus_err = (NihDBusError *)err;

			reply = NIH_MUST (dbus_message_new_error (message->message, dbus_err->name, err->message));
			nih_free (err);
			nih_error_pop_context ();

			NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			reply = NIH_MUST (dbus_message_new_error (message->message, DBUS_ERROR_FAILED, err->message));
			nih_free (err);
			nih_error_pop_context ();

			NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
	}
	nih_error_pop_context ();

	return DBUS_HANDLER_RESULT_HANDLED;
}

int
my_test_peek_reply (NihDBusMessage *message,
                    const char *    value)
{
	DBusMessage *   reply;
	DBusMessageIter iter;

	nih_assert (message != NULL);
	nih_assert (value != NULL);

	/* If the sender doesn't care about a reply, don't bother wasting
	 * effort constructing and sending one.
	 */
	if (dbus_message_get_no_reply (message->message))
		return 0;

	/* Construct the reply message. */
	reply = dbus_message_new_method_return (message->message);
	if (! reply)
		return -1;

	dbus_message_iter_init_append (reply, &iter);

	/* Marshal a char * onto the message */
	if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &value)) {
		dbus_message_unref (reply);
		return -1;
	}

	/* Send the reply, appending it to the outgoing queue. */
	if (! dbus_connection_send (message->connection, reply, NULL)) {
		dbus_message_unref (reply);
		return -1;
	}

	dbus_message_unref (reply);

	return 0;
}


static DBusHandlerResult
my_com_netsplit_Nih_Test_IsValidAddress_method (NihDBusObject * object,
                                                NihDBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessage *   reply;
	uint32_t        address;
	int             is_valid;

	nih_assert (object != NULL);
	nih_assert (message != NULL);

	/* Iterate the arguments to the message and demarshal into arguments
	 * for our own function call.
	 */
	dbus_message_iter_init (message->message, &iter);

	/* Demarshal a uint32_t from the message */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_UINT32) {
		reply = dbus_message_new_error (message->message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid arguments to IsValidAddress method");
		if (! reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (! dbus_connection_send (message->connection, reply, NULL)) {
			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_message_iter_get_basic (&iter, &address);

	dbus_message_iter_next (&iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INVALID) {
		reply = dbus_message_new_error (message->message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid arguments to IsValidAddress method");
		if (! reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (! dbus_connection_send (message->connection, reply, NULL)) {
			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Call the handler function */
	nih_error_push_context ();
	if (my_test_is_valid_address (object->data, message, address, &is_valid) < 0) {
		NihError *err;

		err = nih_error_get ();
		if (err->number == ENOMEM) {
			nih_free (err);
			nih_error_pop_context ();

			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		} else if (err->number == NIH_DBUS_ERROR) {
			NihDBusError *dbus_err = (NihDBusError *)err;

			reply = NIH_MUST (dbus_message_new_error (message->message, dbus_err->name, err->message));
			nih_free (err);
			nih_error_pop_context ();

			NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			reply = NIH_MUST (dbus_message_new_error (message->message, DBUS_ERROR_FAILED, err->message));
			nih_free (err);
			nih_error_pop_context ();

			NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
	}
	nih_error_pop_context ();

	/* If the sender doesn't care about a reply, don't bother wasting
	 * effort constructing and sending one.
	 */
	if (dbus_message_get_no_reply (message->message))
		return DBUS_HANDLER_RESULT_HANDLED;

	do {
		__label__ enomem;

		/* Construct the reply message. */
		reply = dbus_message_new_method_return (message->message);
		if (! reply)
			goto enomem;

		dbus_message_iter_init_append (reply, &iter);

		/* Marshal a int onto the message */
		if (! dbus_message_iter_append_basic (&iter, DBUS_TYPE_BOOLEAN, &is_valid)) {
			dbus_message_unref (reply);
			reply = NULL;
			goto enomem;
		}
	enomem: __attribute__ ((unused));
	} while (! reply);

	/* Send the reply, appending it to the outgoing queue. */
	NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

	dbus_message_unref (reply);

	return DBUS_HANDLER_RESULT_HANDLED;
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


static DBusHandlerResult
my_com_netsplit_Nih_Foo_Bing_method (NihDBusObject * object,
                                     NihDBusMessage *message)
{
	DBusMessageIter iter;
	DBusMessage *   reply;

	nih_assert (object != NULL);
	nih_assert (message != NULL);

	/* Iterate the arguments to the message and demarshal into arguments
	 * for our own function call.
	 */
	dbus_message_iter_init (message->message, &iter);

	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_INVALID) {
		reply = dbus_message_new_error (message->message, DBUS_ERROR_INVALID_ARGS,
		                                "Invalid arguments to Bing method");
		if (! reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		if (! dbus_connection_send (message->connection, reply, NULL)) {
			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		dbus_message_unref (reply);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Call the handler function */
	nih_error_push_context ();
	if (my_foo_bing (object->data, message) < 0) {
		NihError *err;

		err = nih_error_get ();
		if (err->number == ENOMEM) {
			nih_free (err);
			nih_error_pop_context ();

			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		} else if (err->number == NIH_DBUS_ERROR) {
			NihDBusError *dbus_err = (NihDBusError *)err;

			reply = NIH_MUST (dbus_message_new_error (message->message, dbus_err->name, err->message));
			nih_free (err);
			nih_error_pop_context ();

			NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		} else {
			reply = NIH_MUST (dbus_message_new_error (message->message, DBUS_ERROR_FAILED, err->message));
			nih_free (err);
			nih_error_pop_context ();

			NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

			dbus_message_unref (reply);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
	}
	nih_error_pop_context ();

	/* If the sender doesn't care about a reply, don't bother wasting
	 * effort constructing and sending one.
	 */
	if (dbus_message_get_no_reply (message->message))
		return DBUS_HANDLER_RESULT_HANDLED;

	do {
		__label__ enomem;

		/* Construct the reply message. */
		reply = dbus_message_new_method_return (message->message);
		if (! reply)
			goto enomem;

		dbus_message_iter_init_append (reply, &iter);
	enomem: __attribute__ ((unused));
	} while (! reply);

	/* Send the reply, appending it to the outgoing queue. */
	NIH_MUST (dbus_connection_send (message->connection, reply, NULL));

	dbus_message_unref (reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}
