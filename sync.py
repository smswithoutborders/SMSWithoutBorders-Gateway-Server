
def sessions_start(user_id):
    """Begins a new synchronization session for User.
    
    A user can have multiple sessions.

    Actions:
    - create user record and store session ID.
    - attach session ID to websocket url and return to agent.

    Args:
            user_id (str): UserID provided when the user logs in.

    Returns: {}, int
    
    TODO:
        - figure out mechanism to determine session expiration.

    """
    try:
        user = Users(user_id)
    except Exception as error:
        logging.exception(error)

    else:
        try:
            session_id = user.start_new_session()

            # ws://localhost/v2/sync/init/1s1s/sss
            websocket_protocol = "ws"
            if (
                    os.path.exists(gateway_server.websocket_ssl_crt_filepath) and 
                    os.path.exists(gateway_server.websocket_ssl_key_filepath)):
                websocket_protocol = "wss"
                gateway_server.websocket_url = gateway_server.websocket_ssl_url
                        
            synchronization_initialization_url = "%s://%s:%s/v%s/sync/init/%s/%s" % (websocket_protocol, 
                    gateway_server.websocket_url,
                    gateway_server.websocket_port, 
                    __api_version_number, 
                    user_id, session_id)

            mobile_url = ""

            return synchronization_initialization_url, 200

        except Exception as error:
            logging.exception(error)

    return '', 500


def sessions_public_key_exchange(user_id, session_id):
    """Generates a shared for the user attached to this session.
    Args:
            user_id (str): User ID provided when the user logs in
            session_id (str): Unique ID as has been provided by the websocket connections. The use of this is to keep
            the user safe; changing the QR code during generated stops using expired QR codes during the sync process.

    Returns: {}, int

    TODO:
        - Extract public key from body
        - Store public_key key against session
        - return own public key and user_id
    """

    try:
        data = json.loads(request.data, strict=False)
    except Exception as error:
        logging.exception(error)

        return 'poorly formed json', 400
    else:
        if not 'public_key' in data:
            return 'missing public key', 400

        app.logger.debug("Requesting __PAUSE__")
        gateway_server.websocket_message(message='__PAUSE__', 
                user_id = user_id, session_id = session_id)

        user_public_key = data['public_key']
        # TODO: validate is valid public key

        with open(gateway_server.public_key_filepath, 'r') as public_key_fd:
            gateway_server_public_key = public_key_fd.read()
        
        """Since key value pair is already present, it just returns it """

        try:
            user = Users(user_id)
        except Exception as error:
            logging.exception(error)
        else:
            try:
                """
                TODO:
                    - Check for other criterias here, for example -
                        - does session already have a public key?
                """
                verification_url = '/v%s/sync/users/%s/sessions/%s' % \
                        (__api_version_number, user_id, session_id)

                if user.update_public_key(
                        session_id = session_id, public_key=user_public_key) > 0:

                    return jsonify(
                            {"public_key": gateway_server_public_key,
                                "verification_url": verification_url
                                }), 200
                else:
                    logging.error("failed to update user[%s] session[%s]", user_id, session_id)
                return "failed to update user's public key", 400

            except Exception as error:
                logging.exception(error)
                return "failed to update user's public key", 500

    return '', 500


def sessions_user_update(user_id, session_id):
    """Updates the current session for user.
    Uses users ID and session ID to update current user's session on the users record DB.

    Args:
            user_id (str): User ID provided when the user logs in
            session_id (str): Unique ID as has been provided by the websocket connections

    Returns: str, int

    TODO:
    """
    # logging.debug("updating user session from - %s to - %s", session_id, new_session_id)
    try:
        user = Users(user_id)
    except Exception as error:
        logging.exception(error)
    else:
        new_session_id = user.update_current_session(session_id)
        return new_session_id, 200

    return '', 500


def sessions_user_fetch(user_id, session_id):
    """Authenticates and fetches information to populate the usser's app.
    Authenticating users happen at the BE user management API which can be configured in the config routes.
    Args:
            user_id (str): User ID provided when the user logs in
            session_id (str): Unique ID as has been provided by the websocket connections
    Body:
        password (str): User password encrypted with server public key

    Returns: {}, int

    TODO:
    - Decrypts the user password with own public key
    - Authenticate user with user_id and decrypted password
    - Use header to make request to API for platforms details
    - Read complete ledger for available Gateways
    - Generate and store secret (shared) key for against user
    - Return platforms, gateways, user ID and secret key to user
    """

    try:
        data = request.json
    except Exception as error:
        return 'invalid json', 400
    else:
        if not 'password' in data:
            return 'missing password', 400

        try:
            """
            Password is in base64 and encrypted with server's public key
            """
            password = data['password']

            decrypted_password = SecurityRSA.decrypt(
                    data=password,
                    private_key_filepath=gateway_server.private_key_filepath)
            decrypted_password = decrypted_password.decode('utf-8')
        except Exception as error:
            logging.exception(error)
            return '', 500
        else:
            try:
                state, request_payload = \
                        sessions_websocket.user_management_api_authenticate_user( 
                                password=decrypted_password, 
                                user_id = user_id )
            except Exception as error:
                # TODO figure out what the issue here
                logging.error(error)
                logging.exception(error)
                return 'failed to authenticate', 401
            else:
                app.logger.debug("Sending ACK__")
                gateway_server.websocket_message(
                        message='__ACK__', user_id=user_id, session_id=session_id)
                # Authentication details are stored in the cookies, so use them for further request
                # Shouldn't be stored because they expire after a while

                try:
                    user = Users(user_id) 
                    shared_key = user.update_shared_key(session_id=session_id)
                    app.logger.debug("Shared key: %s", shared_key)

                    user_public_key = user.get_public_key(session_id=session_id)
                    if len(user_public_key) < 1:
                        return 'invalid session requested', 400

                    user_public_key = user_public_key[0][0]
                except Exception as error:
                    logging.exception(error)
                    return '', 500
                else:
                    encrypted_shared_key: bytes = SecurityRSA.encrypt_with_key(
                            data=shared_key, public_key=user_public_key)

                    encrypted_shared_key = base64.b64encode(encrypted_shared_key)

                    gateway_server_seeds_url = __gateway_confs['seeds']['api_endpoint']
                    user_platforms: dict = \
                            sessions_websocket.user_management_api_request_platforms( 
                                    request=request_payload, user_id = user_id)
                    logging.debug(user_platforms)

                    for i in range(len(user_platforms['saved_platforms'])):
                        user_platforms['saved_platforms'][i]["logo"] = \
                                user_management_api \
                                + user_platforms['saved_platforms'][i]["logo"] 

                    user_platforms = user_platforms["saved_platforms"]

                    return jsonify(
                            {
                                "shared_key": encrypted_shared_key.decode('utf-8'),
                                "user_platforms": user_platforms,
                                "seeds_url": gateway_server_seeds_url
                                }), 200
    return '', 500
