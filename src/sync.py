import os
import sync
import ip_grap
import logging

__api_version_number = "2"

def get_sockets_sessions_url(user_id: str, session_id: str) -> str:
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
        # user = Users(user_id)
        user = None
    except Exception as error:
        raise error

    else:
        try:
            # session_id = user.start_new_session()
            host = ip_grap.get_private_ip() \
                    if os.environ.get("HOST") == "127.0.0.1" or os.environ.get("HOST") == "localhost" \
                    else os.environ.get("HOST")

            port = os.environ.get("SOC_PORT") \
                    if "SOC_PORT" in os.environ else int(os.environ.get("PORT")) + 1

            logging.debug("socket host: %s", host)
            logging.debug("socket port: %d", port)

            websocket_protocol = "ws"
            synchronization_initialization_url = "%s://%s:%s/v%s/sync/init/%s/%s" % (websocket_protocol, 
                    host,
                    port,
                    __api_version_number, 
                    user_id, session_id)

            return synchronization_initialization_url

        except Exception as error:
            # logging.exception(error)
            raise error


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
        # data = json.loads(request.data, strict=False)
        data = None
    except Exception as error:
        raise error
    else:
        """
        if not 'public_key' in data:
            return 'missing public key', 400

        app.logger.debug("Requesting __PAUSE__")
        gateway_server.websocket_message(message='__PAUSE__', 
                user_id = user_id, session_id = session_id)

        user_public_key = data['public_key']
        # TODO: validate is valid public key

        with open(gateway_server.public_key_filepath, 'r') as public_key_fd:
            gateway_server_public_key = public_key_fd.read()
        """
        
        try:
            # user = Users(user_id)
            user = None
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

                """
                if user.update_public_key(
                        session_id = session_id, public_key=user_public_key) > 0:

                return jsonify(
                        { "verification_url": verification_url
                            }), 200
                """

                return verification_url

            except Exception as error:
                raise error


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


def sessions_user_fetch(user_id: str, session_id: str, password: str):
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
