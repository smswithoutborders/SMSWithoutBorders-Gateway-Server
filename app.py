#!/usr/bin/env python3

# Use this for IDEs to check data types
# https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import os
import configparser
import logging
import json
import websocket

from gateway_server import sessions_websocket
from gateway_server.ledger import Ledger
from gateway_server.users import Users
from security.rsa import SecurityRSA


__api_version_number = 2

__gateway_server_confs = configparser.ConfigParser()
__gateway_server_confs.read(os.path.join(
    os.path.dirname(__file__), 'gateway_server/confs', 'conf.ini'))

__gateway_confs = configparser.ConfigParser()
__gateway_confs.read(os.path.join(
    os.path.dirname(__file__), 'confs', 'conf.ini'))

app = Flask(__name__)
CORS(app)


@app.route('/clients/status/<IMSI>', methods=['GET'])
def get_client_imsi(IMSI):
    if not IMSI:
        return 'missing IMSI', 400


@app.route('/clients', methods=['GET'])
def get_clients():
    logging.debug('fetching clients')
    try:
        list_clients = Ledger().get_list()

        return jsonify(list_clients), 200
    except Exception as error:
        logging.exception(error)

    return '', 500


"""
@app.route('/clients/status/<IMSI>', methods=['GET'])
def get_clients(IMSI):
    logging.debug('beginning clients handshake')

    try:
        client = Clients(number=data['number'], 
                sim_imei=data['sim_imei'])
    except Exception as error:
        # raise error
        logging.exception(error)
    else:
        try:
            logging.debug("cheking if client exist...")
            if client.exist():
                # return jsonify({"route_path":route_path}), 200
                return 'exist'

            else:
                return 'not exist'
        except Exception as error:
            logging.exception(error)

    return '', 500
"""


def publish_record(Body: str, From: str) -> bool:
    try:
        data = json.loads(b64decode(Body))
        logging.debug("%s", data)

    except Exception as error:
        raise error
    else:
        if not 'IMSI' in data:
            logging.error('no IMSI in data - %s', data)
            return False

        try:
            ledger = Ledger()

            data = {"MSISDN": From, "IMSI": data['IMSI'], "update_platform": platform}
            if not ledger.exist(data):
                ledger.create(data=data)
                logging.info("New record inserted")
            else:
                logging.info("Record exist")
        except Exception as error:
            raise error
        else:
            # TODO: https://www.twilio.com/docs/sms/tutorials/how-to-receive-and-reply-python
            # return jsonify({"MSISDN":From}), 200
            return True


@app.route('/v%s/sync/users/<user_id>' % (__api_version_number), methods=['GET'])
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
            gateway_server_websocket_url = __gateway_server_confs['websocket']['host']
            gateway_server_websocket_port = __gateway_server_confs['websocket']['port']
            session_id = user.start_new_session()

            # ws://localhost/v2/sync/init/1s1s/sss
            websocket_ssl_crt_filepath = __gateway_server_confs['websocket_ssl']['crt']
            websocket_ssl_key_filepath = __gateway_server_confs['websocket_ssl']['key']

            websocket_protocol = "ws"
            if (
                    os.path.exists(websocket_ssl_crt_filepath) and 
                    os.path.exists(websocket_ssl_key_filepath)):
                websocket_protocol = "wss"
                        

            return "%s://%s:%s/v%s/sync/init/%s/%s" % (websocket_protocol, 
                    gateway_server_websocket_url,
                    gateway_server_websocket_port, 
                    __api_version_number, 
                    user_id, session_id), 200

        except Exception as error:
            logging.exception(error)

    return '', 500


@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>/handshake' % (__api_version_number), methods=['POST'])
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

        websocket_message(message='__PAUSE__', 
                user_id = user_id, session_id = session_id)

        user_public_key = data['public_key']
        # TODO: validate is valid public key

        public_key_filepath = __gateway_confs['security']['public_key_filepath']
        private_key_filepath = __gateway_confs['security']['private_key_filepath']

        with open(public_key_filepath, 'r') as public_key_fd:
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

                if user.update_public_key(session_id = session_id, public_key=user_public_key) > 0:
                    return jsonify(
                            {"public_key": gateway_server_public_key,
                                "verification_url": verification_url
                                })
                else:
                    logging.error("failed to update user[%s] session[%s]", user_id, session_id)
                return "failed to update user's public key", 400

            except Exception as error:
                logging.exception(error)
                return "failed to update user's public key", 500

    return '', 500


@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>' % (__api_version_number), methods=['PUT'])
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


@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>' % (__api_version_number), methods=['POST'])
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

        __gateway_confs_private_key_filepath = __gateway_confs['security']['private_key_filepath']

        try:
            """
            Password is in base64 and encrypted with server's public key
            """
            password = data['password']

            decrypted_password = SecurityRSA.decrypt(
                    data=password,
                    private_key_filepath=__gateway_confs_private_key_filepath)
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
                return 'failed to authenticate', 401
            else:
                websocket_message(message='__ACK__', user_id=user_id, session_id=session_id)
                logging.debug("Authenticated successfully")

                # Authentication details are stored in the cookies, so use them for further request
                # Shouldn't be stored because they expire after a while

                try:
                    user = Users(user_id) 
                    shared_key = user.update_shared_key(session_id=session_id)

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
                    logging.debug("encrypted_shared_key: %s", encrypted_shared_key)

                    gateway_clients: list = []
                    user_platforms: dict = \
                            sessions_websocket.user_management_api_request_platforms( 
                                    request=request_payload, user_id = user_id)

                    for i in range(len(user_platforms['saved_platforms'])):
                        user_platforms['saved_platforms'][i]["logo"] = \
                                __gateway_confs['user_management_api']['verification_url'] + \
                                user_platforms['saved_platforms'][i]["logo"] 
                    logging.debug(user_platforms)

                    user_platforms = user_platforms["saved_platforms"]
                    logging.debug("user_platforms_payload: %s", user_platforms)

                    return jsonify(
                            {
                                "shared_key": encrypted_shared_key.decode('utf-8'),
                                "user_platforms": user_platforms,
                                "gateway_clients": gateway_clients
                                }), 200
    return '', 500


@app.route('/sms/platform/<platform>/incoming/protocol/verification', methods=['POST'])
def sms_incoming(platform):
    """Receive inbound messages from Webhooks.
    Given that this URL is unique, only seeders can have the required key to route to them
        TODO:
            - Add platform security with secret keys at url levels
    """

    if not platform:
        return 'no platform provided', 500
    logging.debug('incoming sms for platform %s', platform)

    if platform == 'twilio':

        From = request.values.get('From', None)
        To = request.values.get('To', None)
        FromCountry = request.values.get('FromCountry', None)
        NumSegments = request.values.get('NumSegments', None)
        Body = request.values.get('Body', None)

        logging.debug('\nFrom: %s\nTo: %s\nFrom Country: %s\nBody: %s',
                      From, To, FromCountry, Body)

        try:
            if publish_record(Body=Body, From=From):
                return '', 200
            else:
                return '', 400
        except Exception as error:
            return '', 500

    if platform == 'gateway-client':
        try:
            From = request.values.get('From', None)
            Body = request.values.get('Body', None)
            if publish_record(Body=Body, From=From):
                return '', 200
            else:
                return '', 400
        except Exception as error:
            return '', 500

    else:
        return 'unknown platform requested', 400

    return '', 200


def create_clients(data: dict) -> None:
    try:
        logging.debug("creating client...")
        '''
        validate -
            - is valid number
            - number matches imsi origins
        - from number extract country
        '''
        client.create(data)
        # return jsonify({"route_path":route_path}), 200
    except Exception as error:
        # logging.exception(error)
        raise error


def generate_keypair(private_key_filepath: str, public_key_filepath: str) -> tuple:
    """Generates the main keypair values for Instance of Gateway server
    """
    # securityRSA = SecurityRSA()
    public_key, private_key = SecurityRSA.generate_keypair_write(
            private_key_filepath=private_key_filepath, 
            public_key_filepath=public_key_filepath)

    return public_key, private_key


def check_has_keypair(private_key_filepath, public_key_filepath) -> bool:
    """Checks if public keys are installed on the system.
    """
    if not os.path.isfile(public_key_filepath):
        logging.debug("public key not present at: %s", public_key_filepath)
        return False

    if not os.path.isfile(private_key_filepath):
        logging.debug("private key not present at: %s", private_key_filepath)
        return False
    
    return True

def websocket_message(message: str, user_id: str, session_id: str) -> None:
    """Messages the default gateway server websocket.

    Args:
        message (str):
            Should contain the state of the synchronization process. Either of the following:
                - __PAUSE__
                - __ACK__
    """

    ssl_context=None
    websocket_ssl_crt_filepath = __gateway_server_confs['websocket_ssl']['crt']
    websocket_ssl_key_filepath = __gateway_server_confs['websocket_ssl']['key']
    # websocket_ssl_pem_filepath = __gateway_server_confs['websocket_ssl']['pem']

    websocket_protocol = "ws"
    if (
            os.path.exists(websocket_ssl_crt_filepath) and 
            os.path.exists(websocket_ssl_key_filepath)):

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=websocket_ssl_crt_filepath, keyfile=websocket_ssl_key_filepath)
        websocket_protocol = "wss"

    '''
    if message == 'ack':
        # uri= f"ws://localhost:{CONFIGS['WEBSOCKET']['PORT']}/sync/ack/{session_id}"
        uri= f"{CONFIGS['WEBSOCKET']['URL']}:{CONFIGS['WEBSOCKET']['PORT']}/sync/ack/{session_id}"
        print(uri)
        ws = websocket.WebSocketApp(uri, on_error=socket_message_error)
        if not ssl_context == None:
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            ws.run_forever()
    '''

    if message == '__PAUSE__':
        def socket_message_error(wsapp, error):
            logging.error(error)

        # ws://localhost:6996/v2/sync/pause/user_id/session_id
        websocket_url = "%s://%s:%s/v%s/sync/pause/%s/%s" % (
                websocket_protocol,
                __gateway_server_confs['websocket']['host'],
                __gateway_server_confs['websocket']['port'],
                __api_version_number,
                user_id,
                session_id)

        logging.debug("pausing url: %s", websocket_url)
        ws = websocket.WebSocketApp(websocket_url, on_error=socket_message_error)
        if not ssl_context == None:
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            ws.run_forever()

    elif message == '__ACK__':
        def socket_message_error(wsapp, error):
            logging.error(error)

        # ws://localhost:6996/v2/sync/pause/user_id/session_id
        websocket_url = "%s://%s:%s/v%s/sync/ack/%s/%s" % (
                websocket_protocol,
                __gateway_server_confs['websocket']['host'],
                __gateway_server_confs['websocket']['port'],
                __api_version_number,
                user_id,
                session_id)

        logging.debug("ack url: %s", websocket_url)
        ws = websocket.WebSocketApp(websocket_url, on_error=socket_message_error)
        if not ssl_context == None:
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            ws.run_forever()

    else:
        logging.error("Unknown socket message %s", message)

if __name__ == "__main__":
    logging.basicConfig(level='DEBUG')

    debug = bool(__gateway_confs['api']['debug'])
    host = __gateway_confs['api']['host']
    port = int(__gateway_confs['api']['port'])

    __gateway_confs_public_key_filepath = __gateway_confs['security']['public_key_filepath']
    __gateway_confs_private_key_filepath = __gateway_confs['security']['private_key_filepath']

    if not check_has_keypair(
            __gateway_confs_private_key_filepath,
            __gateway_confs_public_key_filepath):

        public_key, private_key = generate_keypair(
                __gateway_confs_private_key_filepath, 
                __gateway_confs_public_key_filepath)
        logging.debug("Generated public key: %s", public_key)
        logging.debug("Generated private key: %s", private_key)

    logging.debug("- public key filepath: %s\n- private key filepath: %s", 
            __gateway_confs_public_key_filepath,
            __gateway_confs_private_key_filepath)

    app.run(host=host, port=port, debug=debug, threaded=True )
