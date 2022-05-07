#!/usr/bin/env python3

# Use this for IDEs to check data types
# https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS

import base64
import os
import configparser
import json
import websocket
import ssl
import logging

from gateway_server import sessions_websocket
from gateway_server.ledger import Ledger
from gateway_server.users import Users
from gateway_server.security.rsa import SecurityRSA
from gateway_server.seeds import Seeds
import gateway_server.main as gateway_server


logging.basicConfig(level='DEBUG')
__api_version_number = 2

__gateway_confs = configparser.ConfigParser()
__gateway_confs.read(os.path.join(
    os.path.dirname(__file__), 'confs', 'conf.ini'))

user_management_api = __gateway_confs['user_management_api']['api_url']

app = Flask(__name__)
# TODO Add origins to config file
CORS(
    app,
    origins="*",
    supports_credentials=True,
)

@app.route('/seeds/ping', methods=['POST'])
def seed_pings():
    try:
        data = request.json
    except Exception as error:
        return '', 500
    else:
        if not "IMSI" in data:
            return 'missing IMSI', 400

        if not "MSISDN" in data:
            return 'missing MSISDN', 400

        if not "seed_type" in data:
            return 'missing seeder state', 400

        seed_IMSI = data['IMSI']
        seed_MSISDN = data['MSISDN']
        seed_type = data['seed_type']

        try:
            seed = Seeds(IMSI=seed_IMSI, MSISDN=seed_MSISDN, seed_type=seed_type)

            LPS = seed.register_ping_request()
            app.logger.debug("Registered new ping LPS: %s", LPS)
        except Exception as error:
            logging.exception(error)
            return '', 500
        else:
            return LPS, 200

    return '', 500


@app.route('/seeds', methods=['GET'])
def get_seeds():
    try:
        seeds = Seeds.list()
        return jsonify(seeds), 200
    except Exception as error:
        logging.exception(error)

    return '', 500

@app.route('/seeds/<IMSI>', methods=['GET'])
def get_seed_IMSI(IMSI):
    try:
        seeds = Seeds.list()
        for seed in seeds:
            if seed["IMSI"] == IMSI:
                return seed["MSISDN"], 200

    except Exception as error:
        logging.exception(error)
        return '', 500

    return '', 200


@app.route('/seeders', methods=['GET'])
def get_seeders():
    try:
        seeders = []
        seeds = Seeds.list()
        for seed in seeds:
            if seed["seed_type"] == "seeder":
                seeders.append(seed)
        return jsonify(seeders), 200
    except Exception as error:
        logging.exception(error)

    return '', 500


def publish_record(Body: str, From: str) -> bool:
    try:
        data = json.loads(b64decode(Body))
        app.logger.debug("%s", data)

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
            session_id = user.start_new_session()

            # ws://localhost/v2/sync/init/1s1s/sss
            websocket_protocol = "ws"
            if (
                    os.path.exists(gateway_server.websocket_ssl_crt_filepath) and 
                    os.path.exists(gateway_server.websocket_ssl_key_filepath)):
                websocket_protocol = "wss"
                gateway_server.websocket_url = gateway_server.websocket_ssl_url
                        
            return "%s://%s:%s/v%s/sync/init/%s/%s" % (websocket_protocol, 
                    gateway_server.websocket_url,
                    gateway_server.websocket_port, 
                    __api_version_number, 
                    user_id, session_id), 200

        except Exception as error:
            logging.exception(error)

    return '', 500


@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>/handshake' % 
        (__api_version_number), methods=['POST'])
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
                                })
                else:
                    logging.error("failed to update user[%s] session[%s]", user_id, session_id)
                return "failed to update user's public key", 400

            except Exception as error:
                logging.exception(error)
                return "failed to update user's public key", 500

    return '', 500


@app.route(
        '/v%s/sync/users/<user_id>/sessions/<session_id>' % 
        (__api_version_number), methods=['PUT'])

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


@app.route(
        '/v%s/sync/users/<user_id>/sessions/<session_id>' % 
        (__api_version_number), methods=['POST'])

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
                gateway_server.websocket_message(
                        message='__ACK__', user_id=user_id, session_id=session_id)
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

                    gateway_server_seeds_url = __gateway_confs['seeds']['api_endpoint']
                    user_platforms: dict = \
                            sessions_websocket.user_management_api_request_platforms( 
                                    request=request_payload, user_id = user_id)

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


@app.route('/sms/platform/<platform>', methods=['POST'])
def sms_incoming(platform):
    """Receive inbound messages from Webhooks.
    Given that this URL is unique, only seeders can have the required key to route to them
        TODO:
            - Add platform security with secret keys at url levels
    """

    if not platform:
        return 'no platform provided', 500
    app.logger.debug('incoming sms for platform %s', platform)

    if platform == 'twilio':
        """Receives Form Data.
        """
        From = request.values.get('From', None)
        To = request.values.get('To', None)
        FromCountry = request.values.get('FromCountry', None)
        NumSegments = request.values.get('NumSegments', None)
        Body = request.values.get('Body', None)

        app.logger.debug('\nFrom: %s\nTo: %s\nFrom Country: %s\nBody: %s',
                      From, To, FromCountry, Body)

    else:
        """Receives JSON Data.
        """
        try:
            data = json.loads(request.data)
        except Exception as error:
            logging.exception(error)
            return 'invalid data type, json expected', 500
        else:
            Body = data['text']
            MSISDN = data['MSISDN']

            app.logger.debug('\n+ MSISDN: %s\n+ Body: %s', MSISDN, Body)

    return '', 200


if not gateway_server.check_has_keypair(
        gateway_server.private_key_filepath,
        gateway_server.public_key_filepath):

    public_key, private_key = gateway_server.generate_keypair(
            gateway_server.private_key_filepath, 
            gateway_server.public_key_filepath)
    logging.debug("Generated public key: %s", public_key)
    logging.debug("Generated private key: %s", private_key)

logging.debug("[*] Public key filepath: %s\n[*] Private key filepath: %s", 
        gateway_server.public_key_filepath,
        gateway_server.private_key_filepath)

Ledger.make_ledgers()
logging.debug("[*] Checked and created ledgers...")

if __name__ == "__main__":

    debug = bool(__gateway_confs['api']['debug'])
    host = __gateway_confs['api']['host']
    port = int(__gateway_confs['api']['port'])


    app.run(host=host, port=port, debug=debug, threaded=True )
