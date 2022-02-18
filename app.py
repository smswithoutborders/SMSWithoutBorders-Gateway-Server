#!/usr/bin/env python3

from flask import Flask, request, jsonify
from flask_cors import CORS
from base64 import b64decode, b64encode
import os
import configparser
import logging
import json

from gateway_server.ledger import Ledger
from gateway_server.users import Users


__api_version_number = 2

__gateway_server_confs = configparser.ConfigParser()
__gateway_server_confs.read(os.path.join(
    os.path.dirname(__file__), 'gateway_server/confs', 'conf.ini'))

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
            gateway_server_websocket_url = __gateway_server_confs['websocket']['url']
            gateway_server_websocket_port = __gateway_server_confs['websocket']['port']
            session_id = user.start_new_session()

            # http://localhost/v2/sync/init/1s1s/sss
            return "%s:%s/v%s/sync/init/%s/%s" % (gateway_server_websocket_url,
                    gateway_server_websocket_port, __api_version_number, user_id, session_id), 200

        except Exception as error:
            logging.exception(error)

    return '', 500


@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>/handshake' % (__api_version_number), methods=['POST'])
def sessions_public_key_exchange(user_id, session_id):
    """Generates a shared for the user attached to this session.
    Args:
            user_id (str): UserID provided when the user logs in
            session_id (str): Unique ID as has been provided by the websocket connections. The use of this is to keep
            the user safe; changing the QR code during generated stops using expired QR codes during the sync process.

    Returns: {}, int

    TODO:
    - Extract public key from body
    - Store public_key key against session
    - return own public key and user_id
    """

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


if __name__ == "__main__":
    logging.basicConfig(level='DEBUG')

    debug = bool(__gateway_server_confs['server']['debug'])
    host = __gateway_server_confs['server']['host']
    port = int(__gateway_server_confs['server']['port'])

    app.run(host=host, port=port, debug=True, threaded=True )
