#!/usr/bin/env python3

# Use this for IDEs to check data types
# https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS
import sync

import os
import json
import logging

__api_version_number = 2

app = Flask(__name__)

CORS(
    app,
    origins="*",
    supports_credentials=True,
)

"""
steps to sync:
    1. user start sessions with server 
        - sends verification url and user id
            # check make sure no redirects can happen on server
            # Thought - TODO: encrypt user id with server public key and send

        - sends encrypted password to verification url
            # cannot access password screen without handshake being established
            # if event is strictly smswithoutborders, then domain needs be highjacked
            # on app, verify the authenticity of verification url before sending password

            TODO: Authenticate is valid session
            TODO: Figure out where here the malicious person would sit to steal the password
            TODO: If password is stolen access to tokens exposed
            TODO: (something only us will know)
            # Thought - TODO: decrypt encrypted user_id with private key

        - receives encrypted shared key (shared keys should be tied to domains)
            TODO: if shared key stolen, encrypted messages can be decrypted
"""


"""
@app.route('/sms/platform/<platform>', methods=['POST'])
"""


@app.route('/v%s/sync/users/<user_id>' % (__api_version_number), methods=['GET'])
def get_sync_url(user_id: str):
    """
    """
    try:
        session_id = '11111'
        sockets_url = sync.get_sockets_sessions_url(user_id=user_id, session_id=session_id)
    except Exception as error:
        app.logger.exception(error)
        return '', 500
    else:
        return sockets_url, 200


@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>/handshake' % (__api_version_number), methods=['POST'])
def user_perform_handshake(user_id: str, session_id: str):
    """
    """

@app.route( '/v%s/sync/users/<user_id>/sessions/<session_id>' % (__api_version_number), methods=['POST'])
def get_users_platforms(user_id: str):
    """
    """

    """
    return jsonify(
            {
                "shared_key": encrypted_shared_key.decode('utf-8'),
                "user_platforms": user_platforms,
                "seeds_url": gateway_server_seeds_url
                }), 200
    """




if __name__ == "__main__":
    """Requirements: -
    ENV:
        - HOST
        - PORT
        - SOC_PORT = websocket path, host is deduced
        - RSA_PR_KEY = private key path for server
    """
    logging.basicConfig(level='DEBUG')
    try:
        host = os.environ["HOST"]
        port = os.environ["PORT"]
        os.environ["RSA_PR_KEY"]

        debug = True
    except KeyError as error:
        logging.exception(error)
    except Exception as error:
        logging.exception(error)
    else:
        app.run(host=host, port=port, debug=debug, threaded=True )
