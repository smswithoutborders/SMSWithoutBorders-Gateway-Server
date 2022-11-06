#!/usr/bin/env python3

# Use this for IDEs to check data types
# https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS

import os
import json
import websocket
import logging


logging.basicConfig(level='DEBUG')
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



# App begins handshake from here
@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>/handshake' % (__api_version_number), methods=['POST'])


"""

"""
@app.route('/sms/platform/<platform>', methods=['POST'])

TODO:
    - Generate and store public key pair in secured location
"""

@app.route('/v%s/sync/users/<user_id>' % (__api_version_number), methods=['GET'])
def get_sync_url(user_id: str):
    """
    """
    try:
        sync.get_sockets_sessions_url(user_id=user_id)
    except Exception as error:
        app.logger.exception(error)
        return '', 500

    """ should return the verification_url"""

    return '', 200

@app.route( '/v%s/sync/users/<user_id>/sessions/<session_id>' % (__api_version_number), methods=['POST'])
def get_platforms(user_id: str):
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
        - SOC_PORT 
    """
    host = os.environ.get("HOST")
    port = os.environ.get("PORT")
    debug = True

    app.run(host=host, port=port, debug=debug, threaded=True )
