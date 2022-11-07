#!/usr/bin/env python3

# Use this for IDEs to check data types
# https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify
from flask_cors import CORS

from src import sync, ip_grap, socket_sessions

import os
import json
import logging
import threading

__api_version_number = 2

RSA_PR_KEY = os.environ.get("RSA_PR_KEY")
HOST = os.environ.get("HOST")
PORT = os.environ.get("PORT")
SOCK_PORT = os.environ.get("SOCK_PORT")

app = Flask(__name__)
app.config.from_object(__name__)

CORS(
    app,
    origins="*",
    supports_credentials=True,
)

"""sockets
"""

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
        port = app.config["SOCK_PORT"]
        host = socket_sessions.get_host(app.config["HOST"])

        sockets_url = sync.get_sockets_sessions_url(user_id=user_id, host=host, port=SOCK_PORT)
    except Exception as error:
        app.logger.exception(error)
        return '', 500
    else:
        return sockets_url, 200


@app.route('/v%s/sync/users/<user_id>/handshake/<session_id>/' % (__api_version_number), methods=['POST'])
def user_perform_handshake(user_id: str, session_id: str):
    """
    """
    app.logger.debug(user_id)
    app.logger.debug(session_id)
    return '', 200

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
