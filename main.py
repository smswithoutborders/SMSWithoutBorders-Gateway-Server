#!/usr/bin/env python3

# Use this for IDEs to check data types
# https://docs.python.org/3/library/typing.html

from crypt import methods
from flask import Flask, request, jsonify
from flask_cors import CORS

import base64
import os
import configparser
import json
import websocket
import ssl
import logging
import requests
import sqlite3

from gateway_server import sessions_websocket
from gateway_server.ledger import Ledger
from gateway_server.users import Users
from gateway_server.security.rsa import SecurityRSA
from gateway_server.seeds import Seeds
import gateway_server.main as gateway_server

logging.basicConfig(level='DEBUG')
__api_version_number = 2

app = Flask(__name__)
# TODO Add origins to config file
CORS(
    app,
    origins="*",
    supports_credentials=True,
)

@app.route('/v%s/sync/users/<user_id>' % (__api_version_number), methods=['GET'])

@app.route('/v%s/sync/users/<user_id>/sessions/<session_id>/handshake' % (__api_version_number), methods=['POST'])

@app.route( '/v%s/sync/users/<user_id>/sessions/<session_id>' % (__api_version_number), methods=['POST'])

@app.route('/sms/platform/<platform>', methods=['POST'])


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

    ssl_crt = __gateway_confs['api_ssl']['crt']
    ssl_key = __gateway_confs['api_ssl']['key']

    debug = bool(__gateway_confs['api']['debug'])
    host = __gateway_confs['api']['host']
    port = int(__gateway_confs['api']['port'])

    """
    if ssl_crt != "" and ssl_key != "":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ssl_crt, ssl_key)

        app.run(host=host, port=port, debug=debug, threaded=True, ssl_context=context )
    else:
        app.run(host=host, port=port, debug=debug, threaded=True )
    """
    app.run(host=host, port=port, debug=debug, threaded=True )
