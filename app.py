#!/usr/bin/env python3

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from clients import Clients

app = Flask(__name__)
CORS(app)

@app.route('/clients', methods=['GET'])
def get_clients():
    logging.debug('fetching clients')

    try:
        clients = Clients()
        list_clients = clients.get_list()

        return jsonify(list_clients), 200
    except Exception as error:
        logging.exception(error)

    return '', 500


@app.route('/clients', methods=['POST'])
def init_handshake_clients():
    logging.debug('beginning clients handshake')


    return '', 500


if __name__ == "__main__":

    logging.basicConfig(level='DEBUG')

    debug = True
    app.run(debug=debug)
