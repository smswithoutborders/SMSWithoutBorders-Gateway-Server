#!/usr/bin/env python3

from flask import Flask, request, jsonify
from flask_cors import CORS
import logging

from gateway_server.clients import Clients

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
    '''
    - some handshake happens here
    '''

    ''' database structure --- 
    + number:""
    + country:""
    + sim_imei:""
    + routes_online:""
    + routes_offline:""
    + instantiated_datetime:""
    + shared_key:""
    + public_key:""
    '''

    data = {}
    try:
        data = request.json
        if len(data) < 1:
            return 'data missing', 400

    except Exception as error:
        return 'invalid json format', 500

    if not 'number' in data:
        return 'missing number', 400

    if not 'sim_imei' in data:
        return 'missing sim_imei', 400

    if not 'country' in data:
        return 'missing country', 400
    
    if not 'routes_online' in data:
        return 'missing routes online', 400

    if not 'routes_offline' in data:
        return 'missing routes offline', 400


    try:
        client = Clients()
        client.create(data)

        return '', 200

    except Exception as error:
        logging.exception(error)

    return '', 500


if __name__ == "__main__":

    logging.basicConfig(level='DEBUG')

    debug = True
    app.run(debug=debug)
