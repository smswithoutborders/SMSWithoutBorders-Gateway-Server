#!/usr/bin/env python3

import configparser, os, json
import re
import requests
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS
from CustomConfigParser.customconfigparser import CustomConfigParser
from cluster import Cluster

app = Flask(__name__)
CORS(app)


configreader = CustomConfigParser(os.getcwd())
config=configreader.read('.configs/config.ini')

rmq_server_url=config['rabbit_mq']['server_url']
rmq_outgoing_exchange_name=config['rabbit_mq']['exchange_name']
rmq_outgoing_exchange_type=config['rabbit_mq']['exchange_type']
rmq_outgoing_queue_name=config['rabbit_mq']['queue_name']

def send_sms(auth_id, data):
    print('* Requesting sms for...')
    for request in data:
        print(f"\t+ number: {request['number']}, isp: {request['isp']}")
        try:
            Cluster.request_sms(
                    auth_id,
                    request, 
                    rmq_server_url, 
                    rmq_outgoing_exchange_name, 
                    rmq_outgoing_exchange_type, 
                    rmq_outgoing_queue_name)
        except Exception as error:
            print(traceback.format_exc())
            raise(error)

    return True


@app.route('/sms/<string:country>', methods=['POST'])
def sms(country:str):
    print('* sending sms...')
    ''' the request is in the data '''

    data=None

    try:
        data=request.json
    except Exception as error:
        print(error)
        return 'invalid json', 400

    if not "auth_id" in data:
        # data["error_requests"] = 'auth ID missing'
        return 'auth ID missing', 400
    """
    if not "auth_key" in data:
        # data["error_requests"] = 'auth Key missing'
        return 'auth Key missing', 400
    if not "project_id" in data:
        # data["error_requests"] = 'auth Key missing'
        return 'project ID missing', 400
    """
    if not "data" in data:
        # data["error_requests"] = 'auth Key missing'
        return 'data missing', 400


    # TODO: Authenticate()

    try:
        auth_id=data['auth_id']
        data1=data['data']
        if send_sms(auth_id=auth_id, data=data1):
            return '', 200
    except Exception as error:
        return jsonify(error), 500


if __name__ == "__main__":
    """
    host = config['API']['host']
    port = config['API']['port']
    """
    host='localhost'
    port='15673'

    app.run(host=host, port=port, debug=True, threaded=True )
