#!/usr/bin/env python3

import configparser, os, json
import re
import requests
import traceback

from flask import Flask, request, jsonify
from flask_cors import CORS
from commons.CustomConfigParser.customconfigparser import CustomConfigParser
from cluster import Cluster

app = Flask(__name__)
CORS(app)

configreader = CustomConfigParser(os.getcwd())
config=configreader.read('.configs/config.ini')
rmq_server_url=config['rabbit_mq']['server_url']
rmq_outgoing_exchange_name=config['rabbit_mq']['exchange_name']
rmq_outgoing_exchange_type=config['rabbit_mq']['exchange_type']
rmq_outgoing_queue_name=config['rabbit_mq']['queue_name']

def send_sms(auth_id, data, country=None):
    for request in data:
        try:
            if Cluster.request_sms(
                    auth_id,
                    request, 
                    rmq_server_url, 
                    rmq_outgoing_exchange_name, 
                    rmq_outgoing_exchange_type, 
                    rmq_outgoing_queue_name):

                return True
        except Exception as error:
            print(traceback.format_exc())
            raise(error)

    return False
