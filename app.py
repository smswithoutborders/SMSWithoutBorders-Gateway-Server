#!/usr/bin/env python3

from flask import Flask, request, jsonify
from flask_cors import CORS
from base64 import b64decode,b64encode
import logging
import json

from gateway_server.ledger import Ledger

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
        clients = Clients()
        list_clients = clients.get_list()

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


@app.route('/sms/platform/<platform>/incoming/protocol/verification', methods=['POST'])
def sms_incoming(platform):
    """Receive inbound messages from Webhooks.
        TODO:
            - Add platform security with secret keys at url levels
    """

    logging.debug('incoming sms for platform %s', platform)

    if not platform:
        return 'no platform provided', 500

    if platform == 'twilio':
        logging.debug('incoming for %s', platform)

        From=request.values.get('From', None)
        To=request.values.get('To', None)
        FromCountry=request.values.get('FromCountry', None)
        NumSegments=request.values.get('NumSegments', None)
        Body=request.values.get('Body',None)

        logging.debug('\nFrom: %s\nTo: %s\nFrom Country: %s\nBody: %s', 
                From, To, FromCountry,Body)

        try:
            data = json.loads(b64decode(Body))
            logging.debug("%s", data)

        except Exception as error:
            logging.exception(error)
            return '', 500
        else:
            if not 'IMSI' in data:
                logging.error('no IMSI in data - %s', data)
                return '', 400
        
            try:
                ledger = Ledger()

                data = { "MSISDN":From, "IMSI":data['IMSI'], "update_platform":platform}
                if not ledger.exist(data):
                    ledger.create(data=data)
                    logging.info("New record inserted")
                else:
                    logging.info("Record exist")
            except Exception as error:
                logging.exception(error)
                return '', 500
            else:
                # TODO: https://www.twilio.com/docs/sms/tutorials/how-to-receive-and-reply-python
                return jsonify({"MSISDN":From}), 200

        """
        data = None
        ''' transform from base64 and get your string '''
        ''' should do some action with the SMS that just came in '''
        try:
            IMSI = Body.split('IMSI: ')[1]
            # TODO register and get the hell outta here
            data = acquire_ledger_data(IMSI=IMSI, number=From)
        except Exception as error:
            return '', 500

        try:
            create_clients(data)
        except Exception as error:
            return '', 500
            
        """
    else:
        return 'unknown platform requested', 400

    return '', 200


def create_clients(data:dict) -> None:
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
    global route_path
    # route_path = Router.get_route_path()

    logging.basicConfig(level='DEBUG')

    debug = True
    app.run(debug=debug)
