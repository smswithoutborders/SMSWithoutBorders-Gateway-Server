#!/usr/bin/env python3

import os
import configparser
import websocket
import logging
from gateway_server.security.rsa import SecurityRSA

__confs = configparser.ConfigParser(interpolation=None)
__confs.read(os.path.join(
    os.path.dirname(__file__), 'confs', 'conf.ini'))

public_key_filepath = __confs['security']['public_key_filepath']
private_key_filepath = __confs['security']['private_key_filepath']

public_key_filepath = os.path.join(
    os.path.dirname(__file__), public_key_filepath)

private_key_filepath = os.path.join(
    os.path.dirname(__file__), private_key_filepath)

websocket_url = __confs['websocket']['host']
websocket_port = __confs['websocket']['port']


# ws://localhost/v2/sync/init/1s1s/sss
websocket_ssl_url = __confs['websocket_ssl']['host']
websocket_ssl_crt_filepath = __confs['websocket_ssl']['crt']
websocket_ssl_key_filepath = __confs['websocket_ssl']['key']


def generate_keypair(private_key_filepath: str, public_key_filepath: str) -> tuple:
    """Generates the main keypair values for Instance of Gateway server.
    """
    # securityRSA = SecurityRSA()
    public_key, private_key = SecurityRSA.generate_keypair_write(
            private_key_filepath=private_key_filepath, 
            public_key_filepath=public_key_filepath)

    return public_key, private_key


def check_has_keypair(private_key_filepath: str, public_key_filepath: str) -> bool:
    """Checks if public keys are installed on the system.
    """
    if not os.path.isfile(public_key_filepath):
        logging.debug("public key not present at: %s", public_key_filepath)
        return False

    if not os.path.isfile(private_key_filepath):
        logging.debug("private key not present at: %s", private_key_filepath)
        return False
    
    return True


def websocket_message(message: str, user_id: str, session_id: str) -> None:
    """Messages the default gateway server websocket.

    Args:
        message (str):
            Should contain the state of the synchronization process. Either of the following:
                - __PAUSE__
                - __ACK__
    """

    ssl_context=None
    websocket_ssl_crt_filepath = __confs['websocket_ssl']['crt']
    websocket_ssl_key_filepath = __confs['websocket_ssl']['key']
    # websocket_ssl_pem_filepath = __confs['websocket_ssl']['pem']

    websocket_protocol = "ws"
    if (
            os.path.exists(websocket_ssl_crt_filepath) and 
            os.path.exists(websocket_ssl_key_filepath)):

        websocket_protocol = "wss"

    if message == '__PAUSE__':
        def socket_message_error(wsapp, error):
            logging.error(error)

        # ws://localhost:6996/v2/sync/pause/user_id/session_id
        websocket_url = "%s://%s:%s/v%s/sync/pause/%s/%s" % (
                websocket_protocol,
                __confs['websocket']['host'],
                __confs['websocket']['port'],
                __api_version_number,
                user_id,
                session_id)

        logging.debug("pausing url: %s", websocket_url)
        ws = websocket.WebSocketApp(websocket_url, on_error=socket_message_error)
        ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})

    elif message == '__ACK__':
        def socket_message_error(wsapp, error):
            logging.error(error)

        # ws://localhost:6996/v2/sync/pause/user_id/session_id
        websocket_url = "%s://%s:%s/v%s/sync/ack/%s/%s" % (
                websocket_protocol,
                __confs['websocket']['host'],
                __confs['websocket']['port'],
                __api_version_number,
                user_id,
                session_id)

        logging.debug("ack url: %s", websocket_url)
        ws = websocket.WebSocketApp(websocket_url, on_error=socket_message_error)
        if not ssl_context == None:
            ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
        else:
            ws.run_forever()

    else:
        logging.error("Unknown socket message %s", message)
