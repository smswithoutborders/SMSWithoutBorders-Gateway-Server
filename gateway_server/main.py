#!/usr/bin/env python3

import os
import configparser
import websocket
import logging
import ssl
import base64

from gateway_server.security.rsa import SecurityRSA
from gateway_server.security.aes import AESCipher

__confs = configparser.ConfigParser(interpolation=None)
__confs.read(os.path.join(
    os.path.dirname(__file__), 'confs', 'conf.ini'))

public_key_filepath = __confs['security']['public_key_filepath']
private_key_filepath = __confs['security']['private_key_filepath']

public_key_filepath = os.path.join(
    os.path.dirname(__file__), public_key_filepath)

private_key_filepath = os.path.join(
    os.path.dirname(__file__), private_key_filepath)

__api_version_number = 2

websocket_url = __confs['websocket']['host']
websocket_port = __confs['websocket']['port']


# ws://localhost/v2/sync/init/1s1s/sss
websocket_ssl_url = __confs['websocket_ssl']['host']
websocket_ssl_crt_filepath = __confs['websocket_ssl']['crt']
websocket_ssl_key_filepath = __confs['websocket_ssl']['key']


def decrypt_message(iv: str, shared_key: str, message: str)->str:
    """
    """
    decrypted_data = AESCipher.decrypt(iv=iv, shared_key=shared_key, data=message)
    # logging.debug(decrypted_data)
    return decrypted_data

def process_for_decryption(message: str) -> str:
    """Format: {IV}{encrypted_content}.
    """
    iv = message[:16]
    encoded_encrypted_message = message[16:]

    encrypted_message = base64.b64decode(bytes(encoded_encrypted_message, 'utf-8'))

    return iv, encrypted_message

def process_message_for_publishing(message: str) -> tuple:
    """
    """
    try:
        decoded_message = str(base64.b64decode(bytes(message, 'utf-8')), 'utf-8')
    except base64.binascii.Error as error:
        raise error

    except Exception as error:
        raise error
    else:
        try:
            if len(decoded_message) < 16:
                logging.debug("Message of len %d cannot be for publisher", 
                        len(decoded_message))
                return False

            iv, encrypted_message = process_for_decryption(decoded_message)
        except Exception as error:
            raise error
        else:
            return iv, encrypted_message


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
    websocket_host = "localhost"
    if (
            os.path.exists(websocket_ssl_crt_filepath) and 
            os.path.exists(websocket_ssl_key_filepath)):

        websocket_protocol = "wss"
        websocket_host = websocket_ssl_url

    if message == '__PAUSE__':
        def socket_message_error(wsapp, error):
            logging.error(error)

        # ws://localhost:6996/v2/sync/pause/user_id/session_id
        websocket_url = "%s://%s:%s/v%s/sync/pause/%s/%s" % (
                websocket_protocol,
                websocket_host,
                websocket_port,
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
                websocket_host,
                websocket_port,
                __api_version_number,
                user_id,
                session_id)

        logging.debug("ack url: %s", websocket_url)
        ws = websocket.WebSocketApp(websocket_url, on_error=socket_message_error)
        ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})

    else:
        logging.error("Unknown socket message %s", message)
