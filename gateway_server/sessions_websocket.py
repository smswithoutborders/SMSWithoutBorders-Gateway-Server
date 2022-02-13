#!/usr/bin/env python3 

import asyncio
# import datetime
# import random
import websockets
import uuid
import configparser
import os
import requests
import ssl
# import pathlib
import logging


__api_version = 2

class client_websocket:
    state = '__RUN__'
    def __init__(self, websocket):
        self.websocket = websocket
        # self.state = 'run'

    def get_socket(self):
        return self.websocket

__persistent_connections = {}

def update_session(session_id: str, gateway_server_url: str, gateway_server_port: int, user_id: str) -> str:
    """Updates sessions for client.
    Makes the request for new session and update it on the user's database.

    Args:
        session_id (str): valid in-use session id which will be used to track and update to new session id.

    Return: str
    """
    try:
        # new_session_id = uuid.uuid4().hex

        # example: http://localhost:5000/v2/sync/users/0000/sessions/11111
        gateway_server_session_update_url = "%s:%d/v%d/sync/users/%s/sessions/%s" % \
                (gateway_server_url, gateway_server_port, __api_version, user_id, session_id)
        response = requests.put(gateway_server_session_update_url)

        if response.status_code == 200:
            new_session_id = response.text

            return new_session_id
        else:
            raise Exception("update status failed: HTTP status code %d", response.status_code)

    except Exception as error:
        raise error

async def serve_sessions(websocket, path):
    """Websocket connection required for synchronizing users.

    Once a client is connected, this begins streaming a series of urls after set durations to the client.
    The URLs are session urls which when connected to begin a handshake process for the requesting user
    """

    # http://localhost/v2/sync/init/1s1s/sss

    if path.find('/v%s/sync/init' % (__api_version )) > -1:
        split_path = path.split('/')

        if len(split_path) < 5:
            logging.error("Invalid init request")
            return

        user_id = split_path[-2]
        session_id = split_path[-1]
        logging.info("new client connection: %s %s", user_id, session_id)

        try:
            client_persistent_key = session_id + user_id
            if client_persistent_key in __persistent_connections:
                logging.warning("client already connected with session %s", client_persistent_key)
                await websocket.close(reason='already connected')

            client_socket = client_websocket(websocket)
            __persistent_connections[client_persistent_key] = client_socket

            session_change_counter = 0
            session_change_limit = int(__conf['sync']['session_change_limit'])
            session_sleep_timeout = int(__conf['sync']['session_sleep_timeout'])
            session_paused_timeout = int(__conf['sync']['session_paused_timeout'])

            gateway_server_url = __conf['server']['url']
            gateway_server_port = int(__conf['server']['port'])

            while(
                    session_change_counter < session_change_limit and 
                    __persistent_connections[client_persistent_key].state == '__RUN__'):

                # example: http://localhost:5000/v2/sync/users/0000/sessions/11111/handshake
                gateway_server_handshake_url = "%s:%d/v%d/sync/users/%s/sessions/%s/handshake" % \
                        (gateway_server_url, gateway_server_port, __api_version, user_id, session_id)

                logging.debug("Gateway server handshake url %s", gateway_server_url)

                await __persistent_connections[client_persistent_key].get_socket().send(gateway_server_handshake_url)

                await asyncio.sleep(session_sleep_timeout)

                session_change_counter += 1

                prev_session=session_id

                if __persistent_connections[client_persistent_key].state != '__PAUSE__':
                    try:
                        session_id = update_session(session_id=session_id, 
                                gateway_server_url=gateway_server_url, gateway_server_port=gateway_server_port, 
                                user_id=user_id)

                    except Exception as error:
                        raise error

                    else:
                        new_client_persistent_key = session_id + user_id
                        __persistent_connections[new_client_persistent_key] = __persistent_connections[client_persistent_key]

                        del __persistent_connections[client_persistent_key]

                        client_persistent_key = new_client_persistent_key
                        logging.debug("updated session key to: %s", new_client_persistent_key)

                else:
                    await asyncio.sleep(session_paused_timeout)
                    """
                    session expires here, exiting loop
                    """
                    break

            await __persistent_connections[client_persistent_key].get_socket().close()
            del __persistent_connections[client_persistent_key]

            logging.debug("removed client %s", client_persistent_key)

            try:
                session_id = update_session(session_id=session_id, 
                        gateway_server_url=gateway_server_url, gateway_server_port=gateway_server_port, 
                        user_id=user_id)
            
            except Exception as error:
                logging.exception(error)

            else:
                logging.debug("removed client session %s", client_persistent_key)
                logging.info("%d clients remain connected", len(__persistent_connections))

        except websockets.exceptions.ConnectionClosedError as error:
            logging.warning("socket connection closed: %s", client_socket)

        except Exception as error:
            logging.exception(error)
            raise error

    """
    elif path.find('v%s/sync/ack' % (__api_version)) > -1:
        logging.debug("Acknowledging session")

        split_path = path.split('/')

        if len(split_path) < 5:
            logging.error("Invalid init request")
            return

        user_id = split_path[-2]
        session_id = split_path[-1]

        session_id = path.split('/')[3]
        connected[session_id].state = 'ack'

        await connected[session_id].get_socket().send("200- acked")
        del connected[session_id]


    elif path.find('/sync/pause') > -1:
        print(">> paused seen...")
        session_id = path.split('/')[3]
        connected[session_id].state = 'pause'
        await connected[session_id].get_socket().send("201- paused")
    """

def construct_websocket_object():
    """Create the start connection url for the socket.
    Checks if SSL required files are present, then connect to wss.
    """

    logging.debug("constructing connection websocket object")
    server_ip = __conf['websocket']['url']
    server_port = __conf['websocket']['port']
    logging.debug("server %s -> port %s", server_ip, server_port)

    ssl_crt_filepath = __conf['ssl']['crt']
    ssl_key_filepath = __conf['ssl']['key']
    ssl_pem_filepath = __conf['ssl']['pem']

    if(
            os.path.exists(ssl_crt_filepath) and 
            os.path.exists(ssl_key_path) and 
            os.path.exists(ssl_pem_filepath)):

        logging.debug("websocket going secured with WSS")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=ssl_crt_filepath, 
                keyfile=ssl_key_filepath)

        return websockets.serve(serve_sessions, server_ip, server_port, ssl=ssl_context)

    else:
        logging.debug("websocket going WS")
        return websockets.serve(serve_sessions, server_ip, server_port)


if __name__ == "__main__":
    global __conf, __is_ssl

    logging.basicConfig(level='DEBUG')
    __conf = configparser.ConfigParser()
    __conf.read(os.path.join(os.path.dirname(__file__), 'confs', 'conf.ini'))

    connection_function = construct_websocket_object()
    logging.debug("%s", connection_function)

    asyncio.get_event_loop().run_until_complete(connection_function)
    asyncio.get_event_loop().run_forever()