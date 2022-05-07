#!/usr/bin/env python3 

import asyncio
import socket
import websockets
import uuid
import configparser
import os
import requests
import ssl
import logging


__api_version = 2

__conf = configparser.ConfigParser(interpolation=None)
__conf.read(os.path.join(os.path.dirname(__file__), 'confs', 'conf.ini'))

def user_management_api_authenticate_user(password: str, user_id: str) -> tuple:
    """Authenticates users at the user management api level.

    Args:
        password (str): Password for user when they created the account.

        user_id (str): unique identifier for the intended user. Assigned
        when account was created.

    Returns:
        state (bool), user_management_auth_payload (requests.Response)
    """

    user_management_api_auth_url = __conf['user_management_api']['verification_url'] % \
            (user_id)
    logging.debug("user_management_api_auth_url: %s", user_management_api_auth_url)

    request = requests.Session()
    response = request.post(
            user_management_api_auth_url,
            json={"password":password})

    response.raise_for_status()

    return True, request


def user_management_api_request_platforms(request: requests.Session, user_id: str) -> dict:
    """Request for the user's stored platforms.

    Args:
        headers (dict): Should be extracted from an authentication response.

        user_id (str): unique identifier for the intended user. Assigned
        when account was created.

    Returns:
        json_response (dict)
    """
 
    user_management_api_platform_request_url = __conf['user_management_api']['platforms_url'] % \
            (user_id)

    response = request.get(
            user_management_api_platform_request_url, 
            json={})

    response.raise_for_status()

    return response.json()


def get_interface_ip(family: socket.AddressFamily) -> str:
    # This method was extracted from pallet/flask (flask)
    # https://github.com/pallets/werkzeug/blob/a44c1d76689ae6608d1783ac628127150826c809/src/werkzeug/serving.py#L925
    """Get the IP address of an external interface. Used when binding to
    0.0.0.0 or ::1 to show a more useful URL.
    :meta private:
    """
    # arbitrary private address
    host = "fd31:f903:5ab5:1::1" if family == socket.AF_INET6 else "10.253.155.219"

    with socket.socket(family, socket.SOCK_DGRAM) as s:
        try:
            s.connect((host, 58162))
        except OSError:
            return "::1" if family == socket.AF_INET6 else "127.0.0.1"

        return s.getsockname()[0]  # type: ignore

class client_websocket:
    """Manages states of each client connecting.
    """

    state = '__RUN__'
    def __init__(self, websocket):
        self.websocket = websocket
        # self.state = 'run'

    def get_socket(self):
        return self.websocket

__persistent_connections = {}

def update_session(session_id: str, api_host: str, api_port: int, user_id: str, api_protocol: str="http") -> str:
    """Updates sessions for client.
    Makes the request for new session and update it on the user's database.

    Args:
        session_id (str): valid in-use session id which will be used to track and update to new session id.

    Return: str
    """
    try:
        # new_session_id = uuid.uuid4().hex

        # example: http://localhost:5000/v2/sync/users/0000/sessions/11111
        api_session_update_url = "%s://%s:%d/v%d/sync/users/%s/sessions/%s" % (
                api_protocol,
                api_host, 
                api_port, 
                __api_version, 
                user_id, 
                session_id)
        response = requests.put(api_session_update_url)

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
            session_change_limit = int(__conf['websocket_sync']['session_change_limit'])
            session_sleep_timeout = int(__conf['websocket_sync']['session_sleep_timeout'])
            session_paused_timeout = int(__conf['websocket_sync']['session_paused_timeout'])

            api_host = __api_conf['api']['host']
            api_state = __api_conf['api']['state']
            """
            - If api_host == 0.0.0.0:
                Then it should be converted to local ip address.
            - Assumption is it would be bad practice to use 0.0.0.0 on a production server.
            """
            api_host = get_interface_ip(socket.AF_INET) if(
                    api_host == "0.0.0.0" and api_state != "production") else api_host

            api_port = int(__api_conf['api']['port'])

            api_ssl_crt_filepath = __api_conf['api_ssl']['crt']
            api_ssl_key_filepath = __api_conf['api_ssl']['key']

            api_protocol = "http"
            if (
                    os.path.exists(api_ssl_crt_filepath) and 
                    os.path.exists(api_ssl_key_filepath)):
                api_protocol = "https"

            while(
                    session_change_counter < session_change_limit and 
                    __persistent_connections[client_persistent_key].state == '__RUN__'):

                # example: http://localhost:5000/v2/sync/users/0000/sessions/11111/handshake
                api_handshake_url = "%s://%s:%d/v%d/sync/users/%s/sessions/%s/handshake" % (
                        api_protocol,
                        api_host, 
                        api_port, 
                        __api_version, user_id, 
                        session_id)

                logging.debug("Gateway server handshake url %s", api_host)

                await __persistent_connections[client_persistent_key].get_socket().send(api_handshake_url)

                await asyncio.sleep(session_sleep_timeout)

                session_change_counter += 1

                prev_session=session_id

                if __persistent_connections[client_persistent_key].state != '__PAUSE__':
                    try:
                        session_id = update_session(
                                session_id=session_id, 
                                api_host=api_host, 
                                api_port=api_port, 
                                user_id=user_id,
                                api_protocol=api_protocol)

                    except Exception as error:
                        raise error

                    else:
                        new_client_persistent_key = session_id + user_id
                        __persistent_connections[new_client_persistent_key] = __persistent_connections[client_persistent_key]

                        del __persistent_connections[client_persistent_key]

                        client_persistent_key = new_client_persistent_key
                        logging.debug("updated session key to: %s", new_client_persistent_key)

                else:
                    logging.info("Paused for %s seconds", session_paused_timeout)
                    await asyncio.sleep(session_paused_timeout)
                    """
                    session expires here, exiting loop
                    """
                    break

            try:
                await __persistent_connections[client_persistent_key].get_socket().close()
                del __persistent_connections[client_persistent_key]

                logging.debug("removed client %s", client_persistent_key)
            except Exception as error:
                logging.exception(error)


            try:
                session_id = update_session(
                        session_id=session_id, 
                        api_host=api_host, 
                        api_port=api_port, 
                        user_id=user_id, 
                        api_protocol=api_protocol)
            
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


    elif path.find('v%s/sync/pause' % (__api_version)) > -1:
        split_path = path.split('/')

        if len(split_path) < 5:
            logging.error("Invalid pause request")
            return

        user_id = split_path[-2]
        session_id = split_path[-1]

        client_persistent_key = session_id + user_id
        logging.info("session paused requested: %s", client_persistent_key)

        __persistent_connections[client_persistent_key].state = '__PAUSE__'
        try:
            await __persistent_connections[client_persistent_key].get_socket().send("201- pause")
        except Exception as error:
            logging.exception(error)


    elif path.find('v%s/sync/ack' % (__api_version)) > -1:
        split_path = path.split('/')

        if len(split_path) < 5:
            logging.error("Invalid ack request")
            return

        user_id = split_path[-2]
        session_id = split_path[-1]

        client_persistent_key = session_id + user_id
        logging.info("session ack requested: %s", client_persistent_key)

        __persistent_connections[client_persistent_key].state = '__ACK__'
        try:
            await __persistent_connections[client_persistent_key].get_socket().send("200- ack")
            await __persistent_connections[client_persistent_key].get_socket().close()
            del __persistent_connections[client_persistent_key]
        except Exception as error:
            logging.exception(error)

def construct_websocket_object():
    """Create the start connection url for the socket.
    Checks if SSL required files are present, then connect to wss.
    """

    logging.debug("constructing connection websocket object")
    server_ip = __conf['websocket']['host']
    server_port = __conf['websocket']['port']

    ssl_crt_filepath = __conf['websocket_ssl']['crt']
    ssl_key_filepath = __conf['websocket_ssl']['key']
    ssl_pem_filepath = __conf['websocket_ssl']['pem']

    if(
            os.path.exists(ssl_crt_filepath) and 
            os.path.exists(ssl_key_filepath) and 
            os.path.exists(ssl_pem_filepath)):

        logging.debug("websocket going secured with WSS")
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=ssl_crt_filepath, 
                keyfile=ssl_key_filepath)

        server_ip = __conf['websocket_ssl']['host']
        logging.debug("server %s -> port %s", server_ip, server_port)

        return websockets.serve(serve_sessions, server_ip, server_port, ssl=ssl_context)

    else:
        logging.debug("websocket going WS")
        logging.debug("server %s -> port %s", server_ip, server_port)
        return websockets.serve(serve_sessions, server_ip, server_port)


if __name__ == "__main__":
    global __api_conf, __is_ssl

    logging.basicConfig(level='DEBUG')

    __api_conf = configparser.ConfigParser()
    __api_conf.read(os.path.join(os.path.dirname(__file__), '../confs', 'conf.ini'))

    connection_function = construct_websocket_object()
    logging.debug("%s", connection_function)

    asyncio.get_event_loop().run_until_complete(connection_function)
    asyncio.get_event_loop().run_forever()
