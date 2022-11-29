#!/usr/bin/env python3 

import os
import socket

import asyncio
import websockets
import uuid
import ssl
import logging
import json

import ip_grap

logging.basicConfig(level='DEBUG')

class SyncSockets:
    """
    """
    __persistent_connections = {}

    class ClientWebsocket:
        """Manages states of each client connecting.
        """
        state = '__RUN__'
        def __init__(self, websocket):
            self.websocket = websocket
            # self.state = 'run'

        def get_socket(self):
            return self.websocket

    def __init__(self, host: str, port: str, 
            gateway_server_host: str, gateway_server_port: str, ssl_context = None):
        """
        """
        self.host = host
        self.port = port
        self.ssl_context = ssl_context

        self.gateway_server_port = gateway_server_port
        self.gateway_server_host = gateway_server_host

        self.refresh_limit = 3
        self.time_to_refresh = 10

        self.gateway_server_protocol = "http" if not ssl_context else "https"
        self.gateway_server_protocol_mobile = "app" if not ssl_context else "apps"

        self.__valid_sessions = {}

    async def construct_websocket_object(self):
        """
        read for prod: 
            https://websockets.readthedocs.io/en/stable/reference/server.html
        """
        logging.debug("[*] HOST %s", self.host)
        logging.debug("[*] PORT %s", self.port)
        async with websockets.serve(
                ws_handler = self.active_sessions, 
                host = self.host, 
                port = self.port,
                ssl= self.ssl_context):

            await asyncio.Future()
    
    def __get_sessions_url__(self, user_id: str):
        """
        TODO: use session_id for something important
                like verifying the integrity of the connection
        """
        session_id = uuid.uuid4().hex

        sessions_protocol = f"%s://{self.gateway_server_host}:{self.gateway_server_port}/" \
                f"v2/sync/users/{user_id}/sessions/{session_id}/"

        api_handshake_url = sessions_protocol % ( self.gateway_server_protocol)

        mobile_url = sessions_protocol % ( self.gateway_server_protocol_mobile)
        
        return api_handshake_url, mobile_url
    
    async def __active_session__(self, 
            client_socket_connection: websockets.WebSocketServerProtocol, 
            user_id: str):
        """
        """
        client_socket = self.ClientWebsocket(client_socket_connection)

        session_change_counter = 0

        while( session_change_counter < self.refresh_limit):
            self.__persistent_connections[user_id] = client_socket

            api_handshake_url, mobile_url = self.__get_sessions_url__(user_id=user_id)

            synchronization_request = {
                    "qr_url": api_handshake_url,
                    "mobile_url": mobile_url
                    }

            try:
                await self.__persistent_connections[user_id].get_socket().send(
                        json.dumps(synchronization_request))
            except Exception as error:
                raise error

            await asyncio.sleep(self.time_to_refresh)

            client_state = self.__persistent_connections[user_id].state

            if client_state == '__PAUSE__':
                await asyncio.sleep(self.session_paused_timeout)

            if client_state == "__ACK__":
                logging.debug("connection has been acked, closing")
                break

            session_change_counter += 1

    
    async def __process_new_client_connection__(self, 
            client_socket_connection: websockets.WebSocketServerProtocol, 
            user_id: str):
        """
        """
        try:
            await self.__active_session__(client_socket_connection = client_socket_connection,
                    user_id=user_id)

        except Exception as error:
            raise error

        else:
            try:
                await self.__persistent_connections[user_id].get_socket().close()
            except Exception as error:
                raise error


    async def __process_pause_connection__(self, user_id: str):
        """
        """
        self.__persistent_connections[user_id].state = '__PAUSE__'
        try:
            await self.__persistent_connections[user_id].get_socket().send("201- pause")
        except Exception as error:
            raise error


    @classmethod
    async def pause_connection(cls, user_id: str):
        """
        """
        try:
            await cls.__process_ack_connection__(user_id = user_id)
        except Exception as error:
            logging.exception(error)


    async def __process_ack_connection__(cls, user_id: str):
        """
        """
        self.__persistent_connections[user_id].state = '__ACK__'
        try:
            await self.__persistent_connections[user_id].get_socket().send("200- ack")
            await self.__persistent_connections[user_id].get_socket().close()
            del self.__persistent_connections[user_id]
        except Exception as error:
            raise error

    @classmethod
    async def ack_connection(cls, user_id: str):
        """
        """
        try:
            await cls.__process_ack_connection__(user_id=user_id)
        except Exception as error:
            logging.exception(error)


    def __verify_url_path__(self, path):
        """
        """
        split_path = path.split('/')

        if len(split_path) < 4:
            raise Exception("Invalid init path request")
        
        user_id = split_path[-1]

        return user_id


    async def active_sessions(self, 
            client_socket_connection: websockets.WebSocketServerProtocol, 
            path: str) -> None:
        """Websocket connection required for synchronizing users.

        Once a client is connected, this begins streaming a series of urls after set durations to the client.
        The URLs are session urls which when connected to begin a handshake process for the requesting user
        """

        # http://localhost/v2/sync/init/1s1s/sss
        if path.find('/v2/sync/init') > -1:
            try:
                user_id = self.__verify_url_path__(path=path)
            except Exception as error:
                logging.exception(error)
            else:
                if user_id in self.__persistent_connections and \
                        self.__persistent_connections[user_id].get_socket().open:
                    logging.error("User already exist...: %s", user_id)
                    return 

                try:
                    await self.__process_new_client_connection__(
                            client_socket_connection=client_socket_connection, 
                            user_id = user_id)

                except Exception as error:
                    logging.exception(error)
                    await client_socket_connection.close(reason='')


def get_host(host: str) -> str:
    """
    """
    if not host:
        host = "127.0.0.1"

    else:
        host = ip_grap.get_private_ip() if host == "0.0.0.0" else host

    return host

def main_tls(ssl_key_filepath: str, ssl_crt_filepath: str, ssl_pem_filepath: str):
    """
    """
    logging.info("WSS protocol!")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_cert_chain(certfile=ssl_crt_filepath,
            keyfile=ssl_key_filepath)
    ssl_context.load_verify_locations(ssl_pem_filepath)

    try:
        socket = SyncSockets(
                host=HOST, 
                port=PORT, 
                gateway_server_port=GATEWAY_SERVER_PORT, 
                gateway_server_host=GATEWAY_SERVER_HOST,
                ssl_context=ssl_context)

    except Exception as error:
        logging.exception(error)
    else:
        asyncio.run(socket.construct_websocket_object())


def main_no_tls() -> None:
    """
    """
    logging.info("WS protocol!")
    try:
        socket = SyncSockets(
                host=HOST, 
                port=PORT, 
                gateway_server_port=GATEWAY_SERVER_PORT, 
                gateway_server_host=GATEWAY_SERVER_HOST)

    except Exception as error:
        logging.exception(error)
    else:
        asyncio.run(socket.construct_websocket_object())

def main() -> None:
    """
    """
    global PORT, HOST, GATEWAY_SERVER_HOST, GATEWAY_SERVER_PORT

    PORT = os.environ.get("PORT")
    HOST = os.environ.get("HOST")
    # HOST = "127.0.0.1" if not HOST else HOST
    HOST = "127.0.0.1" if not HOST else "0.0.0.0"


    SSL_KEY_FILEPATH = os.environ.get("SSL_KEY")
    SSL_CRT_FILEPATH = os.environ.get("SSL_CRT")
    SSL_PEM_FILEPATH = os.environ.get("SSL_PEM")

    logging.debug("SSL_KEY_FILEPATH: %s", SSL_KEY_FILEPATH)
    logging.debug("SSL_CRT_FILEPATH: %s", SSL_CRT_FILEPATH)
    logging.debug("SSL_PEM_FILEPATH: %s", SSL_PEM_FILEPATH)

    GATEWAY_SERVER_HOST = os.environ["GATEWAY_SERVER_HOST"]
    if(SSL_KEY_FILEPATH and SSL_CRT_FILEPATH and SSL_PEM_FILEPATH):
        GATEWAY_SERVER_PORT = os.environ["GATEWAY_SERVER_SSL_PORT"]
        main_tls(ssl_key_filepath=SSL_KEY_FILEPATH, 
                ssl_crt_filepath=SSL_CRT_FILEPATH,
                ssl_pem_filepath=SSL_PEM_FILEPATH)
    else:
        GATEWAY_SERVER_PORT = os.environ["GATEWAY_SERVER_PORT"]
        main_no_tls()


if __name__ == "__main__":
    main()
