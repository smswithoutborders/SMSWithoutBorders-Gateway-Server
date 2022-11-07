#!/usr/bin/env python3 

import os
import socket

import asyncio
import websockets
import uuid
import ssl
import logging
import json

from src import ip_grap


logging.basicConfig(level='DEBUG')

class SocketSessions:
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

    def __init__(self, host: str, port: str, gateway_server_port: str):
        """
        """
        self.host = host
        self.port = port

        self.gateway_server_port = gateway_server_port

        self.refresh_limit = 3
        self.time_to_refresh = 10

        self.gateway_server_protocol = "http"
        self.gateway_server_protocol_mobile = "app"

        self.__valid_sessions = {}

    async def construct_websocket_object(self):
        """Create the start connection url for the socket.
        Checks if SSL required files are present, then connect to wss.
        """
        """
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

            return websockets.serve(active_sessions, server_ip, server_port, ssl=ssl_context)
        """

        """
        read for prod: 
            https://websockets.readthedocs.io/en/stable/reference/server.html
        """
        async with websockets.serve(
                ws_handler = self.active_sessions, 
                host = self.host, 
                port = self.port,
                origins = [self.host]):

            await asyncio.Future()
    
    def __get_sessions_url__(self, user_id: str):
        """
        TODO: use session_id for something important
                like verifying the integrity of the connection
        """
        session_id = uuid.uuid4().hex

        sessions_protocol = f"%s://{self.host}:{self.gateway_server_port}/" \
                f"v2/sync/users/{user_id}/handshake/{session_id}/"

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

    host = ip_grap.get_private_ip() if host == "0.0.0.0" else host

    return host

def main() -> None:
    """
    """
    PORT = os.environ.get("PORT")
    SOCK_PORT = os.environ.get("SOCK_PORT") 
    SOCK_HOST = os.environ.get("SOCK_HOST") 

    host = get_host(SOCK_HOST)
    try:
        socket = SocketSessions(host=host, 
                port=SOCK_PORT, gateway_server_port=PORT)

    except Exception as error:
        logging.exception(error)
    else:
        asyncio.run(socket.construct_websocket_object())


if __name__ == "__main__":
    main()
