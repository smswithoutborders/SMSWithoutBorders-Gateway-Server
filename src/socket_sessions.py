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


__api_version = 2
logging.basicConfig(level='DEBUG')


class SocketSessions:
    """
    """
    class ClientWebsocket:
        """Manages states of each client connecting.
        """
        state = '__RUN__'
        def __init__(self, websocket):
            self.websocket = websocket
            # self.state = 'run'

        def get_socket(self):
            return self.websocket

    def __init__(self, host: str, port: str):
        """
        """
        self.host = host
        self.port = port


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

        logging.debug("server %s -> port %s", self.host, self.port)

        """
        read for prod: 
            https://websockets.readthedocs.io/en/stable/reference/server.html

            # TODO: origins should match host
        """
        async with websockets.serve(
                ws_handler = self.active_sessions, 
                host = self.host, 
                port = self.port,
                origins = [self.host]):

            await asyncio.Future()

    def __get_sessions_url__(self):
        """
        """
        api_handshake_url = "%s://%s:%d/v%d/sync/users/%s/sessions/%s/handshake" % (
                api_protocol,
                api_host, 
                api_port, 
                __api_version, user_id, 
                session_id)

        mobile_url = "%s://%s:%d/v%d/sync/users/%s/sessions/%s/handshake" % (
                api_protocol_mobile,
                api_host, 
                api_port, 
                __api_version, user_id, 
                session_id)
        
        return api_handshake_url, mobile_url
    
    async def __active_session__(self):
        """
        """
        session_change_counte = 0
        while( session_change_counter < self.refresh_limit):
            # example: http://localhost:5000/v2/sync/users/0000/sessions/11111/handshake

            api_handshake_url, mobile_url = self.__get_sessions_url__()

            synchronization_request = {
                    "qr_url": api_handshake_url,
                    "mobile_url": mobile_url
                    }

            await __persistent_connections[client_persistent_key].get_socket().send(
                    json.dumps(synchronization_request))

            await asyncio.sleep(self.time_to_refresh)

            session_change_counter += 1

            prev_session =  session_id

            client_state = __persistent_connections[client_persistent_key].state

            if client_state == '__PAUSE__':
                await asyncio.sleep(self.session_paused_timeout)

            if client_state == "__ACK__":
                logging.debug("connection has been acked, closing")
                break
    
    async def __process_new_client_connection__(self, 
            client_socket_connection: websockets.WebSocketServerProtocol, 
            user_id: str, session_id: str):
        """
        """
        try:

            client_persistent_key = session_id + user_id

            if client_persistent_key in __persistent_connections:
                raise Exception("connection already exist")

            client_socket = self.ClientWebsocket(client_socket_connection)
            __persistent_connections[client_persistent_key] = client_socket

            try:
                await self.__active_session__()
            except Exception as error:
                logging.exception(error)

            try:
                await __persistent_connections[client_persistent_key].get_socket().close()
            except Exception as error:
                logging.exception(error)

            del __persistent_connections[client_persistent_key]
            logging.debug("removed client %s", client_persistent_key)

        except websockets.exceptions.ConnectionClosedError as error:
            raise error

        except Exception as error:
            raise error


    async def __process_pause_connection__(self, user_id: str, session_id: str):
        """
        """
        client_persistent_key = session_id + user_id
        __persistent_connections[client_persistent_key].state = '__PAUSE__'

        try:
            await __persistent_connections[client_persistent_key].get_socket().send("201- pause")
        except Exception as error:
            raise error


    @classmethod
    async def pause_connection(cls, user_id: str, session_id: str):
        """
        """
        try:
            await cls.__process_ack_connection__(user_id = user_id, session_id =session_id)
        except Exception as error:
            logging.exception(error)


    async def __process_ack_connection__(cls, user_id: str, session_id: str):
        """
        """
        client_persistent_key = session_id + user_id

        __persistent_connections[client_persistent_key].state = '__ACK__'
        try:
            await __persistent_connections[client_persistent_key].get_socket().send("200- ack")
            await __persistent_connections[client_persistent_key].get_socket().close()
            del __persistent_connections[client_persistent_key]
        except Exception as error:
            raise error

    @classmethod
    async def ack_connection(cls, user_id: str, session_id: str):
        """
        """
        try:
            await cls.__process_ack_connection__(user_id=user_id, session_id=session_id)
        except Exception as error:
            logging.exception(error)


    def __verify_url_path__(self, path):
        """
        """
        split_path = path.split('/')

        if len(split_path) < 5:
            raise Exception("Invalid init path request")
        
        user_id = split_path[-2]
        session_id = split_path[-1]

        return user_id, session_id


    async def active_sessions(self, client_socket_connection: websockets.WebSocketServerProtocol, path: str) -> None:
        """Websocket connection required for synchronizing users.

        Once a client is connected, this begins streaming a series of urls after set durations to the client.
        The URLs are session urls which when connected to begin a handshake process for the requesting user
        """

        # http://localhost/v2/sync/init/1s1s/sss
        if path.find('/v2/sync/init') > -1:
            try:
                user_id, session_id = self.__verify_url_path__(path=path)
            except Exception as error:
                logging.exception(error)
            else:

                try:
                    await self.__process_new_client_connection__(user_id = user_id, session_id=session_id)
                except Exception as error:
                    logging.exception(error)
                    client_socket_connection.close(reason='')


def main(host: str, port: str) -> None:
    """
    """
    global __persistent_connections
    __persistent_connections = {}

    try:
        socket = SocketSessions(host=host, port=port)
    except Exception as error:
        logging.exception(error)
    else:
        asyncio.run(socket.construct_websocket_object())


if __name__ == "__main__":
    try:
        host = ip_grap.get_private_ip()
        port = os.environ["PORT"]

    except Exception as error:
        logging.exception(error)
    else:
        main(host=host, port=port)
