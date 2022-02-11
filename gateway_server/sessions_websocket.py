#!/usr/bin/python3 

# WS server that sends messages at random intervals

import asyncio
import datetime
import random
import websockets
import uuid
import configparser
import os
import requests
import ssl
import pathlib


class c_websocket:
    state = 'run'
    def __init__(self, websocket):
        self.websocket = websocket
        # self.state = 'run'

    def get_socket(self):
        return self.websocket

connected = {}
async def serve_sessions(websocket, path):
    print("[+] New client:", websocket, path)
    # print(f'# Clients: {len(connected)}')
    if path.find('sync/sessions') > -1:
        path= path.split('/')
        s_path = path[1] + '/' + path[2]
        session_id = path[3]
        # print("[+] s_path:", s_path)
        # print("[+] session_id:", session_id)
        api_url = CONFIGS['API']['HOST']
        api_port = CONFIGS['API']['PORT']
        protocol = "http"
        if os.path.exists(CONFIGS['SSL']['CRT']) and os.path.exists(CONFIGS['SSL']['KEY']):
            protocol = "https" try:
            iterator = 0
            soc = c_websocket(websocket)
            if session_id in connected:
                print('>> stoping connection, client exist')
                return
            connected[session_id] = soc

            '''
            import socket
            h_name = socket.gethostname()
            IP_address = socket.gethostbyname(h_name)
            '''
            while iterator < 3 and connected[session_id].state == 'run':
                url_data = f"{CONFIGS['CLOUD_API']['URL']}:{CONFIGS['API']['PORT']}/sync/sessions/{session_id}"
                print(url_data)
                await connected[session_id].get_socket().send(url_data)
                await asyncio.sleep(15)
                iterator+=1

                prev_session=session_id
                if connected[session_id].state != 'pause':
                    session_id = _id=uuid.uuid4().hex
                    response = requests.get(f"{CONFIGS['CLOUD_API']['URL']}:{CONFIGS['CLOUD_API']['PORT']}/sync/sessions?prev_session_id={prev_session}&session_id={session_id}")
                    connected[session_id] = soc
                else:
                    await asyncio.sleep(60*2)
                    break
            del connected[session_id]
            print("[-] Socket ended..")
            session_id = _id=uuid.uuid4().hex
            response = requests.get(f"{CONFIGS['CLOUD_API']['URL']}:{CONFIGS['CLOUD_API']['PORT']}/sync/sessions?prev_session_id={prev_session}&session_id={session_id}")
        except Exception as error:
            print(error)
            print(websocket)

    elif path.find('/sync/ack') > -1:
        print(">> acknowledgment seen...")
        session_id = path.split('/')[3]
        connected[session_id].state = 'ack'
        await connected[session_id].get_socket().send("200- acked")
        del connected[session_id]

    elif path.find('/sync/pause') > -1:
        print(">> paused seen...")
        session_id = path.split('/')[3]
        connected[session_id].state = 'pause'
        await connected[session_id].get_socket().send("201- paused")

def build_url() -> str:
    """Create the start connection url for the socket.
    Checks if SSL required files are present, then connect to wss.
    """
    server_ip = __conf['socket']['url']
    server_port = __conf['socket']['port']

    ssl_crt_filepath = __conf['ssl']['crt']
    ssl_key_filepath = __conf['ssl']['key']
    ssl_pem_filepath = __conf['ssl']['pem']

    if(
            os.path.exists(ssl_crt_filepath) and 
            os.path.exists(ssl_key_path) and 
            os.path.exists(ssl_pem_filepath)):

        logging.debug("websocket going secured")

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=ssl_crt_filepath, 
                keyfile=ssl_key_filepath)
        return websockets.serve(serve_sessions, server_ip, server_port, ssl=ssl_context)

    else:
        return websockets.serve(serve_sessions, server_ip, server_port)

if __name__ == "__main__":
    global __conf
    __conf = configparser.ConfigParser()
    __conf.read(os.path.join(os.path.dirname(__file__), 'confs', 'conf.ini'))

    connection_url = build_url()

    asyncio.get_event_loop().run_until_complete(connection_url)
    asyncio.get_event_loop().run_forever()
