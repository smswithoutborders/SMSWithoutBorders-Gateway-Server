#!/usr/bin/env python3

import pika
import ssl
import logging


def create_rmq_channel(connection: pika.BlockingConnection) -> pika.channel.Channel:
    """
    """
    channel = connection.channel()
    return channel

def create_rmq_exchange(
        channel: pika.channel.Channel,
        exchange_name: str="smswithoutborders-exchange",
        exchange_type: str="topic") -> None: 
    """
    """
    channel.exchange_declare(
        exchange=exchange_name,
        exchange_type=exchange_type,
        durable=True)

def get_rmq_connection(
        ssl_crt: str=None, 
        ssl_key: str=None, 
        ssl_pem: str=None, 
        tls_rmq: bool=False,
        connection_name: str="default-connection",
        heartbeat:int = 30,
        host: str='127.0.0.1',
        ssl_port: str="5671", 
        port: str="5672") -> pika.BlockingConnection:
    """
    - If using docker-compose network, unless certificate signed with
    service name it will fail to verify certificates.

    - If connecting to external host set: tls_rmq = True - would allow
    for using SSL.
    """
    client_properties = {'connection_name' : connection_name}
    conn_params = None

    if(ssl_crt and ssl_key and ssl_pem and tls_rmq):
        logging.debug("Connectin securely to %s", host)

        # ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

        ssl_context = ssl.create_default_context()
        ssl_context.load_cert_chain(certfile=ssl_crt,
                keyfile=ssl_key)
        ssl_context.load_verify_locations(ssl_pem)

        ssl_options = pika.SSLOptions(ssl_context)
        conn_params = pika.ConnectionParameters(
                host=host,
                port=ssl_port, 
                ssl_options=ssl_options,
                heartbeat=heartbeat,
                client_properties=client_properties)
    else:
        conn_params = pika.ConnectionParameters( 
                host=host, 
                port=port,
                client_properties=client_properties)
    connection = pika.BlockingConnection(conn_params)

    return connection

def publish(channel: pika.channel.Channel, text: str, token: str) -> None:
    """
    """
    data = json.dumps({
        "text":text,
        "token": token})

    try:
        channel.basic_publish(
            exchange=rabbitmq_exchange_name,
            routing_key=routing_key,
            body=data,
            properties=pika.BasicProperties(
                delivery_mode=2,  # make message persistent
            ),
        )
    except Exception as error:
        raise error
