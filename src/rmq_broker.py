#!/usr/bin/env python3

import os
import pika
import ssl
import logging

default_routing_key = "default-smswithoutborders-routing-key" \
        if not os.environ.get("RMQ_ROUTING_KEY") \
        else os.environ.get("RMQ_ROUTING_KEY")

default_exchange_name = "default-smswithoutborders-exchange" \
        if not os.environ.get("RMQ_EXCHANGE") \
        else os.environ.get("RMQ_EXCHANGE")

default_connection_name = "default-smswithoutborders-publisher" \
        if not os.environ.get("RMQ_CONNECTION_NAME") \
        else os.environ.get("RMQ_CONNECTION_NAME")

default_queue_name = "default-smswithoutborders-queue" \
        if not os.environ.get("RMQ_QUEUE_NAME") \
        else os.environ.get("RMQ_QUEUE_NAME")


def create_queue(channel: pika.channel.Channel) -> None:
    """
    """
    channel.queue_declare(default_queue_name, durable=True)
    channel.queue_bind(
            queue=default_queue_name,
            exchange=default_exchange_name,
            routing_key=default_routing_key)

    logging.debug("queue created successfully")

def create_rmq_channel(connection: pika.BlockingConnection) -> pika.channel.Channel:
    """
    """
    channel = connection.channel()
    logging.debug("channel creates successfully")

    create_queue(channel=channel)
    return channel

def create_rmq_exchange(
        channel: pika.channel.Channel,
        exchange_name: str=default_exchange_name,
        exchange_type: str="topic") -> None: 
    """
    """
    channel.exchange_declare(
        exchange=default_exchange_name,
        exchange_type=exchange_type,
        durable=True)

def get_rmq_connection(
        user: str=None,
        password: str=None,
        ssl_crt: str=None, 
        ssl_key: str=None, 
        ssl_pem: str=None, 
        tls_rmq: bool=False,
        connection_name: str=default_connection_name,
        heartbeat: int = 30,
        blocked_connection_timeout: int=300,
        host: str='127.0.0.1',
        ca_ssl_host: str ='localhost',
        ssl_port: str="5671", 
        port: str="5672") -> pika.BlockingConnection:
    """
    - If using docker-compose network, unless certificate signed with
    service name it will fail to verify certificates.

    - If connecting to external host set: tls_rmq = True - would allow
    for using SSL.
    """
    client_properties = {'connection_name' : connection_name}

    credentials=pika.PlainCredentials(user, password)

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

        ssl_options = pika.SSLOptions(ssl_context, ca_ssl_host)
        conn_params = pika.ConnectionParameters(
                host=host,
                port=ssl_port, 
                ssl_options=ssl_options,
                heartbeat=heartbeat,
                credentials=credentials,
                blocked_connection_timeout=blocked_connection_timeout,
                client_properties=client_properties)
    else:
        conn_params = pika.ConnectionParameters( 
                host=host, 
                port=port,
                heartbeat=heartbeat,
                blocked_connection_timeout=blocked_connection_timeout,
                credentials=credentials,
                client_properties=client_properties)
    
    connection = pika.BlockingConnection(conn_params)

    return connection
