#!/usr/bin/env python3

import os
import json
import pika
import logging

from src import rmq_broker

def init_rmq_connections(connection_name:str):
    """
    TODO: transform all env to args
    """
    try:
        logging.debug("RMQ host: %s", os.environ.get("RMQ_HOST"))

        host = os.environ.get("RMQ_HOST") \
                if os.environ.get("RMQ_HOST") else "127.0.0.1"

        tls_rmq = True \
                if os.environ.get("RMQ_SSL") and os.environ.get("RMQ_SSL") == "true" else False
        
        logging.debug("ENV TLS RMQ: %s", os.environ.get("RMQ_SSL"))
        logging.debug("TLS RMQ: %s", tls_rmq)
        logging.debug("RMQ DEFAULT USER: %s", os.environ.get("RABBITMQ_DEFAULT_USER"))

        rmq_connection: pika.BlockingConnection = rmq_broker.get_rmq_connection(
                user=os.environ.get("RABBITMQ_DEFAULT_USER"),
                password=os.environ.get("RABBITMQ_DEFAULT_PASS"),
                ssl_crt = os.environ.get("SSL_CERTIFICATE"), 
                ssl_key=os.environ.get("SSL_KEY"), 
                ssl_pem=os.environ.get("SSL_PEM"),
                tls_rmq=tls_rmq,
                connection_name=connection_name,
                ca_ssl_host=os.environ.get("HOST"),
                host=host)
    except Exception as error:
        raise error
    else:
        channel = rmq_broker.create_rmq_channel(connection=rmq_connection)
        rmq_broker.create_rmq_exchange(channel=channel)

        return rmq_connection, channel

    return None, None


def publish(channel: pika.channel.Channel, data: str) -> None:
    """
    """
    try:
        channel.basic_publish(
            exchange=rmq_broker.default_exchange_name,
            routing_key=rmq_broker.default_routing_key,
            body=data,
            properties=pika.BasicProperties(
                delivery_mode=2,  # make message persistent
            ),
        )
    except Exception as error:
        raise error

def not_active_connection(channel: pika.channel.Channel) -> bool:
    """
    TODO: 
        - Check if channel is closed
    """
    connection: pika.BlockingConnection = channel.connection
    return connection.is_closed

