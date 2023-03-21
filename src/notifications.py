#!/usr/bin/env python3

import pika
import logging
import base64
from src import rmq_broker

default_queue_name = "notifications-smswithoutborders-"
default_exchange_name = "notifications-smswithoutborders-exchange"

def create_users_notifications(rmq_host: str, 
        channel: pika.channel.Channel, 
        queue_name:str, user_name:str, password: str) -> None:
    """
    """
    try:
        rmq_broker.add_user(
                rmq_host=rmq_host,
                user_name=user_name,
                password=password)
    except Exception as error:
        raise error
    else:
        try:
            queue_name = default_queue_name + queue_name

            rmq_broker.create_queue(channel=channel,
                    queue_name=queue_name,
                    exchange_name=default_exchange_name,
                    routing_key=user_name)
        except Exception as error:
            raise error


def create_exchange(channel: pika.channel.Channel) -> None:
    """
    """
    exchange_type = "fanout"

    try:
        rmq_broker.create_rmq_exchange(
                channel=channel,
                exchange_name=default_exchange_name,
                exchange_type=exchange_type)
    except Exception as error:
        raise error
