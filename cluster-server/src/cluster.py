#!/usr/bin/env python3


import pika
import json
class Cluster:

    """
    def __init__(self, auth_id, rmq_server_url):
        self.auth_id=auth_id
        self.rmq_server_url=rmq_server_url
    """

    @classmethod
    def request_sms(cls, auth_id, data, rmq_server_url, rmq_outgoing_exchange_name, rmq_outgoing_exchange_type, rmq_outgoing_queue_name):
        ''' is this wasted and just computational heavy? '''
        connection = pika.BlockingConnection(pika.ConnectionParameters(rmq_server_url))
        channel = connection.channel()

        ''' creates the exchange '''
        channel.exchange_declare( 
                exchange=rmq_outgoing_exchange_name, 
                exchange_type=rmq_outgoing_exchange_type, 
                durable=True)

        # queue_name = config_queue_name + _ + isp
        queue_name = auth_id + '_' + rmq_outgoing_queue_name + '_' + data['isp'].lower()
        routing_key = auth_id + '_' + rmq_outgoing_queue_name + '.' + data['isp'].lower()
        
        ''' creates the queue, due to not knowing the isp this compute is wasted'''
        # channel.queue_declare(queue_name, durable=True)

        text = data['text']
        number = data['number']
        data = json.dumps({"text":text, "number":number})

        try:
            channel.basic_publish(
                exchange=rmq_outgoing_exchange_name,
                routing_key=routing_key,
                body=data,
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                ))
            # print(" [x] Sent %r" % message)
            print(f"\n\tsent to {number}")
            # connection.close()
        except Exception as error:
            raise(error)

        return True

