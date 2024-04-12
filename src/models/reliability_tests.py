"""Gateway Clients Reliability Tests Model."""

from datetime import datetime
from peewee import Model, CharField, DateTimeField, ForeignKeyField

from src.models.db_connector import connect
from src.models.gateway_clients import GatewayClients
from src.utils import create_table

database = connect()
TABLE_NAME = "reliability_tests"


class ReliabilityTests(Model):
    """Model representing Gateway Clients Reliability Tests."""

    start_time = DateTimeField(default=datetime.now)
    sms_sent_time = DateTimeField(null=True)
    sms_received_time = DateTimeField(null=True)
    sms_routed_time = DateTimeField(null=True)
    status = CharField(default="running")
    msisdn = ForeignKeyField(GatewayClients, backref="msisdn", column_name="msisdn")

    # pylint: disable=R0903
    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = TABLE_NAME


create_table(ReliabilityTests, TABLE_NAME, database)
