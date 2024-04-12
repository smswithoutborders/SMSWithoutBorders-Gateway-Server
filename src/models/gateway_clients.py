"""Gateway Clients Model."""

from datetime import datetime
from peewee import Model, CharField, DateTimeField, BooleanField

from src.models.db_connector import connect
from src.utils import create_table

database = connect()
TABLE_NAME = "gateway_clients"


class GatewayClients(Model):
    """Model representing Gateway Clients."""

    msisdn = CharField(primary_key=True)
    country = CharField()
    operator = CharField()
    protocol = CharField()
    published = BooleanField()
    last_published_date = DateTimeField(default=datetime.now)

    # pylint: disable=R0903
    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = TABLE_NAME


create_table(GatewayClients, TABLE_NAME, database)
