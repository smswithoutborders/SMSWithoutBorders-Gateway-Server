"""Gateway Clients Controllers"""

import logging
import datetime

from peewee import fn, DoesNotExist

from src.db import connect
from src.models import GatewayClients

database = connect()

logger = logging.getLogger(__name__)


def get_all(filters=None, page=None, per_page=None) -> list:
    """Get all gateway clients according to the filters, pagination.

    Args:
        filters (dict, optional): A dictionary containing filtering criteria.
        page (int, optional): Page number for pagination.
        per_page (int, optional): Number of records per page for pagination.

    Returns:
        list: A list of dictionaries containing client data.
    """

    results = []

    with database.atomic():
        query = GatewayClients.select().dicts()

        if filters:
            conditions = []

            for key, value in filters.items():
                if value is not None:
                    if key == "country":
                        conditions.append(
                            fn.lower(getattr(GatewayClients, key)) == value.lower()
                        )
                    elif key in ("protocols", "operator"):
                        conditions.append(
                            fn.lower(getattr(GatewayClients, key)).contains(
                                value.lower()
                            )
                        )
                    elif key == "last_published_date":
                        conditions.append(
                            getattr(GatewayClients, key).truncate("day") == value
                        )
                    else:
                        conditions.append(getattr(GatewayClients, key) == value)

            if conditions:
                query = query.where(*conditions).dicts()

        if page is not None and per_page is not None:
            query = query.paginate(page, per_page)

        for client in query:
            for field, value in client.items():
                if isinstance(value, datetime.datetime):
                    client[field] = int(value.timestamp())

            client["protocols"] = client["protocols"].split(",")
            results.append(client)

    return results


def get_by_msisdn(msisdn: str) -> dict:
    """Retrieve a gateway client by its MSISDN.

    Args:
        msisdn (str): The MSISDN of the gateway client to retrieve.

    Returns:
        dict: A dictionary containing client data if a matching client is found,
            or None if no client with the provided MSISDN exists.
    """
    try:
        client = (
            GatewayClients.select().where(GatewayClients.msisdn == msisdn).dicts().get()
        )

        for field, value in client.items():
            if isinstance(value, datetime.datetime):
                client[field] = int(value.timestamp())

        client["protocols"] = client["protocols"].split(",")

        return client

    except DoesNotExist:
        return None
