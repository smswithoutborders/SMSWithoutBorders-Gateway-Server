"""Controllers module."""

import datetime
import logging

from playhouse.shortcuts import model_to_dict
from peewee import OperationalError, fn

from src.db import connect
from src.models import GatewayClients, ReliabilityTests

database = connect()

logger = logging.getLogger(__name__)


def query_gateway_clients(filters, page, per_page):
    """
    Query gateway clients based on filters, pagination, and return associated test data.

    Args:
        filters (dict): A dictionary containing filtering criteria.
        page (int): Page number for pagination.
        per_page (int): Number of records per page for pagination.

    Returns:
        list: A list of dictionaries containing client data along with associated test data.
    """
    query = GatewayClients.select().paginate(page, per_page)

    conditions = []
    for key, value in filters.items():
        if value is not None:
            if key in ("country", "operator", "protocol"):
                conditions.append(
                    fn.lower(getattr(GatewayClients, key)) == value.lower()
                )
            else:
                conditions.append(getattr(GatewayClients, key) == value)

    if conditions:
        query = query.where(*conditions)

    results = []
    for client in query:
        tests = ReliabilityTests.select().where(
            ReliabilityTests.msisdn == client.msisdn
        )
        #  pylint: disable=E1133
        test_data = [model_to_dict(test, False) for test in tests]
        client_data = model_to_dict(client)
        client_data["test_data"] = test_data
        results.append(client_data)

    return results


def check_reliability_tests(check_duration=None):
    """
    Check the status of reliability tests.

    This function checks the start time of each reliability test and
    compares it with the current time.

    Args:
        check_duration (Optional[datetime.timedelta]): The duration after
            which a test is considered timed out. Defaults to 15 minutes
            if not provided.

    Raises:
        OperationalError: If a database error occurs during the operation.

    Note:
        This function relies on a ReliabilityTests table in the database
            with columns 'start_time' and 'status'. The 'status' column
            should represent the status of the test, with 'success'
            indicating successful completion and 'timedout' indicating
            that the test has timed out.

    """
    check_duration = check_duration or datetime.timedelta(minutes=15)
    current_time = datetime.datetime.now()
    try:
        # pylint: disable=E1133,E1101,W0212
        tests = ReliabilityTests.select().where(
            ~(ReliabilityTests.status.in_(["success", "timedout"]))
        )

        for test in tests:
            if current_time - test.start_time >= check_duration:
                logger.debug(
                    "Test ID %d has timed out. Updating status to 'timeout'",
                    test.id,
                )
                test.status = "timedout"
                test.save()
                logger.info("Status updated for Test ID %d", test.id)
    except OperationalError:
        logger.error("Database error occurred", exc_info=True)
