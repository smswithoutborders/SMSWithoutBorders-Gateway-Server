"""Reliability Tests Controllers"""

import logging
import datetime

from werkzeug.exceptions import NotFound

from src.db import connect
from src.models import ReliabilityTests
from src import gateway_clients

database = connect()

logger = logging.getLogger(__name__)


def get_all(filters=None, page=None, per_page=None) -> list:
    """
    Get all reliability tests according to the filters, pagination.

    Args:
        filters (dict, optional): A dictionary containing filtering criteria.
        page (int, optional): Page number for pagination.
        per_page (int, optional): Number of records per page for pagination.

    Returns:
        list: A list of dictionaries containing reliability test data.
    """

    results = []

    with database.atomic():
        query = ReliabilityTests.select().dicts()

        if filters:
            conditions = []

            for key, value in filters.items():
                if value is not None:
                    conditions.append(getattr(ReliabilityTests, key) == value)

            if conditions:
                query = query.where(*conditions).dicts()

        if page is not None and per_page is not None:
            query = query.paginate(page, per_page)

        for test in query:
            for field, value in test.items():
                if isinstance(value, datetime.datetime):
                    test[field] = int(value.timestamp())

            results.append(test)

    return results


def get_tests_for_client(msisdn, filters=None, page=None, per_page=None) -> list:
    """
    Get reliability tests associated with a specific gateway client.

    Args:
        msisdn (str): The MSISDN of the gateway client.
        filters (dict, optional): A dictionary containing filtering criteria.
        page (int, optional): Page number for pagination.
        per_page (int, optional): Number of records per page for pagination.

    Returns:
        list: A list of dictionaries containing reliability test data for the client.
    """

    if not gateway_clients.get_by_msisdn(msisdn):
        raise NotFound(f"No gateway client found with MSISDN: {msisdn}")

    if filters and "msisdn" in filters:
        del filters["msisdn"]

    tests = get_all(filters, page, per_page)

    return tests


def update_timed_out_tests_status(check_interval=15):
    """
    Update the status of reliability tests that have timed out.

    This function checks the start time of each reliability test and
    compares it with the current time. It then updates the status of
    tests that have timed out to 'timedout' in bulk.

    Args:
        check_interval (int, optional): The duration in minutes after
            which a test is considered timed out.

    Note:
        This function relies on a ReliabilityTests table in the database
            with columns 'start_time' and 'status'. The 'status' column
            should represent the status of the test, with 'success'
            indicating successful completion and 'timedout' indicating
            that the test has timed out.

    """
    threshold_time = datetime.datetime.now() - datetime.timedelta(
        minutes=check_interval
    )

    with database.atomic():
        timed_out_tests = ReliabilityTests.update(status="timedout").where(
            (ReliabilityTests.status.not_in(["success", "timedout"]))
            & (ReliabilityTests.start_time <= threshold_time)
        )
        updated_count = timed_out_tests.execute()
        logger.info("Updated %d tests to 'timedout' status.", updated_count)
