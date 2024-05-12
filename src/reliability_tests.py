"""Reliability Tests Controllers"""

import logging
import datetime

from playhouse.shortcuts import model_to_dict

from src.db import connect
from src.models import ReliabilityTests
from src import gateway_clients

database = connect()

logger = logging.getLogger(__name__)


class PreCommitError(Exception):
    """Custom exception for pre-commit function failures."""


def get_all(filters: dict = None, page: int = None, per_page: int = None) -> list:
    """Get all reliability tests according to the filters, pagination.

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


def get_tests_for_client(
    msisdn: str,
    filters: dict = None,
    page: int = None,
    per_page: int = None,
) -> list:
    """Get reliability tests associated with a specific gateway client.

    Args:
        msisdn (str): The MSISDN of the gateway client.
        filters (dict, optional): A dictionary containing filtering criteria.
        page (int, optional): Page number for pagination.
        per_page (int, optional): Number of records per page for pagination.

    Returns:
        list or None: A list of dictionaries containing reliability test data
            for the client. None if no gateway client is found with the provided
            MSISDN.
    """

    if not gateway_clients.get_by_msisdn(msisdn):
        return None

    if filters is None:
        filters = {}

    filters["msisdn"] = msisdn

    tests = get_all(filters, page, per_page)

    return tests


def update_timed_out_tests_status(check_interval: int = 15) -> None:
    """Update the status of reliability tests that have timed out.

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


# pylint: disable=W0718,E1101,W0212
def create_test_for_client(
    msisdn: str, status: str, pre_commit_funcs: list = None
) -> dict:
    """Create a reliability test for a specific gateway client.

    Args:
        msisdn (str): The MSISDN of the client.
        status (str): The test status.
        pre_commit_funcs (list, optional): A list of tuples where each tuple
            contains a function and its arguments to execute before committing
            the transaction.

    Returns:
        dict: A dictionary with test data. Returns None if the same test
              already exists.

    Example:
        # Define pre-commit functions
        def example_pre_commit_func(test_data, arg1, arg2):
            logger.info("Using test data: %s", test_data)

            # Example of rolling back transaction based on a condition
            if some_condition:
                return None

            # Otherwise, proceed with the transaction
            logger.info("Pre-commit executed with args: %s, %s", arg1, arg2)

        def another_pre_commit_func(prev_return, arg3):
            logger.info("Using previous return value: %s", prev_return)

            # Example of additional operations before committing
            logger.info("Another pre-commit executed with arg: %s", arg3)

        # Define arguments for pre-commit functions
        arg1 = "value1"
        arg2 = "value2"
        arg3 = "value3"

        # Define pre-commit functions with arguments
        pre_commit_funcs = [
            (example_pre_commit_func, (arg1, arg2)),
            (another_pre_commit_func, (arg3,))
        ]

        # Call create_test_for_client with pre-commit functions
        create_test_for_client("1234567890", "running", pre_commit_funcs)
    """
    existing_test = get_tests_for_client(msisdn, filters={"status": status})

    if existing_test:
        logger.error(
            "Test not created for MSISDN: %s with status: %s, as it already exists",
            msisdn,
            status,
        )
        return None

    with ReliabilityTests._meta.database.atomic() as transaction:
        try:
            new_test = ReliabilityTests.create(msisdn=msisdn, status=status)
            new_test_data = model_to_dict(new_test, False)
            if pre_commit_funcs:
                prev_return = new_test_data
                for func, args in pre_commit_funcs:
                    args = (prev_return,) + args
                    prev_return = func(*args)

                    if prev_return is None:
                        raise PreCommitError(
                            f"Pre-commit function '{func.__name__}' failed"
                        )

            logger.info("Test created for MSISDN: %s with status: %s", msisdn, status)
            return new_test_data

        except PreCommitError as e:
            transaction.rollback()
            logger.error(str(e))
            return None

        except Exception:
            transaction.rollback()
            logger.error(
                "Failed to create test for MSISDN: %s with status: %s",
                msisdn,
                status,
                exc_info=True,
            )
            return None
