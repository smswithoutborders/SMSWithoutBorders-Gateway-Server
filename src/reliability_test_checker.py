"""Gateway Clients Reliability Tests Checker."""

import datetime
import time
import logging
from peewee import OperationalError
from src.models.reliability_tests import ReliabilityTests

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def check_reliability_tests(check_duration):
    """
    Check the status of reliability tests.

    This function checks the start time of each reliability test and
    compares it with the current time.
    If the time difference between start time and current time is more
    than check_duration and the status is not 'success' or 'timedout',
    it updates it to 'timedout'.
    """
    current_time = datetime.datetime.now()
    logger.info("Starting reliability tests check at %s", current_time)
    try:
        tests = ReliabilityTests.select().where(
            ~(ReliabilityTests.status.in_(["success", "timedout"]))
        )

        #  pylint: disable=E1133
        for test in tests:
            if current_time - test.start_time >= check_duration:
                logger.debug(
                    "Test ID %d has timed out. Updating status to 'timeout'", test.id
                )
                test.status = "timeout"
                test.save()
                logger.info("Status updated for Test ID %d", test.id)
    except OperationalError:
        logger.error("Database error occurred", exc_info=True)


def main():
    """Main function to run the reliability tests checker."""
    check_interval = datetime.timedelta(minutes=15)
    logger.info(
        "Starting reliability tests checker with a check interval of %s",
        check_interval.total_seconds(),
    )
    while True:
        try:
            check_reliability_tests(check_interval)
            logger.info("Next reliability test check in %s", check_interval)
            time.sleep(check_interval.total_seconds())
        except KeyboardInterrupt:
            logger.info("Received KeyboardInterrupt. Exiting...")
            break
        #  pylint: disable=W0718
        except Exception as e:
            logger.error("An unexpected error occurred: %s", e)
            time.sleep(10)


if __name__ == "__main__":
    main()
