"""Gateway Clients Reliability Tests Checker."""

import datetime
import time
import logging
from src.controllers import check_reliability_tests

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def main():
    """Main function to run the reliability tests checker."""
    check_interval = datetime.timedelta(minutes=15)
    logger.info(
        "Starting reliability tests checker with a check interval of %s secs",
        check_interval.total_seconds(),
    )
    while True:
        try:
            logger.info(
                "Starting reliability tests check at %s", datetime.datetime.now()
            )
            check_reliability_tests()
            logger.info(
                "Next reliability test check at %s",
                check_interval + datetime.datetime.now(),
            )
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
