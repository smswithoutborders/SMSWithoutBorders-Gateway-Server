"""Gateway Clients Reliability Tests Checker."""

import datetime
import time
import logging
from src.controllers import check_reliability_tests
from src.db import connect

database = connect()

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("[RELIABILITY TEST CHECKER]")
logger.setLevel(logging.INFO)


def main():
    """Main function to run the reliability tests checker."""
    check_interval = datetime.timedelta(minutes=15)
    logger.info(
        "Starting reliability tests checker with a check interval of %s minutes",
        check_interval.total_seconds() / 60,
    )
    while True:
        try:
            logger.info(
                "Starting reliability tests check at %s",
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            )
            check_reliability_tests()
            logger.info(
                "Next reliability test check scheduled at %s",
                (datetime.datetime.now() + check_interval).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
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
