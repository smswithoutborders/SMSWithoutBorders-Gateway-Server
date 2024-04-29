"""Reliability Tests CLI"""

import os
import logging
import datetime
import json
import base64
import argparse
import requests
from playhouse.shortcuts import model_to_dict

from src.models.gateway_clients import GatewayClients
from src.models.reliability_tests import ReliabilityTests
from src.reliability_test_checker import check_reliability_tests
from src import aes

DEKU_CLOUD_URL = os.environ.get("DEKU_CLOUD_URL")
DEKU_CLOUD_PROJECT_REF = os.environ.get("DEKU_CLOUD_PROJECT_REF")
DEKU_CLOUD_SERVICE_ID = os.environ.get("DEKU_CLOUD_SERVICE_ID")
DEKU_CLOUD_ACCOUNT_SID = os.environ.get("DEKU_CLOUD_ACCOUNT_SID")
DEKU_CLOUD_AUTH_TOKEN = os.environ.get("DEKU_CLOUD_AUTH_TOKEN")

SHARED_KEY_FILE = os.environ.get("SHARED_KEY")

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def make_deku_api_call(msisdn, payload):
    """Make API call to Deku Cloud.

    Args:
        msisdn (str): MSISDN to be passed in the API call.
        payload (str): Payload to be passed in the API call.

    Returns:
        bool: True if API call is successful, False otherwise.
    """
    if (
        not DEKU_CLOUD_URL
        or not DEKU_CLOUD_ACCOUNT_SID
        or not DEKU_CLOUD_AUTH_TOKEN
        or not DEKU_CLOUD_PROJECT_REF
        or not DEKU_CLOUD_SERVICE_ID
    ):
        logger.error("Deku Cloud environment variables are not set.")
        return False

    data = {"sid": "", "to": msisdn, "body": payload}
    auth = (DEKU_CLOUD_ACCOUNT_SID, DEKU_CLOUD_AUTH_TOKEN)
    url = f"{DEKU_CLOUD_URL}/v1/projects/{DEKU_CLOUD_PROJECT_REF}/services/{DEKU_CLOUD_SERVICE_ID}"

    try:
        response = requests.post(url, json=data, auth=auth, timeout=10)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException:
        logger.error("Failed to make API call to Deku Cloud.", exc_info=True)
        return False


def encrypt_payload(payload):
    """Encrypts test payload using AES encryption.

    Args:
        payload (bytes): Test Payload to be encrypted.

    Returns:
        str: The base64 encoded ciphertext.
    """
    if not SHARED_KEY_FILE:
        logger.error("SHARED_KEY_FILE environment variable not set.")
        return None

    with open(SHARED_KEY_FILE, "r", encoding="utf-8") as f:
        encryption_key = f.readline().strip()[:32]

    if not encryption_key:
        logger.error("Encryption key is empty or invalid.")
        return None

    try:
        ciphertext = aes.AESCipher.encrypt(shared_key=encryption_key, data=payload)
        return base64.b64encode(ciphertext).decode("utf-8")
    # pylint: disable=W0718
    except Exception:
        logger.error("Failed to encrypt payload.", exc_info=True)
        return None


def create_test_payload(test_data):
    """Creates a test payload and encrypts it.

    Args:
        test_data (dict): Test data containing 'id' and 'msisdn'.

    Returns:
        str: The base64 encoded ciphertext of the encrypted payload.
    """
    test_payload = {"test_id": test_data["id"], "msisdn": test_data["msisdn"]}
    test_ciphertext = encrypt_payload(payload=bytes(json.dumps(test_payload), "utf-8"))
    return test_ciphertext


def start_tests(msisdn=None, all_tests=False):
    """Start reliability tests for specified MSISDN or all MSISDNs.

    Args:
        msisdn (str, optional): MSISDN for which tests are to be started.
        all_tests (bool, optional): Flag to indicate if tests are to be started for all MSISDNs.
    """
    if not msisdn and not all_tests:
        logger.error(
            "Please provide an MSISDN or use --all option to start tests for all MSISDNs."
        )
        return

    try:
        if all_tests:
            clients = GatewayClients.select()
        else:
            clients = [GatewayClients.get_or_none(msisdn=msisdn)]

        for client in clients:
            if not client:
                logger.info("No client found with MSISDN: %s", msisdn)
                continue

            existing_test = ReliabilityTests.get_or_none(msisdn=client.msisdn)
            if not existing_test or existing_test.status != "running":
                # pylint: disable=W0212,E1101
                with ReliabilityTests._meta.database.atomic() as transaction:
                    test = ReliabilityTests.create(msisdn=client.msisdn)
                    test_dict = model_to_dict(test, recurse=False)
                    test_payload = create_test_payload(test_dict)

                    if not test_payload:
                        logger.error(
                            "Failed to create test payload for MSISDN: %s",
                            test_dict["msisdn"],
                        )
                        transaction.rollback()
                        continue

                    if not make_deku_api_call(test_dict["msisdn"], test_payload):
                        logger.error(
                            "Failed to start tests for MSISDN: %s", test_dict["msisdn"]
                        )
                        transaction.rollback()
                        continue

                    test.status = "running"
                    test.save()
                    logger.info("Started tests for MSISDN: %s", test_dict["msisdn"])

            else:
                logger.info("Tests for MSISDN %s are already running.", client.msisdn)
    # pylint: disable=W0718
    except Exception:
        logger.error("An unexpected error occurred:", exc_info=True)


def view_test_data(msisdn=None):
    """View test data for specified MSISDN or all test data in the database.

    Args:
        msisdn (str, optional): MSISDN for which test data is to be viewed.
    """
    try:
        if msisdn:
            test = ReliabilityTests.get_or_none(msisdn=msisdn)
            if test:
                print(f"{'Test Details':=^60}")
                for key, value in model_to_dict(test, recurse=False).items():
                    print(f"{key.upper()}: {value}")
            else:
                logger.error("No test data found for MSISDN: %s", msisdn)
        else:
            tests = ReliabilityTests.select().dicts()
            if tests:
                print(f"{'All Tests':=^60}")
                for test in tests:
                    print("-" * 60)
                    for key, value in test.items():
                        print(f"{key.upper()}: {value}")
            else:
                logger.info("No tests found.")
    # pylint: disable=W0718
    except Exception:
        logger.error("Failed to get test(s).", exc_info=True)


def main():
    """Parse command line arguments and execute corresponding action."""
    parser = argparse.ArgumentParser(
        description="Gateway Clients Reliability Tests CLI"
    )

    parser.add_argument(
        "action",
        choices=["start", "view"],
        help="Action to perform: start or view tests",
    )
    parser.add_argument(
        "--msisdn", help="MSISDN for which tests are to be started or viewed"
    )
    parser.add_argument(
        "--all", action="store_true", help="Start tests for all MSISDNs"
    )

    args = parser.parse_args()

    check_duration = datetime.timedelta(minutes=15)
    check_reliability_tests(check_duration)

    if args.action == "start":
        start_tests(args.msisdn, args.all)
    elif args.action == "view":
        view_test_data(args.msisdn)


if __name__ == "__main__":
    main()
