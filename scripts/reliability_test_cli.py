"""Gateway Clients Reliability Tests CLI"""

import os
import argparse
import requests
from peewee import OperationalError

from src.models.gateway_clients import GatewayClients
from src.models.reliability_tests import ReliabilityTests

DEKU_CLOUD_URL = os.environ.get("DEKU_CLOUD_URL")


def make_deku_api_call(msisdn):
    """Make API call to Deku Cloud.

    Args:
        msisdn (str): MSISDN to be passed in the API call.

    Returns:
        bool: True if API call is successful, False otherwise.
    """
    if not DEKU_CLOUD_URL:
        print("[!] Error: DEKU_CLOUD_URL environment variable not set.")
        return False

    payload = {"msisdn": msisdn}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(
            DEKU_CLOUD_URL, json=payload, headers=headers, timeout=10
        )
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: Failed to make API call to Deku Cloud: {e}")
        return False


def start_tests(msisdn=None, all_tests=False):
    """Start reliability tests for specified MSISDN or all MSISDNs.

    Args:
        msisdn (str, optional): MSISDN for which tests are to be started.
        all_tests (bool, optional): Flag to indicate if tests are to be started for all MSISDNs.
    """
    if all_tests:
        clients = GatewayClients.select()
    elif msisdn:
        clients = [GatewayClients.get_or_none(msisdn=msisdn)]
    else:
        print(
            "[!] Please provide an MSISDN or use --all option to start tests "
            "for all MSISDNs. Use --help for more information."
        )
        return

    for client in clients:
        if not client:
            print(f"[!] No client found with MSISDN: {msisdn}")
            return

        if make_deku_api_call(client.msisdn):
            existing_test = ReliabilityTests.get_or_none(msisdn=client.msisdn)
            if not existing_test or existing_test.status != "running":
                try:
                    test = ReliabilityTests.create(msisdn=client.msisdn)
                    print(f"[>>>] Started tests for MSISDN: {test.msisdn}")
                except OperationalError as e:
                    print(
                        f"[!] Error: Failed to start tests for MSISDN: {client.msisdn}. {e}"
                    )
            else:
                print(f"[!] Tests for MSISDN {client.msisdn} are already running.")
        else:
            print(f"[!] Failed to make API call for MSISDN: {client.msisdn}.")


def view_test_data(msisdn=None):
    """View test data for specified MSISDN or all test data in the database.

    Args:
        msisdn (str, optional): MSISDN for which test data is to be viewed.
    """
    if msisdn:
        test = ReliabilityTests.get_or_none(msisdn=msisdn)
        if test:
            print(f"[>>>] Test Data for MSISDN: {test.msisdn}, Status: {test.status}")
        else:
            print(f"[!] No test data found for MSISDN: {msisdn}")
    else:
        tests_query = ReliabilityTests.select()
        for test in tests_query:
            print(f"[>>>] Test Data for MSISDN: {test.msisdn}, Status: {test.status}")


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

    if args.action == "start":
        start_tests(args.msisdn, args.all)
    elif args.action == "view":
        view_test_data(args.msisdn)


if __name__ == "__main__":
    main()
