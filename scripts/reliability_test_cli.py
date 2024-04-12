"""Gateway Clients Reliability Tests CLI"""

import os
import argparse

import requests
from peewee import OperationalError
from src.models.gateway_clients import GatewayClients
from src.models.reliability_tests import ReliabilityTests


# DEKU_CLOUD_URL = os.environ["DEKU_CLOUD_URL"]


def make_deku_api_call(msisdn):
    """Make API call to Deku Cloud.

    Args:
        msisdn (str): MSISDN to be passed in the API call.

    Returns:
        bool: True if API call is successful, False otherwise.
    """
    payload = {"msisdn": msisdn}
    headers = {"Content-Type": "application/json"}

    try:
        # response = requests.post(
        #     DEKU_CLOUD_URL, json=payload, headers=headers, timeout=10
        # )

        # if response.status_code == 200:
        #     return True

        # print(f"Error: API call failed with status code {response.status_code}")
        # return False
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False


def start_tests(msisdn=None, all_tests=False):
    """Start reliability tests for a particular MSISDN or all MSISDNs.

    Args:
        msisdn (str, optional): MSISDN for which tests are to be started.
        all_tests (bool, optional): Flag to indicate if tests are to be started for all MSISDNs.
    """
    if all_tests:
        clients = GatewayClients.select()
        for client in clients:
            if make_deku_api_call(client.msisdn):
                try:
                    test = ReliabilityTests.create(msisdn=client.msisdn)
                    print(f"Started tests for MSISDN: {test.msisdn}")
                except OperationalError as e:
                    print(f"Error starting tests for MSISDN: {client.msisdn}. {e}")
    elif msisdn:
        if make_deku_api_call(msisdn):
            try:
                test = ReliabilityTests.create(msisdn=msisdn)
                print(f"Started tests for MSISDN: {test.msisdn}")
            except OperationalError as e:
                print(f"Error starting tests for MSISDN: {msisdn}. {e}")
    else:
        print(
            "Please provide an MSISDN or use --all option to start tests "
            "for all MSISDNs. Use --help for more information."
        )


def view_test_data(msisdn=None):
    """View test data for a particular MSISDN or all test data in the database.

    Args:
        msisdn (str, optional): MSISDN for which test data is to be viewed.
    """
    tests = ReliabilityTests.select()
    if msisdn:
        tests = tests.where(ReliabilityTests.msisdn == msisdn)

    for test in tests:
        print(f"Test Data for MSISDN: {test.msisdn}, Status: {test.status}")


def main():
    """Main function to parse command line arguments."""
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
