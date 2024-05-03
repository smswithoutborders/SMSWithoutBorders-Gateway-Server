"""Gateway Clients CLI"""

import argparse
import logging
import phonenumbers
from phonenumbers import carrier, geocoder
from playhouse.shortcuts import model_to_dict
from src.models import GatewayClients
from mccmnc import find_matches, update

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("[GC CLI]")


def get_plmn(country_code, operator, refresh=False):
    """
    Get PLMN (Public Land Mobile Network) information based on country code and operator.

    Args:
        country_code (int): The country code.
        operator (str): The operator name.
        refresh (bool, optional): Whether to force a refresh of PLMN data. Defaults to False.

    Returns:
        dict: PLMN information.
    """
    if refresh:
        update()

    network = operator.split()[0].lower()

    try:
        plmn = find_matches(user_cc=country_code, user_network=network)
    except FileNotFoundError:
        update()
        plmn = find_matches(user_cc=country_code, user_network=network)

    return list(plmn.keys())[0]


def get_operator_information(msisdn):
    """
    Get country and operator information from MSISDN
        (Mobile Station International Subscriber Directory Number).

    Args:
        msisdn (str): The MSISDN of the client.

    Returns:
        tuple: A tuple containing country, operator, and operator code.
            - country (str): The country name.
            - operator (str): The operator name.
            - operator_code (str): The PLMN (Public Land Mobile Network) code.
    """
    try:
        number = phonenumbers.parse(msisdn, None)
        country = geocoder.description_for_number(number, "en")
        country_code = number.country_code
        operator = carrier.name_for_number(number, "en")
        operator_code = get_plmn(country_code, operator)
        return country, operator, operator_code
    # pylint: disable=W0718
    except Exception:
        logger.error("Failed to parse MSISDN.", exc_info=True)
        return None, None


def create_client(msisdn, protocols):
    """
    Create a new gateway client.

    Args:
        msisdn (str): The MSISDN of the client.
        protocols (str): The protocol(s) of the client (comma separated).

    Returns:
        None
    """
    try:
        country, operator, operator_code = get_operator_information(msisdn)

        if country is None or operator is None or operator_code is None:
            logger.error(
                "Failed to retrieve complete operator information for the provided MSISDN."
            )
            if country is None:
                logger.error("Country information is missing.")
            if operator is None:
                logger.error("Operator information is missing.")
            if operator_code is None:
                logger.error("Operator code information is missing.")
            return

        # pylint: disable=W0212,E1101
        with GatewayClients._meta.database.atomic():
            client = GatewayClients.create(
                msisdn=msisdn,
                country=country,
                operator=operator,
                operator_code=operator_code,
                protocols=protocols,
            )

            logger.info("Client created successfully.")

            print("-" * 60)
            print(f"{'Client Details':=^60}")
            for key, value in model_to_dict(client).items():
                print(f"{key.upper()}: {value}")
    # pylint: disable=W0718
    except Exception:
        logger.error("Failed to create client.", exc_info=True)


def view_client(msisdn=None):
    """
    View gateway client(s).

    Args:
        msisdn (str, optional): The MSISDN of the client to view. If None,
            all clients will be displayed.

    Returns:
        None
    """
    # pylint: disable=W0212,E1101
    with GatewayClients._meta.database.atomic():
        try:
            query = GatewayClients.select().dicts()

            if msisdn:
                query = query.where(GatewayClients.msisdn == msisdn).dicts()

            if not query:
                logger.info("No clients found.")
                return

            print(f"{'Clients':=^60}")
            for test in query:
                print("-" * 60)
                for key, value in test.items():
                    print(f"{key.upper()}: {value}")

        # pylint: disable=W0718
        except Exception:
            logger.error("Failed to get client(s).", exc_info=True)


def update_client(msisdn, country=None, operator=None, protocols=None):
    """
    Update an existing gateway client.

    Args:
        msisdn (str): The MSISDN of the client to update.
        country (str, optional): The new country value for the client.
        operator (str, optional): The new operator value for the client.
        protocols (str, optional): The new protocol(s) value for the client (comma separated).

    Returns:
        None
    """
    # pylint: disable=W0212,E1101
    with GatewayClients._meta.database.atomic():
        try:
            client = GatewayClients.get_or_none(msisdn=msisdn)
            if client:
                if country:
                    client.country = country

                if operator:
                    client.operator = operator

                if protocols:
                    client.protocols = protocols

                client.save()
                logger.info("Client updated successfully.")
            else:
                logger.info("No client found with MSISDN: %s", msisdn)
        # pylint: disable=W0718
        except Exception:
            logger.error("Failed to update record.", exc_info=True)


def main():
    """
    Parse command line arguments and execute corresponding actions.
    """
    parser = argparse.ArgumentParser(description="Gateway Clients CLI")
    parser.add_argument(
        "action",
        choices=["create", "view", "update", "delete"],
        help="Action to perform",
    )
    parser.add_argument("--msisdn", help="MSISDN of the client")
    parser.add_argument("--country", help="Country of the client")
    parser.add_argument("--operator", help="Operator of the client")
    parser.add_argument(
        "--protocols", help="Protocol(s) of the client (comma separated)"
    )

    args = parser.parse_args()

    if not args.action:
        parser.error("Please specify an action to perform (create, view, update)")

    if args.action == "create":
        if not all([args.msisdn, args.protocols]):
            parser.error(
                "For 'create' action, all arguments are required: --msisdn, --protocols"
            )
    elif args.action == "update":
        if not args.msisdn:
            parser.error(f"For '{args.action}' action, --msisdn is required")

    if args.action == "create":
        create_client(args.msisdn, args.protocols)
    elif args.action == "view":
        view_client(args.msisdn)
    elif args.action == "update":
        update_client(
            args.msisdn,
            args.country,
            args.operator,
            args.protocols,
        )


if __name__ == "__main__":
    main()
