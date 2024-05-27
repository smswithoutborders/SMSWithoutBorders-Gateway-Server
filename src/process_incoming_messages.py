"""Module to process incoming data."""

import logging
import base64
import json
import os
from datetime import datetime

from src import aes, reliability_tests, gateway_clients

logger = logging.getLogger(__name__)

SHARED_KEY_FILE = os.environ.get("SHARED_KEY")

# pylint: disable=E1101,W0212,W0718


class UserNotFoundError(Exception):
    """Exception raised when user is not found."""


class SharedKeyError(Exception):
    """Exception raised when shared key is missing."""


class InvalidDataError(Exception):
    """Exception raised when data is invalid."""


class DecryptError(Exception):
    """Exception raised when decryption fails"""


def parse_json_data(data):
    """
    Parse JSON data.

    Args:
        data (str): JSON data to parse.

    Returns:
        dict: Parsed JSON data.

    Raises:
        InvalidDataError: If JSON parsing fails.
    """
    try:
        return json.loads(data, strict=False)
    except Exception as err:
        logging.error("Failed to parse JSON data: %s", err)
        raise InvalidDataError(
            "Invalid JSON data format. Please check your input."
        ) from err


def validate_data(data):
    """
    Validate incoming data.

    Args:
        data (dict): Incoming data to validate.

    Raises:
        InvalidDataError: If required fields are missing.
    """
    if not data.get("MSISDN") and not data.get("address"):
        logger.error("Missing MSISDN or address")
        raise InvalidDataError("Missing MSISDN or address")
    if not data.get("text"):
        logger.error("Missing Text")
        raise InvalidDataError("Missing Text")


def decrypt_text(encrypted_text, shared_key, encoding_type=None):
    """
    Decrypt the provided encrypted text using AES algorithm.

    Args:
        encrypted_text (str): Encrypted text to decrypt.
        shared_key (str): Shared key for decryption.
        encoding_type (str, optional): Type of encoding applied to the encrypted text
            before encryption (e.g., 'base64'). Defaults to None.

    Returns:
        str: Decrypted text.

    Raises:
        DecryptError: If decryption fails.
    """
    try:
        encrypted_bytes = base64.b64decode(encrypted_text)
        iv = encrypted_bytes[:16]
        ciphertext = encrypted_bytes[16:]

        if encoding_type == "base64":
            ciphertext = base64.b64decode(ciphertext)

        decrypted_text = aes.AESCipher.decrypt(
            data=ciphertext, iv=iv, shared_key=shared_key
        )
        return str(decrypted_text, "utf-8")
    except Exception as err:
        logger.error(
            "Failed to decrypt the text%s",
            " using " + encoding_type if encoding_type else "",
        )
        raise DecryptError("Failed to decrypt the text") from err


def process_data(data, be_pub_lib, users):
    """
    Process incoming data.

    Args:
        data (str): Incoming data in JSON format.
        be_pub_lib: Backend Publishing library.
        users: User database.

    Returns:
        str: Processed and encrypted data.

    Raises:
        Exception: If any error occurs during processing.
    """
    try:
        data = parse_json_data(data)
        validate_data(data)

        user_msisdn = data.get("MSISDN") or data.get("address")
        user_msisdn_hash = be_pub_lib.hasher(data=user_msisdn)
        user = users.find(msisdn_hash=user_msisdn_hash)

        if not user:
            logger.error("User not found: %s", user_msisdn_hash)
            raise UserNotFoundError("User not found")

        shared_key = user.shared_key

        if not shared_key:
            logging.error("no shared key for user, strange")
            raise SharedKeyError("Shared key error")

        decrypted_text = decrypt_text(data["text"], shared_key, "base64")

        platform_letter = decrypted_text[0]
        platform_name = be_pub_lib.get_platform_name_from_letter(
            platform_letter=platform_letter
        )["platform_name"]

        data = be_pub_lib.get_grant_from_platform_name(
            phone_number=user_msisdn, platform_name=platform_name
        )
        data["data"] = decrypted_text
        data["platform_name"] = platform_name

        shared_key = os.environ["PUBLISHER_ENCRYPTION_KEY"][:32]

        # Padding just in case shorter than required key size
        if len(shared_key) < 32:
            shared_key += "0" * (32 - len(shared_key))

        data = json.dumps(data).encode("utf-8")
        data = aes.AESCipher.encrypt(shared_key=shared_key, data=data)
        data = base64.b64encode(data)

        return str(data, "utf-8")

    except Exception as error:
        raise error


def process_test(data):
    """
    Process incoming test data.

    Args:
        data (str): Incoming data in JSON format.

    Returns:
        bool: True if successful, False otherwise.

    Raises:
        Exception: If any error occurs during processing.
    """
    try:
        data = parse_json_data(data)
        validate_data(data)

        with open(SHARED_KEY_FILE, "r", encoding="utf-8") as f:
            encryption_key = f.readline().strip()[:32]

        plaintext = decrypt_text(data["text"], encryption_key)
        decrypted_test_data = parse_json_data(plaintext)

        test_id = decrypted_test_data.get("test_id")
        test_msisdn = decrypted_test_data.get("msisdn")

        if not test_id or not test_msisdn:
            logger.error("Test data is incomplete.")
            return False

        reliability_tests.update_timed_out_tests_status()

        date_sent = int(data["date_sent"]) / 1000
        date = int(data["date"]) / 1000

        fields = {
            "status": "success",
            "sms_routed_time": datetime.now(),
            "sms_sent_time": datetime.fromtimestamp(date_sent),
            "sms_received_time": datetime.fromtimestamp(date),
        }
        criteria = {
            "sms_routed_time": "is_null",
            "msisdn": test_msisdn,
            "status": "running",
        }
        updated_tests = reliability_tests.update_test_for_client(
            test_id, fields, criteria
        )

        if updated_tests == 0:
            logger.error("No running test record found for MSISDN %s.", test_msisdn)
            return False

        reliability_score = reliability_tests.calculate_reliability_score_for_client(
            test_msisdn
        )
        gateway_clients.update_by_msisdn(
            test_msisdn, {"reliability": reliability_score}
        )

        return True

    except DecryptError:
        logger.info("Skipping test check ...")
        return False
    except Exception as error:
        logger.error("An error occurred during test data processing: %s", error)
        return False
