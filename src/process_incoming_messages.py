"""Module to process incoming data."""

import logging
import base64
import json
import os
from datetime import datetime

from src import aes
from src.models.reliability_tests import ReliabilityTests

logger = logging.getLogger(__name__)

SHARED_KEY_FILE = os.environ.get("SHARED_KEY")


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


def decrypt_text(text, shared_key):
    """
    Decrypt the provided text.

    Args:
        text (str): Encrypted text to decrypt.
        shared_key (str): Shared key for decryption.

    Returns:
        str: Decrypted text.

    Raises:
        DecryptError: If decryption fails.
    """
    try:
        text = base64.b64decode(text)
        iv = text[:16]
        text = text[16:]
        decrypted_text = aes.AESCipher.decrypt(data=text, iv=iv, shared_key=shared_key)
        return str(decrypted_text, "utf-8")
    except Exception as err:
        logger.error("Failed to Decrypt")
        raise DecryptError("Failed to Decrypt") from err


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

        decrypted_text = decrypt_text(data["text"], shared_key)

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

        if not SHARED_KEY_FILE:
            logger.error("SHARED_KEY_FILE environment variable not set.")
            return False

        with open(SHARED_KEY_FILE, "r", encoding="utf-8") as f:
            encryption_key = f.readline().strip()[:32]

        if not encryption_key:
            logger.error("Encryption key is empty or invalid.")
            return False

        plaintext = decrypt_text(data["text"], encryption_key)
        decrypted_test_data = parse_json_data(plaintext)

        test_id = decrypted_test_data.get("test_id")
        test_msisdn = decrypted_test_data.get("msisdn")

        if not test_id or not test_msisdn:
            logger.error("Test data is incomplete.")
            return False

        test = ReliabilityTests.get_or_none(
            ReliabilityTests.sms_routed_time.is_null(),
            id=test_id,
            msisdn=test_msisdn,
            status="running",
        )

        if not test:
            logger.error("No running test record found for MSISDN %s.", test_msisdn)
            return False

        date_sent = int(data["date_sent"]) / 1000
        date = int(data["date"]) / 1000

        test.status = "success"
        test.sms_routed_time = datetime.now()
        test.sms_sent_time = datetime.fromtimestamp(date_sent)
        test.sms_received_time = datetime.fromtimestamp(date)
        test.save()

        return True

    except DecryptError:
        logger.info("Skipping test check ...")
        return False
    except Exception as error:
        logger.error("An error occurred during test data processing: %s", error)
        raise error
