"""Module to process incoming data."""

import logging
import base64
import json
import os

from src import aes

logger = logging.getLogger(__name__)


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
    if "MSISDN" not in data:
        logger.error("Missing MSISDN")
        raise InvalidDataError("Missing MSISDN")
    if "text" not in data:
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

        user_msisdn = data["MSISDN"]
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
