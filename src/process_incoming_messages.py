import logging
import base64
import json
import os

from src import aes

logger = logging.getLogger(__name__)


class UserNotFoundError(Exception):
    """Exception raised when user is not found."""

    pass


class SharedKeyError(Exception):
    """Exception raised when shared key is missing."""

    pass


class InvalidDataError(Exception):
    """Exception raised when data is invalid."""

    pass


class DecryptError(Exception):
    """Exception raised when decryption fails"""

    pass


def process_data(data, BEPubLib, users):
    """Process incoming data"""
    try:
        data = json.loads(data, strict=False)
    except Exception as error:
        logging.error("Failed to parse JSON data: %s", error)
        raise InvalidDataError("Invalid JSON data format. Please check your input.")

    if not "MSISDN" in data:
        logger.error("Missing MSISDN")
        raise InvalidDataError("Missing MSISDN")

    if not "text" in data:
        logger.error("Missing Text")
        raise InvalidDataError("Missing Text")

    text = data["text"]
    user_msisdn = data["MSISDN"]

    try:
        user_msisdn_hash = BEPubLib.hasher(data=user_msisdn)
        user = users.find(msisdn_hash=user_msisdn_hash)

        if not user:
            logger.error("User not found: %s", user_msisdn_hash)
            raise UserNotFoundError("User not found")

        shared_key = user.shared_key

        if not shared_key:
            logging.error("no shared key for user, strange")
            raise SharedKeyError("Shared key error")

        try:
            text = base64.b64decode(text)
        except Exception as error:
            logger.error("Invalid Text Format")
            raise InvalidDataError("Invalid Text Format")

        iv = text[:16]
        text = text[16:]
        text = base64.b64decode(text)

        try:
            decrypted_text = aes.AESCipher.decrypt(
                data=text, iv=iv, shared_key=shared_key
            )
        except Exception:
            logger.error("Failed to Decrypt")
            raise DecryptError("Failed to Decrypt")

        decrypted_text = str(decrypted_text, "utf-8")
        logger.debug("decrypted successfully...")

        platform_letter = decrypted_text[0]
        logger.debug("platform letter: %s", platform_letter)

        platform_name = BEPubLib.get_platform_name_from_letter(
            platform_letter=platform_letter
        )
        logger.debug("platform name: %s", platform_name)

        platform_name = platform_name["platform_name"]

        data = BEPubLib.get_grant_from_platform_name(
            phone_number=user_msisdn, platform_name=platform_name
        )
        data["data"] = decrypted_text
        data["platform_name"] = platform_name
        """
        data = {"username":"dummy_data", 
                "token":{"key":"dummy", "data":"dummy"},
                "uniqueId":"1234567",
                "phoneNumber_bash":user_msisdn_hash }
        """

        shared_key = os.environ["PUBLISHER_ENCRYPTION_KEY"]
        shared_key = shared_key[:32]

        # Padding just in case shorter than required key size
        if len(shared_key) < 32:
            shared_key += "0" * (32 - len(shared_key))

        data = json.dumps(data).encode("utf-8")
        data = aes.AESCipher.encrypt(shared_key=shared_key, data=data)
        data = base64.b64encode(data)

        data = str(data, "utf-8")

        return data

    except Exception as error:
        raise error
