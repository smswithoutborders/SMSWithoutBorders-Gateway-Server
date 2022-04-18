import phonenumbers
from phonenumbers import geocoder, carrier


class InvalidPhoneNUmber(Exception):
    def __init__(self, message="INVALID PHONE NUMBER"):
        self.message = message
        super().__init__(self.message)


class InvalidCountryCode(Exception):
    def __init__(self, message="INVALID COUNTRY CODE"):
        self.message = message
        super().__init__(self.message)


class MissingCountryCode(Exception):
    def __init__(self, message="MISSING COUNTRY CODE"):
        self.message = message
        super().__init__(self.message)


def get_phonenumber_country(MSISDN: str) -> str:
    """Returns the country of MSISDN.
    Args:
        MSISDN (str):
            The phone number for which country is required.

    Returns:
        (str): country name

    Exceptions:
        INVALID_PHONE_NUMBER_EXCEPTION
        INVALID_COUNTRY_CODE_EXCEPTION
        MISSING_COUNTRY_CODE_EXCEPTION
    """

    try:
        _number = phonenumbers.parse(MSISDN, "en")

        if not phonenumbers.is_valid_number(_number):
            raise InvalidPhoneNUmber()

        return phonenumbers.carrier.name_for_number(_number, "en")

    except phonenumbers.NumberParseException as error:
        if error.error_type == phonenumbers.NumberParseException.INVALID_COUNTRY_CODE:
            if MSISDN[0] == "+" or MSISDN[0] == "0":
                raise InvalidCountryCode()
            else:
                raise MissingCountryCode()
        else:
            raise error

    except Exception as error:
        raise error
