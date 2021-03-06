import phonenumbers
from phonenumbers import geocoder, carrier
import helpers.MCCMNC as MCCMNC 

"""
List used by Android and google:
    https://android.googlesource.com/platform/packages/providers/TelephonyProvider/+/master/assets/latest_carrier_id/carrier_list.textpb
"""


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

def get_phonenumber_operator_id(MSISDN: str) -> str:
    MSISDN_country = get_phonenumber_country(MSISDN=MSISDN)
    operator_name = get_phonenumber_operator_name(MSISDN=MSISDN)

    operator_id = None
    for IMSI, values in MCCMNC.MCC_dict.items():
        if MSISDN_country == values[0]:
            for key, values in MCCMNC.MNC_dict.items():
                if IMSI == key[0] and operator_name == values[1]:
                    operator_id = values[0]
                    return str(operator_id)


    return operator_id

def get_phonenumber_operator_name(MSISDN: str) -> str:
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

        # return phonenumbers.carrier.name_for_number(_number, "en")
        return geocoder.description_for_number(_number, "en")

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
