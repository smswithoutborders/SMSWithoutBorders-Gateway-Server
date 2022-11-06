
def sms_incoming(platform):
    """Receive inbound messages from Webhooks.
    Given that this URL is unique, only seeders can have the required key to route to them
        TODO:
            - Add platform security with secret keys at url levels
    """

    if not platform:
        return 'no platform provided', 500
    app.logger.debug('incoming sms for platform %s', platform)

    if platform == 'twilio':
        """Receives Form Data.
        """
        From = request.values.get('From', None)
        To = request.values.get('To', None)
        FromCountry = request.values.get('FromCountry', None)
        NumSegments = request.values.get('NumSegments', None)
        Body = request.values.get('Body', None)

        app.logger.debug("From: %s", From)
        app.logger.debug("Body: %s", Body)

    else:
        """Receives JSON Data.
        """
        try:
            data = json.loads(request.data)
        except Exception as error:
            logging.exception(error)
            return 'invalid data type, json expected', 500
        else:
            if not 'text' in data:
                return 'missing key - text', 400

            if not 'MSISDN' in data:
                return 'missing key - MSISDN', 400

            Body = data['text']
            MSISDN = data['MSISDN']

            app.logger.debug("MSISDN: %s", MSISDN)
            app.logger.debug("Body: %s", Body)

            try:
                decrypted_message = process_publisher(MSISDN=MSISDN, body=Body)
                app.logger.debug("Decrypted message: %s", decrypted_message)

                if decrypted_message is None:
                    return 'message cannot be published', 200
                else:
                    try:
                        publish(MSISDN=MSISDN, message=decrypted_message)
                    except Exception as error:
                        logging.exception(error)
                        raise error
                    else:
                        return 'message published successfully', 200
            except Exception as error:
                logging.exception(error)
                return '', 500
        return 'cannot process request', 400

def publish(MSISDN: str, message: bytes) -> None:
    """
    bytes required because that will keep using this endpoint intentional.
    """
    publisher_endpoint = __gateway_confs['publisher']['endpoint']
    publisher_port = int(__gateway_confs['publisher']['port'])
    publisher_url = "http://localhost:%d%s" % (publisher_port, publisher_endpoint)
    logging.debug("publishing to: %s", publisher_url)

    request = requests.Session()
    response = request.post(
            publisher_url,
            json={"MSISDN": MSISDN, "message": str(message, 'utf-8')})

    response.raise_for_status()


    return True, request

def process_publisher(MSISDN: str, body: str) -> str:
    """
    """

    # TODO: sanitize Body and MSISDN
    try:
        iv, encrypted_message = gateway_server.process_message_for_publishing(
                message=body)
    except base64.binascii.Error as error:
        app.logger.exception(error)
    except Exception as error:
        app.logger.exception(error)
        return '', 500
    else: 
        app.logger.debug("iv: %s", iv)
        app.logger.debug("encrypted_message: %s", encrypted_message)

        try:
            user_id = user_management_api_get_user_id(MSISDN=MSISDN)
        except requests.exceptions.HTTPError as error:
            app.logger.debug("Not an app user")
            raise error
        except Exception as error:
            raise error
        else:
            app.logger.debug("User ID: %s", user_id)

            user = Users(user_id)
            shared_key = user.get_shared_key()
            shared_key = shared_key[0][0]
            app.logger.debug("Shared key: %s", shared_key)

            try:
                decrypted_message = gateway_server.decrypt_message(
                        iv=iv, shared_key=shared_key, message=encrypted_message)
            except Exception as error:
                app.logger.exception(error)
                return '', 500
            else:
                return decrypted_message

    return False


def user_management_api_get_user_id(MSISDN: str) -> str:
    """
    """
    auth_id=__gateway_confs['dev_api']['auth_id']
    auth_key=__gateway_confs['dev_api']['auth_key']
    try:
        state, request = dev_backend_authenticate_user(
                auth_id=auth_id, auth_key=auth_key)
    except Exception as error:
        raise error
    else:
        app.logger.debug("%s %s", state, request)
        try:
            api_response = user_management_api_request_user_id(
                    request=request, MSISDN=MSISDN)
        except Exception as error:
            raise error
        else:
            """
            """
            user_id = api_response['user_id']
            return user_id


def user_management_api_request_user_id(
        request: requests.Session, MSISDN: str) -> dict:
    """Request for the user's tokens.

    Args:
        Request (requests.Session): authenticated sessions from dev BE.

        MSISDN (str): phone number of the user token is requested for.

    Returns:
        json_response (dict)
    """

    backend_publisher_endpoint = __gateway_confs['backend_publisher']['endpoint']
    backend_publisher_port = int(__gateway_confs['backend_publisher']['port'])
    backend_publisher_api_decrypted_tokens_request_url = "http://localhost:%d%s" % (
            backend_publisher_port, backend_publisher_endpoint)

    response = request.post(
            backend_publisher_api_decrypted_tokens_request_url,
            json={"phone_number": MSISDN}, cookies=request.cookies.get_dict())

    response.raise_for_status()

    return response.json()

def dev_backend_authenticate_user(auth_id: str, auth_key: str) -> tuple:
    """
    """
    dev_backend_api_auth_url = __gateway_confs['dev_api']['authentication_url']
    logging.debug("dev_backed_api_auth_url: %s", dev_backend_authenticate_user)

    request = requests.Session()
    response = request.post(
            dev_backend_api_auth_url,
            json={"auth_key": auth_key, "auth_id": auth_id})

    response.raise_for_status()


    return True, request
