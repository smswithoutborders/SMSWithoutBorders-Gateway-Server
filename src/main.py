#!/usr/bin/env python3

# Use this for IDEs to check data types
# https://docs.python.org/3/library/typing.html

from flask import Flask, request, jsonify, Response
from flask_cors import CORS, cross_origin

from src import sync, rsa, aes, publisher, rmq_broker, notifications
from src.process_incoming_messages import (
    process_data,
    DecryptError,
    UserNotFoundError,
    SharedKeyError,
    InvalidDataError,
)
from sockets import ip_grap

from src.users import Users

from src.users_entity import UsersEntity

import os
import json
import logging
import threading
import base64
import bleach

from SwobBackendPublisher import MySQL, Lib
from SwobBackendPublisher.exceptions import UserDoesNotExist, DuplicateUsersExist

__api_version_number = 2

HOST = os.environ.get("HOST")
SOCK_PORT = os.environ.get("SOCK_PORT")
RSA_PR_KEY = os.environ.get("RSA_PR_KEY")
SHARED_KEY_FILE = os.environ.get("SHARED_KEY")

# Required for BE-Publisher Lib
MYSQL_BE_HOST = (
    os.environ["MYSQL_HOST"]
    if not os.environ.get("MYSQL_BE_HOST")
    else os.environ.get("MYSQL_BE_HOST")
)

MYSQL_BE_USER = (
    os.environ["MYSQL_USER"]
    if not os.environ.get("MYSQL_BE_USER")
    else os.environ.get("MYSQL_BE_USER")
)

MYSQL_BE_PASSWORD = (
    os.environ["MYSQL_PASSWORD"]
    if not os.environ.get("MYSQL_BE_PASSWORD")
    else os.environ.get("MYSQL_BE_PASSWORD")
)
MYSQL_BE_DATABASE = (
    os.environ["MYSQL_DATABASE"]
    if not os.environ.get("MYSQL_BE_DATABASE")
    else os.environ.get("MYSQL_BE_DATABASE")
)

# Required for storing user encryption information
MYSQL_HOST = (
    "127.0.0.1" if not os.environ.get("MYSQL_HOST") else os.environ.get("MYSQL_HOST")
)
MYSQL_USER = (
    "root" if not os.environ.get("MYSQL_USER") else os.environ.get("MYSQL_USER")
)

MYSQL_PASSWORD = os.environ["MYSQL_PASSWORD"]
MYSQL_DATABASE = os.environ["MYSQL_DATABASE"]

# Database creations
usersBEPUB = UsersEntity(
    mysql_host=MYSQL_BE_HOST,
    mysql_user=MYSQL_BE_USER,
    mysql_password=MYSQL_BE_PASSWORD,
    mysql_database=MYSQL_BE_DATABASE,
)

BEPubLib = Lib(usersBEPUB.db)

usersEntity = UsersEntity(
    mysql_host=MYSQL_HOST,
    mysql_user=MYSQL_USER,
    mysql_password=MYSQL_PASSWORD,
    mysql_database=MYSQL_DATABASE,
)

users = Users(usersEntity)

try:
    users.create_database_and_tables__()
except Exception as error:
    logging.exception(error)


# RMQ creations
rmq_connection, rmq_channel = publisher.init_rmq_connections()

# create notifications exchanges
try:
    notifications.create_exchange(channel=rmq_channel)
except Exception as error:
    logging.exception(error)

# Flask creations
app = Flask(__name__)
app.config.from_object(__name__)

# CORS(
#    app,
#    resources={r"/*": {
#        "origins": json.loads(os.environ.get("ORIGINS"))}},
#    supports_credentials=True,
# )

CORS(
    app,
    origins=json.loads(os.environ.get("ORIGINS")),
    supports_credentials=True,
)

# @app.before_request
# def after_request_func():
#    response = Response()
#    response.headers['Access-Control-Allow-Origin'] = "https://smswithoutborders.com"
#
#    return response


@app.after_request
def after_request(response):
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubdomains"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "script-src 'self'; object-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), speaker=(), speaker-selection=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()"
    )
    return response


@app.route("/v%s/sync/users/<user_id>" % (__api_version_number), methods=["GET"])
def get_sync_url(user_id: str):
    """
    TODO: validate user_id before having it in production
    """
    user_id = bleach.clean(user_id)

    try:
        port = app.config["SOCK_PORT"]

        # print(dir(app.env["HOST"]))
        # TODO:  does not work well with docker
        # host = socket_sessions.get_host(app.config["HOST"])
        host = request.host.split(":")[0]
        sockets_url = sync.get_sockets_sessions_url(
            user_id=user_id, host=host, port=SOCK_PORT
        )
    except Exception as error:
        app.logger.exception(error)
        return "", 500
    else:
        return sockets_url, 200


@app.route("/v%s/sync/users" % (__api_version_number), methods=["DELETE"])
def refresh_users_shared_key():
    """ """
    try:
        data = json.loads(request.data, strict=False)
    except Exception as error:
        logging.exception(error)

        return "poorly formed json", 400

    if not "msisdn_hashed" in data:
        return "missing msisdn", 400

    SHARED_KEY = None
    with open(SHARED_KEY_FILE, "r") as f:
        SHARED_KEY = f.readline().strip()[:32]

    msisdn_hash = data["msisdn_hashed"]

    # msisdn_hash = base64.b64decode(msisdn_hash)
    iv = msisdn_hash[:16].encode("utf8")
    msisdn_hash = bytes.fromhex(msisdn_hash[16:])

    try:
        msisdn_hash = aes.AESCipher.decrypt(
            data=msisdn_hash, iv=iv, shared_key=SHARED_KEY
        )
    except Exception as error:
        app.logger.exception(error)
        return "failed to decrypt", 403
    else:
        try:
            user = users.find(msisdn_hash=msisdn_hash)

            users.delete(user)
        except Exception as error:
            logging.exception(error)
            return "", 500

        return "OK", 200


@app.route("/v%s/sync/users/verification" % (__api_version_number), methods=["POST"])
@cross_origin(origins="*")
def verify_user_shared_key():
    """
    - encrypt user shared key
    - compare input shared key against encrypted copy
    """
    try:
        data = json.loads(request.data, strict=False)
    except Exception as error:
        logging.exception(error)

        return "poorly formed json", 400
    else:
        if not "msisdn" in data:
            return "missing msisdn", 400
        if not "msisdn_signature" in data:
            return "missing signature", 400

        try:
            mgf1ParameterSpec = (
                data["mgf1ParameterSpec"] if "mgf1ParameterSpec" in data else "sha1"
            )
            # mgf1ParameterSpec = 'sha1'

            hashingAlgorithm = (
                data["hashingAlgorithm"] if "hashingAlgorithm" in data else "sha256"
            )
            # hashingAlgorithm = 'sha256'

            decrypted_msisdn = rsa.SecurityRSA.decrypt(
                data["msisdn"],
                private_key_filepath=RSA_PR_KEY,
                mgf1ParameterSpec=mgf1ParameterSpec,
                hashingAlgorithm=hashingAlgorithm,
            )

            app.logger.debug("%s", decrypted_msisdn)

        except Exception as error:
            app.logger.exception(error)
            return "error with decryption", 403
        else:
            user = users.find(msisdn_hash=decrypted_msisdn)

            if not user.shared_key:
                return "no shared key for user", 403

            if not user.public_key:
                return "no public key for user", 403

            try:
                rsa.SecurityRSA.sign(
                    message=decrypted_msisdn,
                    signature=base64.b64decode(data["msisdn_signature"]),
                    public_key=user.public_key,
                )
            except (ValueError, TypeError) as error:
                return "unknown signature request", 403
            except Exception as error:
                app.logger.exception(error)
                return "signing check error", 400
            else:
                user_shared_key = user.shared_key
                user_public_key = user.public_key

                # mgf1ParameterSpec = user.mgf1ParameterSpec
                # logging.debug("user mgf param: %s", mgf1ParameterSpec)

                hashingAlgorithm = user.hashingAlgorithm

                mgf1ParameterSpec = "sha1"
                encrypted_shared_key = rsa.SecurityRSA.encrypt_with_key(
                    data=user_shared_key,
                    public_key=user_public_key,
                    mgf1ParameterSpec=mgf1ParameterSpec,
                    hashingAlgorithm=hashingAlgorithm,
                )

                encrypted_shared_key = base64.b64encode(encrypted_shared_key)
                logging.debug("encrypted_key: %s", encrypted_shared_key)

                return (
                    jsonify({"shared_key": encrypted_shared_key.decode("utf-8")}),
                    200,
                )


@app.route(
    "/v%s/sync/users/<user_id>/sessions/<session_id>/" % (__api_version_number),
    methods=["POST"],
)
def get_users_platforms(user_id: str, session_id: str):
    """ """
    global rmq_connection, rmq_channel

    user_id = bleach.clean(user_id)
    session_id = bleach.clean(session_id)

    try:
        data = json.loads(request.data, strict=False)
    except Exception as error:
        logging.exception(error)

        return "poorly formed json", 400
    else:

        if not "password" in data:
            return "missing password", 400

        if not "public_key" in data:
            return "missing public key", 400

        """
        TODO:
            - update the ios app to have mgf1ParameterSpec
            - update the android to have hashingAlgorithm
        """
        mgf1ParameterSpec = (
            data["mgf1ParameterSpec"] if "mgf1ParameterSpec" in data else "sha1"
        )
        # mgf1ParameterSpec = 'sha1'
        hashingAlgorithm = (
            data["hashingAlgorithm"] if "hashingAlgorithm" in data else "sha256"
        )
        # hashingAlgorithm = 'sha256'

        try:
            user_password = data["password"]
            user_public_key = data["public_key"]

            app.logger.debug("mgf1ParameterSpec: %s", mgf1ParameterSpec)
            app.logger.debug("hashingAlgorithm: %s", hashingAlgorithm)

            decrypted_password = rsa.SecurityRSA.decrypt(
                user_password,
                private_key_filepath=RSA_PR_KEY,
                mgf1ParameterSpec=mgf1ParameterSpec,
                hashingAlgorithm=hashingAlgorithm,
            )
        except Exception as error:
            app.logger.exception(error)
            return "error with decryption", 400
        else:

            user_msisdn_hash = None
            try:
                user_msisdn_hash = BEPubLib.get_phone_number_hash_from_id(
                    user_id=user_id, password=str(decrypted_password, "utf-8")
                )

            except (UserDoesNotExist, DuplicateUsersExist) as error:
                logging.exception(error)
                return "", 403

            user_msisdn_hash = user_msisdn_hash["phoneNumber_hash"]
            try:
                user = users.find(msisdn_hash=user_msisdn_hash)
            except Exception as error:
                app.logger.exception(error)
                return "", 403

            user_shared_key = sync.generate_shared_key()

            user.id = user_id
            user.public_key = user_public_key
            user.msisdn_hash = user_msisdn_hash
            user.shared_key = user_shared_key
            user.mgf1ParameterSpec = mgf1ParameterSpec
            user.hashingAlgorithm = hashingAlgorithm

            try:
                users.commit(user)
            except Exception as error:
                logging.exception(error)
                return "", 500

            try:
                user_platforms = BEPubLib.get_user_platforms_from_id(user_id=user_id)

                mgf1ParameterSpec = (
                    data["mgf1ParameterSpec_dec"]
                    if "mgf1ParameterSpec_dec" in data
                    else "sha1"
                )
                encrypted_shared_key = rsa.SecurityRSA.encrypt_with_key(
                    data=user_shared_key,
                    public_key=user_public_key,
                    mgf1ParameterSpec=mgf1ParameterSpec,
                    hashingAlgorithm=hashingAlgorithm,
                )

                # TODO: customize exception just in case issue with encrypting for user
            except Exception as error:
                logging.exception(error)
                return "", 500

            else:
                b64_encoded_shared_key = base64.b64encode(encrypted_shared_key)

                try:
                    if not publisher.not_active_connection(rmq_connection):
                        rmq_connection, rmq_channel = publisher.init_rmq_connections()

                    notifications.create_users_notifications(
                        rmq_host=os.environ.get("RMQ_HOST"),
                        channel=rmq_channel,
                        queue_name=user_msisdn_hash,
                        user_name=user_msisdn_hash,
                        password=b64_encoded_shared_key.decode("utf-8"),
                    )

                except Exception as error:
                    logging.exception(error)

                return (
                    jsonify(
                        {
                            "msisdn_hash": user_msisdn_hash,
                            "shared_key": b64_encoded_shared_key.decode("utf-8"),
                            "user_platforms": user_platforms,
                        }
                    ),
                    200,
                )


@app.route("/sms/platform/<platform>", methods=["POST"])
@cross_origin(origins="*")
def incoming_sms_routing(platform):
    """ """
    global rmq_connection, rmq_channel

    platform = bleach.clean(platform)

    data = request.data

    try:
        processed_data = process_data(data, BEPubLib, users)

        app.logger.debug("Encrypted data: %s", processed_data)

        # if not publisher.not_active_connection(rmq_channel):
        if not publisher.not_active_connection(rmq_connection):
            rmq_connection, rmq_channel = publisher.init_rmq_connections()

        publisher.publish(channel=rmq_channel, data=processed_data)

        return "published!", 200

    except (
        DecryptError,
        UserNotFoundError,
        UserDoesNotExist,
        DuplicateUsersExist,
    ) as err:
        return str(err), 403

    except SharedKeyError as err:
        return str(err), 500

    except InvalidDataError as err:
        return str(err), 400

    except Exception as err:
        logging.exception(err)
        return "Internal Server Error", 500


def logging_after_request(response):
    # in here is where we transmit to the logger trace
    # logging.debug(response)
    logging.debug(response.response)
    return response


app.after_request(logging_after_request)
