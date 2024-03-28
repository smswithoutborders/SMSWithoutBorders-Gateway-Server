"""FTP Server Module"""

import os
import logging
import ssl
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler, ThrottledDTPHandler

from SwobBackendPublisher import Lib

from src.process_incoming_messages import process_data
from src import publisher

from src.users import Users
from src.users_entity import UsersEntity

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

FTP_USERNAME = os.environ["FTP_USERNAME"]
FTP_PASSWORD = os.environ["FTP_PASSWORD"]
FTP_IP_ADDRESS = os.environ["FTP_IP_ADDRESS"]
FTP_PORT = int(os.environ.get("FTP_PORT", 9909))
FTP_READ_LIMIT = int(os.environ.get("FTP_READ_LIMIT", 51200))
FTP_WRITE_LIMIT = int(os.environ.get("FTP_WRITE_LIMIT", 51200))
FTP_MAX_CON = int(os.environ.get("FTP_MAX_CON", 256))
FTP_MAX_CON_PER_IP = int(os.environ.get("FTP_MAX_CON_PER_IP", 5))
FTP_DIRECTORY = os.environ["FTP_DIRECTORY"]
SSL_CERTIFICATE = os.environ["SSL_CERTIFICATE"]
SSL_KEY = os.environ["SSL_KEY"]

# Required for BE-Publisher Lib
MYSQL_BE_HOST = os.environ.get("MYSQL_BE_HOST", os.environ["MYSQL_HOST"])
MYSQL_BE_USER = os.environ.get("MYSQL_BE_USER", os.environ["MYSQL_USER"])
MYSQL_BE_PASSWORD = os.environ.get("MYSQL_BE_PASSWORD", os.environ["MYSQL_PASSWORD"])
MYSQL_BE_DATABASE = os.environ.get("MYSQL_BE_DATABASE", os.environ["MYSQL_DATABASE"])

# Required for storing user encryption information
MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
MYSQL_USER = os.environ.get("MYSQL_USER", "root")
MYSQL_PASSWORD = os.environ["MYSQL_PASSWORD"]
MYSQL_DATABASE = os.environ["MYSQL_DATABASE"]

# Database creations
users_bepub_entity = UsersEntity(
    mysql_host=MYSQL_BE_HOST,
    mysql_user=MYSQL_BE_USER,
    mysql_password=MYSQL_BE_PASSWORD,
    mysql_database=MYSQL_BE_DATABASE,
)

bepub_lib = Lib(users_bepub_entity.db)

users_entity = UsersEntity(
    mysql_host=MYSQL_HOST,
    mysql_user=MYSQL_USER,
    mysql_password=MYSQL_PASSWORD,
    mysql_database=MYSQL_DATABASE,
)

users = Users(users_entity)

try:
    users.create_database_and_tables__()
except Exception as error:
    logger.exception(error)


def file_received(_, file):
    """Handle file received event.

    Args:
        _: Instance of FTPHandler (not used).
        file (str): The name of the received file.
    """
    try:
        with open(file, "r", encoding="utf-8") as f:
            content = f.read()

            rmq_connection, rmq_channel = publisher.init_rmq_connections()

            processed_data = process_data(content, bepub_lib, users)

            logger.debug("Encrypted data: %s", processed_data)

            if not publisher.not_active_connection(rmq_connection):
                rmq_connection, rmq_channel = publisher.init_rmq_connections()

            publisher.publish(channel=rmq_channel, data=processed_data)

            os.remove(file)

            logger.info("File '%s' content has been queued successfully.", file)

    except Exception:
        logger.error("Failed to process file '%s':", file, exc_info=True)


def create_ssl_context(certfile, keyfile):
    """Create an SSL context.

    Args:
        certfile (str): Path to the SSL certificate file.
        keyfile (str): Path to the SSL private key file.

    Returns:
        SSLContext: SSL context.
    """
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile, keyfile)
    return context


def main():
    """
    Main function to start the FTP server.
    """
    if os.path.exists(SSL_CERTIFICATE) and os.path.exists(SSL_KEY):
        logger.info("SSL credentials found. Running in production mode.")
        ssl_context = create_ssl_context(SSL_CERTIFICATE, SSL_KEY)
        handler = TLS_FTPHandler
        handler.ssl_context = ssl_context
    else:
        logger.info("No valid SSL credentials found. Running in development mode.")
        handler = FTPHandler

    authorizer = DummyAuthorizer()
    authorizer.add_user(FTP_USERNAME, FTP_PASSWORD, FTP_DIRECTORY, perm="w")

    address = (FTP_IP_ADDRESS, FTP_PORT)
    server = FTPServer(address, handler)

    server.max_cons = FTP_MAX_CON
    server.max_cons_per_ip = FTP_MAX_CON_PER_IP

    dtp_handler = ThrottledDTPHandler
    dtp_handler.read_limit = FTP_READ_LIMIT
    dtp_handler.write_limit = FTP_WRITE_LIMIT

    handler.authorizer = authorizer
    handler.banner = "SMSWITHOUTBORDERS"

    handler.on_file_received = file_received
    handler.dtp_handler = dtp_handler

    server.serve_forever()


if __name__ == "__main__":
    main()
