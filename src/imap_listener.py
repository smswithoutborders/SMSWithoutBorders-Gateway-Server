"""Module to listen for incoming emails via IMAP, process them, and publish encrypted data."""

import os
import ssl
import logging

import time
import socket
import imaplib
import traceback

from imap_tools import (
    AND,
    MailBox,
    MailboxLoginError,
    MailboxLogoutError,
)
from email_reply_parser import EmailReplyParser
from SwobBackendPublisher import Lib
from src.process_incoming_messages import (
    process_data,
    DecryptError,
    UserNotFoundError,
    SharedKeyError,
    InvalidDataError,
)
from src import publisher
from src.users import Users
from src.users_entity import UsersEntity

IMAP_SERVER = os.environ["IMAP_SERVER"]
IMAP_PORT = int(os.environ.get("IMAP_PORT", 993))
IMAP_USERNAME = os.environ["IMAP_USERNAME"]
IMAP_PASSWORD = os.environ["IMAP_PASSWORD"]
MAIL_FOLDER = os.environ.get("MAIL_FOLDER", "INBOX")
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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("[IMAP LISTENER]")

try:
    users.create_database_and_tables__()
except Exception as error:
    logger.exception(error)


def delete_email(mailbox, email_uid):
    """
    Delete an email from the mailbox.

    Args:
        mailbox (imaplib.IMAP4_SSL): An IMAP4_SSL object representing the
            connection to the IMAP server.
        email_uid (int): The UID of the email to be deleted.

    Raises:
        Exception: If there's an error while deleting the email.
    """
    try:
        if email_uid:
            mailbox.delete(email_uid)
            logger.info("Successfully deleted email %s", email_uid)
    except Exception as e:
        logger.error("Error deleting email %s: %s", email_uid, e)
        raise


def process_incoming_email(mailbox, email, rmq_connection, rmq_channel):
    """
    Process an incoming email.

    Args:
        mailbox (imaplib.IMAP4_SSL): An IMAP4_SSL object representing the connection
            to the IMAP server.
        email (imap_tools.MailMessage): An object representing the email message.
        rmq_connection (pika.BlockingConnection): A blocking connection to RabbitMQ.
        rmq_channel (pika.BlockingChannel): A blocking channel to RabbitMQ.
    """

    body = EmailReplyParser.parse_reply(email.text)
    email_uid = email.uid

    try:
        processed_data = process_data(body, bepub_lib, users)

        logger.debug("Encrypted data: %s", processed_data)

        if not publisher.not_active_connection(rmq_connection):
            rmq_connection, rmq_channel = publisher.init_rmq_connections()

        publisher.publish(channel=rmq_channel, data=processed_data)

        delete_email(mailbox, email_uid)

        logger.info("Successfully queued email %s", email_uid)

    except (DecryptError, UserNotFoundError, SharedKeyError, InvalidDataError):
        delete_email(mailbox, email_uid)

    except Exception as e:
        logger.error("Error processing email %s: %s", email_uid, e)


def main():
    """
    Main function to run the email processing loop.
    """
    ssl_context = ssl.create_default_context()
    ssl_context.load_cert_chain(certfile=SSL_CERTIFICATE, keyfile=SSL_KEY)

    rmq_connection, rmq_channel = publisher.init_rmq_connections()

    done = False
    while not done:
        connection_start_time = time.monotonic()
        connection_live_time = 0.0
        try:
            with MailBox(IMAP_SERVER, IMAP_PORT, ssl_context=ssl_context).login(
                IMAP_USERNAME, IMAP_PASSWORD, MAIL_FOLDER
            ) as mailbox:
                logger.info(
                    "Connected to mailbox %s on %s", IMAP_SERVER, time.asctime()
                )
                while connection_live_time < 29 * 60:
                    try:
                        responses = mailbox.idle.wait(timeout=20)
                        if responses:
                            logger.debug("IMAP IDLE responses: %s", responses)

                        for msg in mailbox.fetch(
                            criteria=AND(seen=False),
                            bulk=50,
                            mark_seen=False,
                        ):
                            process_incoming_email(
                                mailbox, msg, rmq_connection, rmq_channel
                            )

                    except KeyboardInterrupt:
                        logger.info("Received KeyboardInterrupt, exiting...")
                        done = True
                        break
                    connection_live_time = time.monotonic() - connection_start_time
        except (
            TimeoutError,
            ConnectionError,
            imaplib.IMAP4.abort,
            MailboxLoginError,
            MailboxLogoutError,
            socket.herror,
            socket.gaierror,
            socket.timeout,
        ) as e:
            logger.error("Error occurred: %s", e)
            logger.error(traceback.format_exc())
            logger.info("Reconnecting in a minute...")
            time.sleep(60)


if __name__ == "__main__":
    main()
