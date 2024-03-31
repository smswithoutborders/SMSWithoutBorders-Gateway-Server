"""Module to listen for incoming emails via IMAP, process them, and publish encrypted data."""

import os
import imaplib
import logging
import email
import time

from concurrent.futures import ThreadPoolExecutor

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
    logging.exception(error)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def connect_to_imap():
    """Establishes a secure connection to the IMAP server.

    Returns:
        imaplib.IMAP4_SSL: An IMAP4_SSL object representing the connection
            to the IMAP server.
    Raises:
        Exception: If connection to the IMAP server fails.
    """
    try:
        logger.debug("Connecting to IMAP server...")
        imap = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
        imap.login(IMAP_USERNAME, IMAP_PASSWORD)
        logger.info("Connection to IMAP server successful.")
        return imap
    except Exception as err:
        logger.error("Failed to connect to IMAP server:")
        raise err


def process_single_email(imap, email_id, rmq_connection, rmq_channel):
    """Processes a single email.

    Args:
        imap (imaplib.IMAP4_SSL): An IMAP4_SSL object representing the
            connection to the IMAP server.
        email_id (bytes): The unique identifier of the email to be processed.
        rmq_connection (pika.BlockingConnection): A blocking connection to RabbitMQ.
        rmq_channel (pika.BlockingChannel): A blocking channel to RabbitMQ.
    """
    try:
        _, data = imap.fetch(email_id, "(RFC822)")
        raw_email = data[0][1]
        email_message = email.message_from_bytes(raw_email)
        content = extract_email_content(email_message)

        processed_data = process_data(content["body"], bepub_lib, users)

        logger.debug("Encrypted data: %s", processed_data)

        if not publisher.not_active_connection(rmq_connection):
            rmq_connection, rmq_channel = publisher.init_rmq_connections()

        publisher.publish(channel=rmq_channel, data=processed_data)

        logger.debug("Deleting email %s", email_id)
        imap.store(email_id, "+FLAGS", "\\Deleted")

        logger.info("Successfully queued email %s", email_id)

    except (DecryptError, UserNotFoundError, SharedKeyError, InvalidDataError):
        logger.debug("Deleting email %s", email_id)
        imap.store(email_id, "+FLAGS", "\\Deleted")

    except Exception:
        logger.error("Error processing email %s:", email_id, exc_info=True)
        imap.store(email_id, "-FLAGS", "(\\Seen)")


def process_unread_emails(imap, rmq_connection, rmq_channel):
    """Fetches and processes unread emails.

    Args:
        imap (imaplib.IMAP4_SSL): An IMAP4_SSL object representing the
            connection to the IMAP server.
        rmq_connection (pika.BlockingConnection): A blocking connection to RabbitMQ.
        rmq_channel (pika.BlockingChannel): A blocking channel to RabbitMQ.
    """
    try:
        imap.select(MAIL_FOLDER)
        _, data = imap.search(None, "(UNSEEN)")

        with ThreadPoolExecutor(max_workers=5) as executor:
            for email_id in data[0].split():
                executor.submit(
                    process_single_email, imap, email_id, rmq_connection, rmq_channel
                )

    except Exception as err:
        logger.error("Error fetching emails:")
        raise err


def extract_email_content(email_message):
    """Extracts content from the email message.

    Args:
        email_message (email.message.Message): An email message object.

    Returns:
        dict: A dictionary containing extracted content from the email message.
    """
    subject = email_message["Subject"]
    sender = email_message["From"]
    date = email_message["Date"]
    body = ""
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if content_type == "text/plain" and "attachment" not in content_disposition:
                body += part.get_payload(decode=True).decode()
            elif (
                content_type == "text/html" and "attachment" not in content_disposition
            ):
                # body += part.get_payload(decode=True).decode()
                pass
            else:
                # Handle attachments or other content types if needed
                pass

    content = {"subject": subject, "sender": sender, "date": date, "body": body}
    return content


def logout_from_imap(imap):
    """Logs out from the IMAP server if the connection is still valid.

    Args:
        imap (imaplib.IMAP4_SSL): An IMAP4_SSL object representing the
            connection to the IMAP server.
    """
    try:
        if imap.state != "LOGOUT":
            if imap.state == "SELECTED":
                imap.close()
            imap.logout()
            logger.info("Logged out from IMAP server.")
        else:
            logger.info("IMAP connection already in logout state.")
    except Exception:
        logger.error("Failed to log out from IMAP server:", exc_info=True)


def main():
    """Main function to run the IMAP listener."""
    imap = connect_to_imap()
    logger.info("IMAP listener started...")

    try:
        rmq_connection, rmq_channel = publisher.init_rmq_connections()

        while True:
            try:
                process_unread_emails(imap, rmq_connection, rmq_channel)
            except imaplib.IMAP4.abort as abort_err:
                if "socket error: TLS/SSL connection has been closed" in str(abort_err):
                    logger.error("IMAP connection aborted. Reconnecting...")
                    try:
                        imap = connect_to_imap()
                        continue
                    except Exception as reconnect_err:
                        logger.error("Error reconnecting to IMAP server:")
                        raise reconnect_err
                else:
                    logger.error("An unexpected error occurred:", exc_info=True)
            except Exception:
                logger.error("An unexpected error occurred:", exc_info=True)

            time.sleep(20)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt: Gracefully shutting down...")

    except Exception:
        logger.error("An unexpected error occurred in the main loop:", exc_info=True)

    finally:
        logout_from_imap(imap)


if __name__ == "__main__":
    main()
