"""Module for connecting to a database."""

import os
import logging
from peewee import DatabaseError, MySQLDatabase
from src.utils import ensure_database_exists

logger = logging.getLogger(__name__)

MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE")
MYSQL_HOST = os.environ.get("MYSQL_HOST")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD")
MYSQL_USER = os.environ.get("MYSQL_USER")


def connect():
    """
    Connects to the database.

    Returns:
        Database: The connected database object.

    Raises:
        DatabaseError: If failed to connect to the database.
    """
    return connect_to_mysql()


@ensure_database_exists(MYSQL_HOST, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE)
def connect_to_mysql():
    """
    Connects to the MySQL database.

    Returns:
        PooledMySQLDatabase: The connected MySQL database object.

    Raises:
        DatabaseError: If failed to connect to the database.
    """
    try:
        db = MySQLDatabase(
            MYSQL_DATABASE,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            host=MYSQL_HOST,
        )
        logger.info("Connected to MySQL database successfully.")
        return db
    except DatabaseError as error:
        logger.error("Failed to connect to MySQL database: %s", error)
        raise error
