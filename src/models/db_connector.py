"""Module for connecting to a MySQL database."""

import os
import logging
from peewee import MySQLDatabase, DatabaseError
from src.utils import ensure_database_exists

logger = logging.getLogger(__name__)

database_name = os.environ.get("MYSQL_DATABASE")
host = os.environ.get("MYSQL_HOST")
password = os.environ.get("MYSQL_PASSWORD")
user = os.environ.get("MYSQL_USER")


@ensure_database_exists(host, user, password, database_name)
def connect():
    """
    Connects to the MySQL database.

    Returns:
        MySQLDatabase: The connected MySQL database object.

    Raises:
        DatabaseError: If failed to connect to the database.
    """
    try:
        db = MySQLDatabase(database_name, user=user, password=password, host=host)
        logger.info("Connected to MySQL database successfully.")
        return db
    except DatabaseError as error:
        logger.error("Failed to connect to MySQL database: %s", error)
        raise error
