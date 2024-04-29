"""Utility module"""

import logging
from functools import wraps

import mysql.connector

logger = logging.getLogger(__name__)


def ensure_database_exists(host, user, password, database_name):
    """
    Decorator that ensures a MySQL database exists before executing a function.

    Args:
        host (str): The host address of the MySQL server.
        user (str): The username for connecting to the MySQL server.
        password (str): The password for connecting to the MySQL server.
        database_name (str): The name of the database to ensure existence.

    Returns:
        function: Decorated function.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                with mysql.connector.connect(
                    host=host, user=user, password=password
                ) as connection:
                    cursor = connection.cursor()

                    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database_name}")

                    logger.info(
                        "Database %s created successfully (if it didn't exist)",
                        database_name,
                    )

            except mysql.connector.Error as error:
                logger.error("Failed to create database: %s", error)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def create_table(model, table_name, db):
    """
    Creates a table for the given model if it doesn't exist in the specified database.

    Args:
        model: The Peewee Model instance for which to create the table.
        table_name (str): The name of the table to create.
        db: The database instance to create the table in.
    """
    with db.connection_context():
        if not db.table_exists(table_name):
            db.create_tables([model])
