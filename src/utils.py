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
                    with connection.cursor() as cursor:
                        sql = "CREATE DATABASE IF NOT EXISTS " + database_name
                        cursor.execute(sql)

                logger.info(
                    "Database %s created successfully (if it didn't exist)",
                    database_name,
                )

            except mysql.connector.Error as error:
                logger.error("Failed to create database: %s", error)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def create_tables(models, db):
    """
    Creates tables for the given models if they don't exist in the specified database.

    Args:
        models: A list of Peewee Model instances.
        db: The database instance to create the tables in.
    """
    with db.connection_context():
        models_to_create = [
            # pylint: disable=W0212
            model
            for model in models
            if not db.table_exists(model._meta.table_name)
        ]
        if models_to_create:
            db.create_tables(models_to_create)
