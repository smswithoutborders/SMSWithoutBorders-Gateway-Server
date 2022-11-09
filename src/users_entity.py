#!/usr/bin/env python3

import logging
import os

from SwobBackendPublisher import MySQL, Lib
from SwobBackendPublisher.exceptions import (
    PlatformDoesNotExist,
    UserDoesNotExist,
    DuplicateUsersExist,
    InvalidDataError
)

class UsersEntity:
    def __init__(self, mysql_host, mysql_user, mysql_password, mysql_database):
        self.MYSQL_HOST=mysql_host
        self.MYSQL_USER=mysql_user
        self.MYSQL_PASSWORD=mysql_password
        self.MYSQL_DATABASE=mysql_database

        self.db = MySQL.connector(
                database=self.MYSQL_DATABASE,
                user=self.MYSQL_USER,
                password=self.MYSQL_PASSWORD,
                host=self.MYSQL_HOST)


if __name__ == "__main__":
    logging.basicConfig(level='DEBUG')
    try:
        host = os.environ["MYSQL_HOST"]
        user = os.environ["MYSQL_USER"]
        password = os.environ["MYSQL_PASSWORD"]
        database = os.environ["MYSQL_DATABASE"]

    except Exception as error:
        logging.exception(error)
    else:
        try:
            usersEntity = UsersEntity(mysql_host=host, mysql_user=user, 
                    mysql_password=password, mysql_database=database)
        except Exception as error:
            logging.exception(error)
        else:
            usersEntity.dbConnector.decrypt(phone_number="000000", platform_name="gmail")

