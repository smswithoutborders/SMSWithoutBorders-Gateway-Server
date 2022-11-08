#!/usr/bin/env python3

import sqlite3
import logging
import uuid
import os

from src.users_entity import UsersEntity

class Users:

    TABLES = {}

    TABLES['gateway_server_users'] = (
    "CREATE TABLE `gateway_server_users` ("
    "  `id` int(11) NOT NULL AUTO_INCREMENT,"
    "  `msisdn_hash` varchar(14) NOT NULL,"
    "  `shared_key` varchar(16) NOT NULL,"
    "  `public_key` varchar(16) NOT NULL,"
    "  `date` date DEFAULT NULL,"
    "  PRIMARY KEY (`id`)"
    ") ENGINE=InnoDB")


    def __init__(self, userEntity: UsersEntity) -> None:
        """Creates new user record if not exist.

        This method would create a record for the user and store in the path of 
        user_record_filepath.

        Args: session_id (str): The last session ID being tracked for this session.
            public_key (str): User's public key.
            shared_key (str): Shared key for encrypting and decrypting incoming messages.
        """
        self.userEntity = userEntity

    def __create_database__(self):
        """
        """
        cursor = self.userEntity.db.cursor()
        try:
            cursor.execute(
            "CREATE DATABASE {} DEFAULT CHARACTER SET 'utf8'".format(
                self.userEntity.MYSQL_DATABASE))
        except mysql.connector.Error as err:
            raise err


    def __create_tables__(self):
        """
        """
        cursor = self.userEntity.db.cursor()

        for table_name in User.TABLES:
            table_description = User.TABLES[table_name]

            try:
                cursor.execute(table_description)
            except mysql.connector.Error as err:
                if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                    logging.warning("User table[%s] populate: already exist.", table_name)
                else:
                    raise err
            else:
                logging.info("User table[%s] populate: OK.", table_name)

        cursor.close()


    def create_database_and_tables__(self) -> None:
        """
        """
        try:
            self.__create_database__()
        except Exception as error:
            raise error

        try:
            self.__create_tables__()
        except Exception as error:
            raise error

    def store_shared_key(self, shared_key: str) -> None:
        """
        TODO: shared key should be encrypted when stored
        """
