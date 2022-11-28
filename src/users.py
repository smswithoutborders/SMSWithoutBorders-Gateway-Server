#!/usr/bin/env python3

import sqlite3
import logging
import uuid
import os

from src.users_entity import UsersEntity

import mysql.connector
from mysql.connector import errorcode

class User:

    id = None

    public_key = None

    msisdn_hash = None

    shared_key = None


class Users(User):
    TABLES = {}

    TABLE_NAME = "gateway_server_users"

    TABLES[TABLE_NAME] = (
    f"CREATE TABLE `{TABLE_NAME}` ("
    "  `msisdn_hash` varchar(256) NOT NULL,"
    "  `shared_key` text NOT NULL,"
    "  `public_key` text NOT NULL,"
    "  `date` date DEFAULT NULL,"
    "  PRIMARY KEY (`msisdn_hash`)"
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
        self.connection = mysql.connector.connect(
                host=self.userEntity.MYSQL_HOST,
                user=self.userEntity.MYSQL_USER,
                database=self.userEntity.MYSQL_DATABASE,
                password=self.userEntity.MYSQL_PASSWORD)


    def __create_database__(self):
        """
        """
        """
        connection = mysql.connector.connect(
                user=self.userEntity.MYSQL_USER,
                password=self.userEntity.MYSQL_PASSWORD)
        """

        cursor = self.connection.cursor()
        try:
            cursor.execute(
            "CREATE DATABASE {} DEFAULT CHARACTER SET 'utf8'".format(
                self.userEntity.MYSQL_DATABASE))
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_DB_CREATE_EXISTS:
                logging.warning("Database [%s] creation: already exist",
                        self.userEntity.MYSQL_DATABASE)
            else:
                raise err


    def __create_tables__(self):
        """
        """
        cursor = self.connection.cursor()

        for table_name in self.TABLES:
            table_description = self.TABLES[table_name]

            try:
                cursor.execute(table_description)
            except (mysql.connector.Error, Exception) as err:
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

    def commit(self, user: User) -> None:
        """
        insert or update
        """
        cursor = self.connection.cursor()

        insert_query = (
                f"INSERT INTO {self.TABLE_NAME} (public_key, shared_key, msisdn_hash) "
                "VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE "
                "public_key = VALUES(public_key), shared_key = VALUES(shared_key), "
                "msisdn_hash = VALUES(msisdn_hash)")

        try:
            cursor.execute(insert_query, (
                user.public_key,
                user.shared_key,
                user.msisdn_hash, ))

            self.connection.commit()

        except Exception as error:
            raise error

        finally:
            cursor.close()

    def find(self, msisdn_hash: str) -> None:
        """
        """
        if not msisdn_hash:
            return User()

        cursor = self.connection.cursor(buffered=True, dictionary=True)
        query = (
                "SELECT public_key, shared_key, msisdn_hash "
                f"FROM {self.TABLE_NAME} WHERE msisdn_hash = %s")
        try:
            cursor.execute(query, (msisdn_hash, ))
        except Exception as error:
            raise error
        else:
            user = User()
            for row in cursor:
                user.public_key = row['public_key']
                user.shared_key = row['shared_key']
                user.msisdn_hash = row['msisdn_hash']

                cursor.close()

            return user
