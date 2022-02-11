#!/usr/bin/env python3

import sqlite3
import logging


class Sessions:

    def __init__(self, session_id: str=None, public_key: str=None, shared_key: str=None):
        """Instantiates object.
        Args:
            session_id (str): The last session ID being tracked for this session
            public_key (str): User's public key
            shared_key (str): Shared key for encrypting and decrypting incoming messages
        """
        self.user_id = None
        self.session_id = session_id
        self.public_key = public_key
        self.shared_key = shared_key

        try:
            self.__create__()
        except Exception as error:
            raise error

    def insert(self, user_id: str):
        """Add a new session record for the specific user.
        Args:
            user_id (str): Creates a new session for the user_id

        Returns:
            int: the session ID
        """
        id = ""
        cur = self.con.cursor()
        cur.execute(
            "INSERT INTO clients( id, user_id, public_key, shared_key) VALUES(?,?,?)",
            (id, user_id, self.public_key, self.shared_key)
        )

        self.user_id = user_id
        return self

    def update_public_key(self, public_key: str):
        try:
            cur = self.con.cursor()
        except Exception as error:
            raise error

    def __create__(self):
        try:
            cur = self.con.cursor()
            cur.execute('''CREATE TABLE IF NOT EXIST sessions
            (id TEXT PRIMARY KEY NOT NULL,
            user_id TEXT NOT NULL,
            public_key TEXT,
            shared_key TEXT,
            update_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL);''')

            self.con.commit()

        except sqlite3.Warning as error:
            # raise error
            logging.warning(error)

        except Exception as error:
            raise error
