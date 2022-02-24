#!/usr/bin/env python3

import sqlite3
import logging
import uuid
import os

class Users:

    def __init__(self, user_id:str) -> None:
        """Creates new user record if not exist.

        This method would create a record for the user and store in the path of 
        user_record_filepath.

        Args: session_id (str): The last session ID being tracked for this session.
            public_key (str): User's public key.
            shared_key (str): Shared key for encrypting and decrypting incoming messages.
        """
        self.public_key = None
        self.shared_key = None

        self.user_id = user_id
        self.user_record_filename = "%s.db" % self.user_id

        self.user_record_filepath = os.path.join(
                os.path.dirname(__file__), '.db/users', self.user_record_filename)

        logging.debug("user db filepath: %s", self.user_record_filepath)

        try:
            logging.debug('checking for user record file')
            db_exist = self.__is_database__()
        except Exception as error:
            raise error
        else:
            if not db_exist:
                try:
                    self.__create_db__()
                    logging.debug('created db file: %s', self.user_record_filepath)
                except Exception as error:
                    raise error
        try:
            logging.debug('checking for user record file tables')
            self.__create_table__()
        except Exception as error:
            logging.error("failed to create table: %s", self.user_record_filepath)
            raise error

    def __is_database__(self):
        try:
            self.con = sqlite3.connect(
                    f"file:{self.user_record_filename}?mode=rw",
                    uri=True)

        except sqlite3.OperationalError as error:
            # raise error
            return False
        except Exception as error:
            raise error

        return True


    def __create_db__(self):
        try:
            self.con = sqlite3.connect(self.user_record_filepath)
        except Exception as error:
            raise error

    def __create_table__(self):
        try:
            cur = self.con.cursor()
            cur.execute(f'''CREATE TABLE IF NOT EXISTS sessions
            (session_id TEXT NOT NULL,
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

    def start_new_session(self, session_id: str = None) -> str:
        """Add a new session record for the specific user.

        Args:
            user_id (str): Creates a new session for the user_id.

        Returns:
            int: the session ID.
        """

        if not session_id:
            session_id = uuid.uuid4().hex

        logging.debug("starting new session [%s] for user [%s]", session_id, self.user_id)
        cur = self.con.cursor()
        try:
            cur.execute(
                f"INSERT INTO sessions (session_id, user_id, public_key, shared_key) VALUES(?,?,?,?)",
                (session_id, self.user_id, self.public_key, self.shared_key)
            )
            self.con.commit()
        except Exception as error:
            raise error

        return session_id


    def update_public_key(self, public_key: str, session_id: str) -> int:
        try:
            cur = self.con.cursor()
            cur.execute(
                    f"UPDATE sessions SET public_key=:public_key WHERE session_id=:session_id AND user_id=:user_id",
                    {"public_key":public_key, "user_id":self.user_id, "session_id":session_id})
            self.con.commit()
            
            return cur.rowcount
        except Exception as error:
            raise error


    def update_shared_key(self, shared_key: str, session_id: str):
        try:
            cur = self.con.cursor()
            cur.execute(
                    f"UPDATE sessions SET shared_key=:shared_key WHERE session_id=:session_id AND user_id=:user_id",
                    {"shared_key":shared_key, "user_id":self.user_id, "session_id":session_id})
            self.con.commit()
        except Exception as error:
            raise error

    def update_current_session(self, current_session_id: str, session_id: str = None) -> str:
        try:
            if not session_id:
                session_id = uuid.uuid4().hex

            cur = self.con.cursor()
            cur.execute(
                    f"UPDATE sessions SET session_id=:session_id WHERE session_id=:current_session_id AND user_id=:user_id",
                    {"session_id":session_id, "current_session_id":current_session_id, "user_id":session_id})
            logging.debug("rows affected: %s", cur.rowcount)
            self.con.commit()
        except Exception as error:
            raise error
        else:
            return session_id

