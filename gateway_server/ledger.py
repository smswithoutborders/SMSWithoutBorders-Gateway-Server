#!/usr/bin/env python3

import os
import logging
import sqlite3 as database

class Ledger:

    seeders_ledger_filename = os.path.join(
            os.path.dirname(__file__), '.db/seeders', f"seeds.db")
    
    def __init__(self, IMSI: str, MSISDN: str, seed_type: str = 'seed'):
        """Creates an instance of ledger for the IMSI (node).
        In case the ledger does not already exist, it is created.
        """
        self.IMSI = IMSI
        self.MSISDN = MSISDN
        self.seed_type = seed_type

        """
        Check if ledger file exist,
        if not, create it
        """
        self.database_conn = None
        self.seeds_ledger_filename = os.path.join(
                os.path.dirname(__file__), '.db/nodes', f"{IMSI}.db")
        try:
            if not self.__is_ledger_file__(self.seeds_ledger_filename):
                try:
                    self.__create_seeds_ledger_file__()
                    logging.info("Created seed's ledger for %s", self.IMSI)

                    self.__populate_seed_ledger_file__()
                    logging.info("Populated seed ledger for %s", self.IMSI)

                    self.__populate_seeders_ledger_file__()
                    logging.info("Populated seeder ledger for %s", self.IMSI)
                except Exception as error:
                    raise error
            else:
                logging.debug("Ledger exist for %s", self.IMSI)
        except Exception as error:
            raise error


    @staticmethod
    def make_ledgers() -> None:
        try:
            if not Ledger.__is_ledger_file__(Ledger.seeders_ledger_filename):
                try:
                    Ledger.__create_seeders_ledger_file__()
                    logging.debug("[*] created seeders ledger")

                except Exception as error:
                    raise error
            else:
                logging.debug("Ledger exist for seeds")
        except Exception as error:
            raise error


    @staticmethod
    def __is_ledger_file__(ledger_filename: str) -> bool:
        """Checks if ledger file exist.
        """
        try:
            database_conn = database.connect(
                    f"file:{ledger_filename}?mode=rw", uri=True)
        except database.OperationalError as error:
            return False
        except Exception as error:
            raise error

        return True


    def __create_seeds_ledger_file__(self) -> None:
        """Create ledger file.
        """
        self.database_conn = database.connect(self.seeds_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            cur.execute( f'''
            CREATE TABLE seed
            (IMSI text PRIMARY KEY NOT NULL, 
            MSISDN text NOT NULL, 
            type text NOT NULL DEFAULT 'seed',
            LPS text DEFAULT NULL,
            date DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL) ''')

            self.database_conn.commit()
        except Exception as error:
            raise error
    
    def __populate_seed_ledger_file__(self)->None:
        self.database_conn = database.connect(self.seeds_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            cur.execute("""INSERT INTO seed (IMSI, MSISDN, type) VALUES (?, ?, ?)""", 
                    (self.IMSI, self.MSISDN, self.seed_type))
            self.database_conn.commit()
        except Exception as error:
            raise error

    def __populate_seeders_ledger_file__(self)->None:
        self.database_conn = database.connect(self.seeders_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            cur.execute("""INSERT INTO seeders (IMSI, MSISDN, type) VALUES (?, ?, ?)""", 
                    (self.IMSI, self.MSISDN, self.seed_type))
            self.database_conn.commit()
        except Exception as error:
            raise error

    @staticmethod
    def __create_seeders_ledger_file__() -> None:
        """Create ledger file.
        """
        database_conn = database.connect(Ledger.seeders_ledger_filename)

        cur = database_conn.cursor()
        try:
            cur.execute( f'''
            CREATE TABLE seeders
            (IMSI text NOT NULL, 
            MSISDN text NOT NULL, 
            type text NOT NULL DEFAULT 'seed',
            date DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL) ''')
            database_conn.commit()
        except Exception as error:
            raise error

    
    def find_seed(self) -> list:
        """Finds the fields
        """
        self.database_conn = database.connect(self.seeds_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            """Because there will always be just one seed. 
            More than one seed and there's a problem"""
            cur.execute('''SELECT * FROM seed WHERE MSISDN IS NOT NULL''')
        except Exception as error:
            raise error
        else:
            return cur.fetchall()

    def find_seeder(self) -> list:
        """Finds the fields
        """
        self.database_conn = database.connect(self.seeders_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            cur.execute('''SELECT * FROM seeders WHERE MSISDN=:MSISDN''', 
                    {"MSISDN":self.MSISDN})
        except Exception as error:
            raise error
        else:
            return cur.fetchall()


    @staticmethod
    def list_seeders() -> list:
        """Finds the fields
        """
        database_conn = database.connect(Ledger.seeders_ledger_filename)

        cur = database_conn.cursor()
        try:
            cur.execute('''SELECT * FROM seeders''')
        except Exception as error:
            raise error
        else:
            return cur.fetchall()


    def update_seed_MSISDN(self, seed_MSISDN: str) -> int:
        """
        """

        self.database_conn = database.connect(self.seeds_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            cur.execute('''UPDATE seed SET MSISDN=:MSISDN WHERE IMSI=:IMSI''', 
                    {"MSISDN":seed_MSISDN, "IMSI":self.IMSI})
            self.database_conn.commit()
        except Exception as error:
            raise error
        else:
            return cur.rowcount

    def update_seeds_seeder_MSISDN(self, seeder_MSISDN: str):
        """
        """

        self.database_conn = database.connect(self.seeds_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            cur.execute('''UPDATE seed SET seeder_MSISDN=:seeder_MSISDN''', {"seeder_MSISDN":seeder_MSISDN})
            self.database_conn.commit()
        except Exception as error:
            raise error


    @staticmethod
    def add_seeders(seeders: list):
        """
        """

        self.database_conn = database.connect(self.seeders_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            cur.executemany('''INSERT INTO seeders values (?)''', 
                    [("MSISDN", seeder.MSISDN) for seeder in seeders])
        except Exception as error:
            raise error
        else:
            return cur.fetchall()

    def update_seed_ping(self, LPS: str) -> int:
        """Updates the ledger with ping request as they come in.

        """
        self.database_conn = database.connect(self.seeds_ledger_filename)

        cur = self.database_conn.cursor()
        try:
            cur.execute('''UPDATE seed SET LPS=:LPS WHERE IMSI=:IMSI''', 
                    {"LPS":LPS, "IMSI":self.IMSI})
            self.database_conn.commit()
        except Exception as error:
            raise error
        else:
            return cur.rowcount
