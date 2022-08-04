#!/usr/bin/env python3

import time
import logging
import sqlite3
import os
from gateway_server.ledger import Ledger
from helpers import telecom

class Seeds(Ledger):


    def __init__(self, IMSI: str, MSISDN: str, seed_type='seed'):
        """
        """
        super().__init__(IMSI=IMSI, MSISDN=MSISDN, seed_type=seed_type)
        self.IMSI = IMSI
        self.MSISDN = MSISDN
        self.seed_type = seed_type
        self.db_dir = os.path.abspath(".db")


    def register_ping_request(self) -> str:
        """Seeders signal their presence by sending ping request.
        """
        try:
            LPS = time.time()
            self.update_seed_ping(LPS=LPS)
        except Exception as error:
            raise error
        else:
            return str(LPS)


    def expired(self) -> bool:
        """Check if last ping is recent enough.
        """
        seed = self.find_seed()
        LPS = float(seed[0][3])
        logging.debug("Last ping session: %s", LPS)

        current_time = time.time()
        logging.debug("Current time: %s", current_time)

        # seconds
        ping_expiration_duration = 20
        return (LPS + ping_expiration_duration) < current_time

    
    def register_seed(self):
        if not os.path.exists(self.db_dir):
            return 400
        db_name = os.path.join(self.db_dir, f"{self.IMSI}.db")
        try:
            con = sqlite3.connect(db_name)
            cur = con.cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS imsi_msisdn
                                (imsi text, msisdn text)''')
            cur.execute('''INSERT INTO imsi_msisdn VALUES
                                (?, ?)''', (self.IMSI, self.MSISDN))
            con.commit()
            con.close()
            return 200
        except sqlite3.Error as err:
            logging.exception(err)
            return 500


    @staticmethod
    def get_all_seeds():

        try:
            db_path = os.path.abspath(".db")
            if os.path.exists(db_path):
                result = []
                for file in os.listdir(db_path):
                    if file.endswith(".db"):
                        try:
                            db_name = os.path.join(db_path, file)
                            con = sqlite3.connect(db_name)
                            cur = con.cursor()
                            imsi_msisdn = cur.execute('''SELECT * FROM imsi_msisdn''').fetchone()
                            if len(imsi_msisdn) == 2:
                                IMSI = imsi_msisdn[0]
                                MSISDN = imsi_msisdn[1]
                                
                                seed = Seeds(IMSI=IMSI, MSISDN=MSISDN)
                                result.append(seed)
                            else:
                                logging.exception(f"{db_name} has incomplete or no data")
                            con.close()
                        except sqlite3.Error as err:
                            logging.exception(err)
                            return ("", 500)
                if len(result) <= 0:
                    return ("No seeds found", 400)
                return (result, 200)
            else:
                return ("Database directory does not exist", 400)
        except Exception as error:
            logging.exception(error)
            return ("", 500)

    
    def get_seed_msisdn(self):
        
        try:
            db_file = f"{self.IMSI}.db"
            filename = os.path.join(self.db_dir, db_file)
            if os.path.exists(filename):
                con = sqlite3.connect(filename)
                cur = con.cursor()
                msisdn = cur.execute('''SELECT msisdn FROM imsi_msisdn
                        WHERE imsi=?''', [self.IMSI]).fetchone()
                con.close()
                if len(msisdn) > 0:
                    seed = Seeds(IMSI=self.IMSI, MSISDN=msisdn[0])
                    return (seed, 200)
                else:
                    return ("MSISDN does not exist", 400)
            else:
                return ("IMSI does not exist", 400)

        except sqlite3.Error as err:
                logging.exception(err)
                return ("Error getting MSISDN", 500)


    @staticmethod
    def list() -> list:
        """
        """

        try:
            """
            """
            seeds = Ledger.list_seeds()
        except Exception as error:
            raise error
        else:
            """
            IMSI
            MSISDN
            seed_type
            update_datetime
            """

            active_seeds = []
            # logging.debug("Seeds: %s", seeds)
            for seed in seeds:
                IMSI = seed[0][0]
                MSISDN = seed[0][1]
                seed_type = seed[0][2]
                seed = Seeds(IMSI=IMSI, MSISDN=MSISDN, seed_type=seed_type)

                if seed.expired():
                    logging.error("%s has expired!", MSISDN)
                else:
                    try:
                        MSISDN_country = telecom.get_phonenumber_country(MSISDN=MSISDN)
                        MSISDN_operator_name = telecom.get_phonenumber_operator_name(MSISDN=MSISDN)
                        MSISDN_operator_id = telecom.get_phonenumber_operator_id(MSISDN=MSISDN)
                        LPS = float(seed.find_seed()[0][3])
                        seed = {
                                "IMSI": IMSI,
                                "MSISDN": MSISDN,
                                "seed_type": seed_type,
                                "country": MSISDN_country,
                                "operator_name": MSISDN_operator_name,
                                "operator_id": MSISDN_operator_id,
                                "LPS": LPS}
                        active_seeds.append(seed)
                    except Exception as error:
                        logging.exception(error)

            return active_seeds

