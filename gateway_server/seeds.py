#!/usr/bin/env python3

import time
import logging
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

