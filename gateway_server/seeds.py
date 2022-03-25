#!/usr/bin/env python3

import time
import logging
from gateway_server.ledger import Ledger

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

        LPS += 10
        return (LPS + 10) < current_time


    @staticmethod
    def list() -> list:
        """
        """

        try:
            """
            """
            seeders = Ledger.list_seeders()
        except Exception as error:
            raise error
        else:
            """
            IMSI
            MSISDN
            seed_type
            update_datetime
            """

            active_seeders = []
            for seeder in seeders:
                IMSI = seeder[0]
                MSISDN = seeder[1]
                seed_type = seeder[2]
                seed = Seeds(IMSI=IMSI, MSISDN=MSISDN, seed_type=seed_type)

                if seed.expired():
                    logging.debug("%s has expired!", MSISDN)
                else:
                    active_seeders.append(seeder)

            return active_seeders

