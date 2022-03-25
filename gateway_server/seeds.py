#!/usr/bin/env python3

import time
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

