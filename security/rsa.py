#!/usr/bin/env python3

from Crypto.PublicKey import RSA

class SecurityRSA:
    def generate_keypair(self, keysize:int = 1024) -> tuple:

        """Generate public and private keypair and return them.

        Returns:
            public_key (str), private_key (str)
        """

        key = RSA.generate(keysize)
        self.private_key = key.export_key()

        self.public_key = key.publickey().export_key()

        return self.public_key, self.private_key


    @staticmethod
    def generate_keypair_write( 
            private_key_filepath: str="private.pem", 
            public_key_filepath: str="public.pem", keysize: int=1024) -> tuple:

        """Generate public and private keypair and write them.
        
        Args:
            public_key_filepath (str): Absolute filepath to where the public key should be written and stored.
            If None, would be stored in the current dir. Files should end with the .pem.


            private_key_filepath (str): Absolute filepath to where the private key should be written and stored.
            If None, would be stored in the current dir. Files should end with the .pem.

        Returns:
            public_key (str), private_key (str)
        """

        securityRSA = SecurityRSA()
        public_key, private_key = securityRSA.generate_keypair()

        file_out = open(private_key_filepath, "wb")
        file_out.write(private_key)
        file_out.close()

        file_out = open(public_key_filepath, "wb")
        file_out.write(public_key)
        file_out.close()


        return public_key, private_key
