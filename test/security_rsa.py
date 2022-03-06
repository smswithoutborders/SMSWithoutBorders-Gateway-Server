#!/usr/bin/env python3

import sys    
import unittest
import uuid
import logging

from security.rsa import SecurityRSA

# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level='DEBUG')

class TestSecurityRSA(unittest.TestCase):

    def test_encrypt_decrypt(self):
        expected_output = "Hello world"

        securityRSA = SecurityRSA()
        public_key, private_key = securityRSA.generate_keypair()

        encrypted_expected_output = securityRSA._encrypt(expected_output)
        decrypted_expected_output = securityRSA._decrypt(encrypted_expected_output)

        self.assertEqual(decrypted_expected_output.decode('utf-8'), 
                expected_output)

    """
    def test_rsa_decrypt_external(self):
        encrypted_input = "WT7Q6gJCmf871z1vFBoaWswF4BFoW8N2l4qmTh0nr9r+zMQ9sybqXmv16jc6fG+MPqe7NkGBnvtC6zB1RDmj1UHPIq23Y2mM849VgTJAyYO/O4aLtavqd+9QBqzsgan7bhag2FNX6t6xpIKy0SdgPRauP5DhhVUf9CvgwvZ0d3c="

        expected_output = "hello world"

        decrypted_output = SecurityRSA.decrypt(
                private_key_filepath="test/private.pem", data=encrypted_input)
        self.assertEqual(decrypted_output.decode('utf-8'), expected_output)
    """

if __name__ == "__main__":
    unittest.main()

