#!/usr/bin/env python3

import sys    
import unittest
import uuid
import logging

from gateway_server.users import Users

# logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(level='DEBUG')

class TestUsers(unittest.TestCase):

    def test_start_new_session(self):
        users = Users(user_id='test_user')
        session_id = uuid.uuid4().hex

        returned_session_id = users.start_new_session(session_id)
        self.assertEqual(session_id, returned_session_id)


if __name__ == "__main__":
    unittest.main()

