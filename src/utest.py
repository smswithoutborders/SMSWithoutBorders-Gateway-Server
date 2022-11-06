#!/usr/bin/env python3

import unittest
import ip_grap
import sync
import os

class Sync(unittest.TestCase):
    """
    """

    def test_get_sockets_sessions_url(self):
        """
        """
        ip = ip_grap.get_private_ip()
        port = "8080"

        os.environ["HOST"] = "localhost"
        os.environ["SOC_PORT"] = port

        user_id = "00000"
        session_id = "11111"

        expected_session_url = "ws://%s:%s/v%s/sync/init/%s/%s" % (
                ip,
                port,
                "2",
                user_id,
                session_id)

        acquired_session_url = sync.get_sockets_sessions_url(user_id=user_id, session_id=session_id)
        self.assertEqual(acquired_session_url, expected_session_url)

    def test_sessions_public_key_exchange(self):
        """
        """
        user_id = "00000"
        session_id = "11111"

        expected_verification_url = "/v%s/sync/users/%s/sessions/%s" % (
                "2",
                user_id,
                session_id
                )

        acquired_verification_url = sync.sessions_public_key_exchange(user_id=user_id, session_id=session_id)
        self.assertEqual(acquired_verification_url, expected_verification_url)


    def test_sessions_user_fetch(self):
        """
        """

if __name__ == '__main__':
    unittest.main()
