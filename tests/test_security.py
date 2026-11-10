import os
import time
import unittest
from urllib.parse import quote

os.environ.setdefault('vulnerable', '1')

import jwt  # noqa: E402

from config import vuln_app  # noqa: E402


class VampiTestCase(unittest.TestCase):
    def setUp(self):
        self.client = vuln_app.app.test_client()
        self.assertEqual(self.client.get('/createdb').status_code, 200)

    def login(self, username, password):
        res = self.client.post('/users/v1/login', json={'username': username, 'password': password})
        return res.get_json()

    def token(self, username, password):
        return self.login(username, password)['auth_token']

    def auth(self, username, password):
        return {'Authorization': 'Bearer ' + self.token(username, password)}


class SqlInjectionTest(VampiTestCase):
    def test_get_user_by_username(self):
        res = self.client.get('/users/v1/name1')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json(), {'username': 'name1', 'email': 'mail1@mail.com'})

    def test_union_select_does_not_leak_passwords(self):
        payload = "x' UNION SELECT 1, password, 3, password, 5 FROM users WHERE username = 'admin'--"
        res = self.client.get('/users/v1/' + quote(payload))
        self.assertEqual(res.status_code, 404)
        self.assertNotIn('pass1', res.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
