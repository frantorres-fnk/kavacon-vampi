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


class UnauthorizedPasswordChangeTest(VampiTestCase):
    def test_user_can_change_own_password(self):
        res = self.client.put('/users/v1/name1/password', json={'password': 'newpass1'}, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 204)
        self.assertIn('auth_token', self.login('name1', 'newpass1'))

    def test_user_cannot_change_password_of_another_user(self):
        res = self.client.put('/users/v1/name2/password', json={'password': 'hacked'}, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 403)
        self.assertNotIn('auth_token', self.login('name2', 'hacked'))
        self.assertIn('auth_token', self.login('name2', 'pass2'))


class BookAuthorizationTest(VampiTestCase):
    def book_of(self, username):
        books = self.client.get('/books/v1').get_json()['Books']
        return next(book['book_title'] for book in books if book['user'] == username)

    def test_owner_can_read_own_book_secret(self):
        title = self.book_of('name1')
        res = self.client.get('/books/v1/' + title, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()['owner'], 'name1')

    def test_user_cannot_read_book_secret_of_another_user(self):
        title = self.book_of('name2')
        res = self.client.get('/books/v1/' + title, headers=self.auth('name1', 'pass1'))
        self.assertEqual(res.status_code, 404)
        self.assertNotIn('secret', res.get_json())


class MassAssignmentTest(VampiTestCase):
    def test_registration_cannot_grant_admin(self):
        res = self.client.post('/users/v1/register', json={
            'username': 'mallory', 'password': 'pw', 'email': 'mallory@mail.com', 'admin': True
        })
        self.assertEqual(res.status_code, 200)
        me = self.client.get('/me', headers=self.auth('mallory', 'pw')).get_json()
        self.assertFalse(me['data']['admin'])


if __name__ == '__main__':
    unittest.main()
