import os
from os import path
from unittest import TestCase
from utils import generate_keys_and_certificates

from cms_utility.cms import CMSTokenUtility

KEY_NAME = 'keystone_signing'
TEST_DIR = path.dirname(__file__)
SSL_DIR = path.join(TEST_DIR, 'ssl')


class CMSTest(TestCase):

    key_path = path.join(SSL_DIR, "{0}_key.pem".format(KEY_NAME))
    cert_path = path.join(SSL_DIR, "ca.pem")
    ca_cert_path = path.join(SSL_DIR, "ca.pem")

    @classmethod
    def setUpClass(cls):
    # Prepare key pair and cert files.
        if not path.exists(SSL_DIR):
            os.mkdir(SSL_DIR)
        if not path.exists(
                path.join(SSL_DIR, "{0}_cert.pem".format(KEY_NAME))):
            generate_keys_and_certificates(
                KEY_NAME,
                SSL_DIR
            )

    def test_sign_token(self):
        cms_token_util = CMSTokenUtility(
            path.join(SSL_DIR, '{0}_key.pem'.format(KEY_NAME)),
            path.join(SSL_DIR, '{0}_cert.pem'.format(KEY_NAME))
        )
        token = cms_token_util.sign_token(dict(name="keystone"))
        py_data = cms_token_util.verify_token(token)
        self.assertTrue('name' in py_data)
