import sys
from os import path
import datetime
import json
from keystone_cms import cms_sign_token, verify_token

# add sys path
sys.path.insert(0, path.dirname(path.dirname(path.dirname(path.abspath(
    __file__)))))

TOKEN_DATA = {
    "access": {"token":
               {
                   "issued_at": "2013-10-15T13:36:40.632711",
                   "expires": "2013-10-16T13:36:40Z", "id": "placeholder"
               },
               "serviceCatalog": [],
               "user": {"username": "admin",
                        "roles_links": [],
                        "id": "616404ea6a484afb92559811ae9e45f0",
                        "roles": [], "name": "admin"}}}


def repeat_keystone_cms_token(token,
                              key_path,
                              cert_path,
                              ca_path,
                              repeat_cnt, logger):
    while repeat_cnt > 0:
        text_token = json.dumps(token)
        signed_token = cms_sign_token(text_token, cert_path, key_path, logger)
        verify_token(signed_token, cert_path, ca_path, logger)
        repeat_cnt -= 1


def main():
    from utils import repeat_sign_and_verify_token
    cur_dir = path.dirname(__file__)
    start_time = datetime.datetime.now()
    repeat_sign_and_verify_token(
        TOKEN_DATA,
        path.join(cur_dir, 'ssl', 'keystone_signing_key.pem'),
        path.join(cur_dir, 'ssl', 'keystone_signing_cert.pem'),
        5000
    )
    end_time = datetime.datetime.now()
    print "Time used: {0}".format(end_time - start_time)

    logger = logging.getLogger()
    start_time = datetime.datetime.now()
    repeat_keystone_cms_token(
        TOKEN_DATA,
        path.join(cur_dir, 'ssl', 'keystone_signing_key.pem'),
        path.join(cur_dir, 'ssl', 'keystone_signing_cert.pem'),
        path.join(cur_dir, 'ssl', 'ca.pem'),
        5000,
        logger
    )
    end_time = datetime.datetime.now()
    print "Time used: {0}".format(end_time - start_time)


if __name__ == '__main__':
    import logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)
    main()
