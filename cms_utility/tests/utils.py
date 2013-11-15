import os
from os import path
from subprocess import Popen, PIPE
import logging
import shutil


LOG = logging.getLogger(__name__)


def find_openssl_bin():
    openssl_bins = []
    for bin_path in os.environ['PATH'].split(path.pathsep):
        if 'openssl' in os.listdir(bin_path):
            LOG.debug("Found openssl bin in {0}.".format(bin_path))
            openssl_cmd = [path.join(bin_path, 'openssl'), 'version']
            openssl_proc = Popen(openssl_cmd, stdout=PIPE, stderr=PIPE)
            # check openssl version, require 1.0.0 and above
            std_out, err_out = openssl_proc.communicate()
            return_code = openssl_proc.poll()
            if return_code != 0:
                LOG.warn(("Failed to get openssl version. Return code:"
                          "{0}. Message: {1}".format(return_code, err_out)))
            else:
                if std_out[:9] >= 'OpenSSL 1':
                    openssl_bins.append(path.join(bin_path, 'openssl'))
                else:
                    LOG.warn("OpenSSL version is too old: {0}".format(
                        std_out.strip()
                    ))
    if len(openssl_bins) > 0:
        return openssl_bins[0]
    else:
        return None

OPENSSL_BIN = find_openssl_bin()


def _openssl_cmd(cmd):
    openssl_process = Popen(cmd,
                            stdin=PIPE,
                            stdout=PIPE,
                            stderr=PIPE)
    std_out, std_err = openssl_process.communicate()
    return_code = openssl_process.poll()
    if return_code != 0:
        LOG.error((
            "Run openssl command error:\nCommand: {0}"
            "Error message: {1}"
            "Return code: {2}".format(
                str(cmd), std_err, return_code)))
        raise Exception("Run command error: {0}".format(
            str(cmd)
        ))


def token_to_cms(signed_text):
    """
    Add begin/end line and reorganize line length.
    This code is from 'keystone/common/cms.py'.
    """
    copy_of_text = signed_text.replace('-', '/')

    formatted = "-----BEGIN CMS-----\n"
    line_length = 64
    while len(copy_of_text) > 0:
        if len(copy_of_text) > line_length:
            formatted += copy_of_text[:line_length]
            copy_of_text = copy_of_text[line_length:]
        else:
            formatted += copy_of_text
            copy_of_text = ""
        formatted += "\n"

    formatted += "-----END CMS-----\n"

    return formatted


KEY_SIZE = 2048
RSA_PUBLIC_EXPONENT = 65537


def generate_keys_and_certificates(key_name, ca_dir):
    """
    Generate CA key, CA certificate, signing key and
    signing certificate.
    """
    # initialize CA
    if not path.exists(ca_dir):
        os.mkdir(ca_dir)
    pwd_dir = path.dirname(__file__)
    shutil.copy(path.join(pwd_dir, 'openssl.conf'),
                path.join(ca_dir, 'openssl.conf'))
    with open(path.join(ca_dir, 'serial'), 'w') as serial_file:
        serial_file.write('01')
    with open(path.join(ca_dir, 'index.txt'), 'w') as index_file:
        index_file.write('')

    openssl_bin = find_openssl_bin()
    # generate CA key pair
    openssl_cmd = [openssl_bin, 'genrsa', '-out',
                   path.join(ca_dir, 'cakey.pem'),
                   '1024', '-config',
                   path.join(ca_dir, 'openssl.conf')]
    _openssl_cmd(openssl_cmd)

    # generate self signing CA certificate
    openssl_cmd = [openssl_bin, 'req', '-new',
                   '-x509', '-extensions', 'v3_ca',
                   '-passin', 'pass:None', '-key',
                   path.join(ca_dir, 'cakey.pem'),
                   '-out',
                   path.join(ca_dir, 'ca.pem'),
                   '-days', '3650', '-config',
                   path.join(ca_dir, 'openssl.conf'),
                   '-subj',
                   '/C=US/ST=Unset/L=Unset/O=Unset/CN=www.example.com']
    _openssl_cmd(openssl_cmd)

    # generate signing key
    openssl_cmd = [openssl_bin, 'genrsa', '-out',
                   path.join(ca_dir, '{0}_key.pem'.format(key_name)),
                   '1024', '-config',
                   path.join(ca_dir, 'openssl.conf')]
    _openssl_cmd(openssl_cmd)

    # generate signing certificate request
    openssl_cmd = [
        openssl_bin, 'req', '-key',
        path.join(ca_dir, '{0}_key.pem'.format(key_name)),
        '-new', '-nodes', '-out',
        path.join(ca_dir, 'req.pem'), '-config',
        path.join(ca_dir, 'openssl.conf'), '-subj',
        '/C=US/ST=Unset/L=Unset/O=Unset/CN=www.example.com'
    ]
    _openssl_cmd(openssl_cmd)

    # generate signing certificate
    openssl_cmd = [
        openssl_bin, 'ca', '-batch',
        '-out', path.join(ca_dir, '{0}_cert.pem'.format(key_name)),
        '-config', path.join(ca_dir, 'openssl.conf'),
        '-days', '3650', '-cert',
        path.join(ca_dir, 'ca.pem'), '-keyfile',
        path.join(ca_dir, 'cakey.pem'),
        '-infiles', path.join(ca_dir, 'req.pem')
    ]
    _openssl_cmd(openssl_cmd)


def repeat_sign_and_verify_token(token, key_path, cert_path, repeat_cnt):
    from cms_utility.cms import CMSTokenUtility
    cms_util = CMSTokenUtility(key_path, cert_path)
    while repeat_cnt > 0:
        signed_token = cms_util.sign_token(token)
        token = cms_util.verify_token(signed_token)
        repeat_cnt -= 1


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    logger.addHandler(ch)
    print find_openssl_bin()
