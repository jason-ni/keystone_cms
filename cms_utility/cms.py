from base64 import b64decode, b64encode
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ, tag
from pyasn1_modules import rfc2315, rfc2437, rfc2459
import json
import M2Crypto
import hashlib
from logging import getLogger

LOG = getLogger(__name__)


class CMSDataError(Exception):
    pass


class ContentData(univ.OctetString):
    tagSet = univ.Any.tagSet.tagExplicitly(
        tag.Tag(
            tag.tagClassContext,
            tag.tagFormatSimple,
            0
        )
    )


class ASN1CMSWrapper(object):

    def __init__(self, logger=None):
        if logger is None:
            self.logger = LOG
        else:
            self.logger = logger
        self.asn1_cms_data = None
        self.signed_data = None

    @classmethod
    def from_base64_token(cls, base64_token, logger=None):
        """
        Parse a base64 encoded token and construct a ASN1CMSWrapper object.
        :param base64_token: (required) Base64 encoded token data.
        :param logger: (optional) Logger.
        :return `ASN1CMSWrapper` instance.
        """
        if logger is None:
            logger = getLogger(name='py_cms')
        asn1_cms_data, unprocessed = decoder.decode(
            b64decode(base64_token.replace('-', '/')),
            asn1Spec=rfc2315.ContentInfo()
        )
        if len(unprocessed) != 0:
            logger.error("Token is invalid: {0}".format(base64_token))
            raise CMSDataError("Token content is invalid.")
        content_type = asn1_cms_data.getComponentByName('contentType')

        # Here we only handle signedData.
        if content_type != rfc2315.signedData:
            logger.error(
                "Token content type is not SingedData: {0}".format(
                    base64_token))
            logger.error("Token is invalid: {0}".format(base64_token))
            raise CMSDataError(
                "ContentType{0} is not SignedData.".format(
                    str(content_type.asTuple())
                )
            )
        cms_obj = cls(logger)
        cms_obj.asn1_cms_data = asn1_cms_data
        cms_obj.signed_data, unprocessed = decoder.decode(
            asn1_cms_data.getComponentByName('content'),
            asn1Spec=rfc2315.SignedData()
        )
        if len(unprocessed) != 0:
            LOG.error("Token content type correct, but content invalid.")
            LOG.error("Token data: {0}".format(base64_token))
            raise CMSDataError("Token content is invalid.")
        return cms_obj

    def get_data(self, is_json=False):
        """
        :return The data that had been signed.
        """
        content_info = self.signed_data.getComponentByName('contentInfo')
        content_type = content_info.getComponentByName('contentType')
        if content_type != rfc2315.data:
            msg = "Content type is not data: {0}".format(
                str(content_type.asTuple())
            )
            self.logger.error(msg)
            raise CMSDataError(msg)
        content = content_info.getComponentByName('content')

        oct_data, unprocessed = decoder.decode(content, univ.OctetString())
        if len(unprocessed) != 0:
            msg = "Content parsing error. Data: {0}".format(
                str(content)
            )
            self.logger.error(msg)
            raise CMSDataError(msg)
        if is_json:
            # parse oct_data as json data.
            return json.loads(oct_data.asOctets())
        else:
            return oct_data.asOctets()

    def get_signer_infors(self):
        """
        Get the SignerInfo sequence.
        :return Sequence of SignerInfo instances.
        """
        return self.signed_data.getComponentByName('signerInfos')

    def get_signer_info(self):
        """
        Get the first SignerInfo record. (There's only one signer
        in the token signing process.)
        :return The first SignerInfo instance.
        """
        return self.get_signer_infors().getComponentByPosition(0)

    def get_signature(self):
        """
        Get the signature that can be used by M2Crypto.RSA.verify method.
        :return The der encoding signature.
        """
        signer_info = self.get_signer_info()
        digest_algorithm = signer_info.getComponentByName('digestAlgorithm')
        if (digest_algorithm.getComponentByName('algorithm') !=
                rfc2437.id_sha1):
            msg = "Digest algorithm is not supported: {0}.".format(
                str(digest_algorithm)
            )
            self.logger.error(msg)
            raise CMSDataError(msg)
        encrypted_digest = signer_info.getComponentByName('encryptedDigest')
        return encrypted_digest.asOctets()

    @classmethod
    def generate_token(cls, message, signature, issuer, serial_number):
        cms = rfc2315.ContentInfo()
        cms.setComponentByName('contentType', rfc2315.signedData)

        signed_data = rfc2315.SignedData()
        signed_data.setComponentByName('version', univ.Integer(1))
        digest_algos = rfc2315.DigestAlgorithmIdentifiers()
        digest_algo_id = rfc2315.DigestAlgorithmIdentifier()
        digest_algo_id.setComponentByName(
            'algorithm',
            rfc2437.id_sha1
        )
        digest_algos.setComponentByPosition(0, digest_algo_id)
        signed_data.setComponentByName('digestAlgorithms', digest_algos)
        content_info = rfc2315.ContentInfo()
        content_info.setComponentByName('contentType', rfc2315.data)
        content_octet_str = univ.OctetString(message)
        content_data = ContentData(encoder.encode(content_octet_str))
        content_info.setComponentByName(
            'content',
            content_data
        )
        signed_data.setComponentByName('contentInfo', content_info)
        signer_info_seq = rfc2315.SignerInfos()
        signer_info = rfc2315.SignerInfo()
        signer_info.setComponentByName('version', univ.Integer(1))
        issuer_and_serial_number = rfc2315.IssuerAndSerialNumber()
        issuer_and_serial_number.setComponentByName('issuer', issuer)
        issuer_and_serial_number.setComponentByName(
            'serialNumber',
            serial_number
        )
        signer_info.setComponentByName(
            'issuerAndSerialNumber',
            issuer_and_serial_number
        )
        signer_info.setComponentByName(
            'digestAlgorithm',
            digest_algo_id
        )
        digest_encrypt_algo_id = rfc2315.DigestEncryptionAlgorithmIdentifier()
        digest_encrypt_algo_id.setComponentByName(
            'algorithm',
            rfc2437.rsaEncryption
        )
        digest_encrypt_algo_id.setComponentByName(
            'parameters',
            univ.Any(bytes('\05\00'))
        )
        signer_info.setComponentByName(
            'digestEncryptionAlgorithm',
            digest_encrypt_algo_id
        )

        encrypted_digest = rfc2315.EncryptedDigest(signature)
        signer_info.setComponentByName('encryptedDigest', encrypted_digest)
        signer_info_seq.setComponentByPosition(0, signer_info)
        signed_data.setComponentByName('signerInfos', signer_info_seq)
        content_data = ContentData(encoder.encode(signed_data))
        cms.setComponentByName('content', content_data, verifyConstraints=False)
        return b64encode(encoder.encode(cms))


class CMSRSAError(Exception):
    pass


class CMSRSABadSignature(Exception):
    pass


class CMSTokenUtility(object):

    def __init__(self, private_key_path, certificate_path, logger=None):
        if logger is None:
            self.logger = getLogger('py_cms')
        else:
            self.logger = logger

        self.rsa_private_key = M2Crypto.RSA.load_key(private_key_path)
        self._cert = M2Crypto.X509.load_cert(certificate_path)
        self.rsa_pub_key = self._cert.get_pubkey().get_rsa()

        self._issuer = None
        self._cert_serial_number = None
        self._parse_cert(self._cert.as_der())

    def _parse_cert(self, der_cert):
        cert, uncompressed = decoder.decode(der_cert, asn1Spec=rfc2459.Certificate())
        if len(uncompressed) != 0:
            raise CMSDataError("Parse certificate error.")
        _tbs_cert = cert.getComponentByName('tbsCertificate')
        self._issuer = _tbs_cert.getComponentByName('issuer')
        self._cert_serial_number = _tbs_cert.getComponentByName('serialNumber')
        return cert

    def _verify(self, message, signature, algo='sha1'):
        if algo == 'sha1':
            msg_digest = hashlib.sha1(message).digest()
        else:
            msg = "Not supported digest algorithm: {0}.".format(algo)
            self.logger.error(msg)
            raise CMSRSAError(msg)
        try:
            self.rsa_pub_key.verify(msg_digest, signature, algo=algo)
        except M2Crypto.RSA.RSAError as err:
            self.logger.warning("Bad signature.")
            self.logger.debug("Message: {0}".format(message))
            self.logger.debug("signature: {0}".format(signature.encode('hex')))
            raise CMSRSABadSignature(str(err))
        return message

    def verify_token(self, base64_token):
        """
        Verify the base64 encoded token.
        :param base64_token: Base64 encoded token.
        :raise CMSRSABadSignature
        """
        self.logger.debug("Verifying token: {0}".format(base64_token))
        cms = ASN1CMSWrapper.from_base64_token(base64_token)
        return json.loads(self._verify(cms.get_data(), cms.get_signature()))

    def _sign(self, json_data):
        message = json.dumps(json_data)
        digest_msg = hashlib.sha1(message).digest()
        signature = self.rsa_private_key.sign(digest_msg, algo='sha1')
        return message, signature

    def sign_token(self, py_data):
        message, signature = self._sign(py_data)

        # construct CMS ContentInfo record
        return ASN1CMSWrapper.generate_token(
            message,
            signature,
            self._issuer,
            self._cert_serial_number
        )
