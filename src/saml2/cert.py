__author__ = "haho0032"

import base64
from os import remove
from os.path import join
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _serialization
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
import cryptography.x509 as _x509

import saml2.cryptography.pki


# pyOpenSSL took an OpenSSL digest *name*; cryptography takes an instance. Only the
# algorithms OpenSSL would actually have accepted for a certificate signature are
# offered, and an unknown one is rejected rather than silently defaulted — the digest
# is part of what the signature means.
_HASH_ALGORITHMS = {
    "sha1": _hashes.SHA1,
    "sha224": _hashes.SHA224,
    "sha256": _hashes.SHA256,
    "sha384": _hashes.SHA384,
    "sha512": _hashes.SHA512,
}

# Attribute order matches the C/ST/L/O/OU/CN sequence the pyOpenSSL implementation
# built by assignment, so an existing caller's certificates keep the same subject DN.
_SUBJECT_FIELDS = (
    ("country_code", _x509.NameOID.COUNTRY_NAME),
    ("state", _x509.NameOID.STATE_OR_PROVINCE_NAME),
    ("city", _x509.NameOID.LOCALITY_NAME),
    ("organization", _x509.NameOID.ORGANIZATION_NAME),
    ("organization_unit", _x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
)


def _as_bytes(value):
    """PEM data reaches this module as `str` or `bytes` depending on the caller.

    `create_certificate` returns bytes, `create_cert_signed_certificate` returns str,
    and `read_str_from_file` returns bytes — so every loader here has always had to
    take both. pyOpenSSL's loaders did the coercion internally; cryptography's do not.
    """
    if value is None or isinstance(value, bytes):
        return value
    return value.encode("utf-8")


def _hash_algorithm(hash_alg):
    algorithm = _HASH_ALGORITHMS.get(str(hash_alg).lower().replace("-", "").replace("_", ""))
    if algorithm is None:
        raise WrongInput(f"Unsupported hash algorithm: {hash_alg!r}")
    return algorithm()


def _subject_name(cert_info, cn):
    if len(cert_info["country_code"]) != 2:
        raise WrongInput("Country code must be two letters!")
    attributes = [_x509.NameAttribute(oid, cert_info[key]) for key, oid in _SUBJECT_FIELDS]
    attributes.append(_x509.NameAttribute(_x509.NameOID.COMMON_NAME, cn))
    return _x509.Name(attributes)


def _validity_window(valid_from, valid_to):
    """`gmtime_adj_notBefore` / `gmtime_adj_notAfter` semantics: seconds from now."""
    now = datetime.now(timezone.utc)
    return now + timedelta(seconds=valid_from), now + timedelta(seconds=valid_to)


class WrongInput(Exception):
    pass


class CertificateError(Exception):
    pass


class PayloadError(Exception):
    pass


class OpenSSLWrapper:
    def __init__(self):
        pass

    def create_certificate(
        self,
        cert_info,
        request=False,
        valid_from=0,
        valid_to=315360000,
        sn=1,
        key_length=1024,
        hash_alg="sha256",
        write_to_file=False,
        cert_dir="",
        cipher_passphrase=None,
    ):
        """
        Can create certificate requests, to be signed later by another
        certificate with the method
        create_cert_signed_certificate. If request is True.

        Can also create self signed root certificates if request is False.
        This is default behaviour.

        :param cert_info:         Contains information about the certificate.
                                  Is a dictionary that must contain the keys:
                                  cn                = Common name. This part
                                  must match the host being authenticated
                                  country_code      = Two letter description
                                  of the country.
                                  state             = State
                                  city              = City
                                  organization      = Organization, can be a
                                  company name.
                                  organization_unit = A unit at the
                                  organization, can be a department.
                                  Example:
                                                    cert_info_ca = {
                                                        "cn": "company.com",
                                                        "country_code": "se",
                                                        "state": "AC",
                                                        "city": "Dorotea",
                                                        "organization":
                                                        "Company",
                                                        "organization_unit":
                                                        "Sales"
                                                    }
        :param request:           True if this is a request for certificate,
                                  that should be signed.
                                  False if this is a self signed certificate,
                                  root certificate.
        :param valid_from:        When the certificate starts to be valid.
                                  Amount of seconds from when the
                                  certificate is generated.
        :param valid_to:          How long the certificate will be valid from
                                  when it is generated.
                                  The value is in seconds. Default is
                                  315360000 seconds, a.k.a 10 years.
        :param sn:                Serial number for the certificate. Default
                                  is 1.
        :param key_length:        Length of the key to be generated. Defaults
                                  to 1024.
        :param hash_alg:          Hash algorithm to use for the key. Default
                                  is sha256.
        :param write_to_file:     True if you want to write the certificate
                                  to a file. The method will then return
                                  a tuple with path to certificate file and
                                  path to key file.
                                  False if you want to get the result as
                                  strings. The method will then return a tuple
                                  with the certificate string and the key as
                                  string.
                                  WILL OVERWRITE ALL EXISTING FILES WITHOUT
                                  ASKING!
        :param cert_dir:          Where to save the files if write_to_file is
                                  true.
        :param cipher_passphrase  A dictionary with cipher and passphrase.
        Example::
                {"cipher": "blowfish", "passphrase": "qwerty"}

        :return:                  string representation of certificate,
                                  string representation of private key
                                  if write_to_file parameter is False otherwise
                                  path to certificate file, path to private
                                  key file
        """
        cn = cert_info["cn"]

        c_f = None
        k_f = None

        if write_to_file:
            cert_file = f"{cn}.crt"
            key_file = f"{cn}.key"
            try:
                remove(cert_file)
            except Exception:
                pass
            try:
                remove(key_file)
            except Exception:
                pass
            c_f = join(cert_dir, cert_file)
            k_f = join(cert_dir, key_file)

        # create a key pair
        k = _rsa.generate_private_key(public_exponent=65537, key_size=key_length)

        subject = _subject_name(cert_info, cn)
        if request:
            builder = _x509.CertificateSigningRequestBuilder().subject_name(subject)
        else:
            # a self-signed cert
            not_before, not_after = _validity_window(valid_from, valid_to)
            builder = (
                _x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(k.public_key())
                .serial_number(sn)
                .not_valid_before(not_before)
                .not_valid_after(not_after)
            )
        cert = builder.sign(k, _hash_algorithm(hash_alg))

        try:
            tmp_cert = cert.public_bytes(_serialization.Encoding.PEM)
            tmp_key = None
            if cipher_passphrase is not None:
                passphrase = cipher_passphrase["passphrase"]
                if isinstance(cipher_passphrase["passphrase"], str):
                    passphrase = passphrase.encode("utf-8")
                # NOTE: `cipher_passphrase["cipher"]` is no longer honoured. pyOpenSSL
                # took an OpenSSL cipher name here; cryptography exposes no way to
                # choose the PEM encryption cipher, only `BestAvailableEncryption`.
                # The passphrase still applies and the output is still a PKCS#8
                # "ENCRYPTED PRIVATE KEY", so callers and `create_cert_signed_certificate`
                # are unaffected — but a caller asking for a specific legacy cipher now
                # gets AES-256-CBC instead. The documented example, "blowfish", is not
                # even reachable in OpenSSL 3's default provider, so nothing that worked
                # stops working.
                encryption = _serialization.BestAvailableEncryption(passphrase)
            else:
                encryption = _serialization.NoEncryption()
            tmp_key = k.private_bytes(
                _serialization.Encoding.PEM,
                # PKCS#8, matching what `dump_privatekey(FILETYPE_PEM, ...)` emitted
                # against OpenSSL 3: "BEGIN PRIVATE KEY" / "BEGIN ENCRYPTED PRIVATE KEY".
                _serialization.PrivateFormat.PKCS8,
                encryption,
            )
            if write_to_file:
                with open(c_f, "w") as fc:
                    fc.write(tmp_cert.decode("utf-8"))
                with open(k_f, "w") as fk:
                    fk.write(tmp_key.decode("utf-8"))
                return c_f, k_f
            return tmp_cert, tmp_key
        except Exception as ex:
            raise CertificateError("Certificate cannot be generated.", ex)

    def write_str_to_file(self, file, str_data):
        with open(file, "w") as f:
            f.write(str_data)

    def read_str_from_file(self, file, type="pem"):
        with open(file, "rb") as f:
            str_data = f.read()

        if type == "pem":
            return str_data

        if type in ["der", "cer", "crt"]:
            return base64.b64encode(str(str_data))

    def create_cert_signed_certificate(
        self,
        sign_cert_str,
        sign_key_str,
        request_cert_str,
        hash_alg="sha256",
        valid_from=0,
        valid_to=315360000,
        sn=1,
        passphrase=None,
    ):

        """
        Will sign a certificate request with a give certificate.
        :param sign_cert_str:     This certificate will be used to sign with.
                                  Must be a string representation of
                                  the certificate. If you only have a file
                                  use the method read_str_from_file to
                                  get a string representation.
        :param sign_key_str:        This is the key for the ca_cert_str
                                  represented as a string.
                                  If you only have a file use the method
                                  read_str_from_file to get a string
                                  representation.
        :param request_cert_str:  This is the prepared certificate to be
                                  signed. Must be a string representation of
                                  the requested certificate. If you only have
                                  a file use the method read_str_from_file
                                  to get a string representation.
        :param hash_alg:          Hash algorithm to use for the key. Default
                                  is sha256.
        :param valid_from:        When the certificate starts to be valid.
                                  Amount of seconds from when the
                                  certificate is generated.
        :param valid_to:          How long the certificate will be valid from
                                  when it is generated.
                                  The value is in seconds. Default is
                                  315360000 seconds, a.k.a 10 years.
        :param sn:                Serial number for the certificate. Default
                                  is 1.
        :param passphrase:        Password for the private key in sign_key_str.
        :return:                  String representation of the signed
                                  certificate.
        """
        ca_cert = _x509.load_pem_x509_certificate(_as_bytes(sign_cert_str))
        # `load_pem_private_key` takes password=None for an unencrypted key, so the
        # two pyOpenSSL call shapes collapse into one. A wrong passphrase raises
        # ValueError here, as `load_privatekey` raised crypto.Error before.
        ca_key = _serialization.load_pem_private_key(_as_bytes(sign_key_str), password=_as_bytes(passphrase))
        req_cert = _x509.load_pem_x509_csr(_as_bytes(request_cert_str))

        not_before, not_after = _validity_window(valid_from, valid_to)
        cert = (
            _x509.CertificateBuilder()
            .subject_name(req_cert.subject)
            .issuer_name(ca_cert.subject)
            .public_key(req_cert.public_key())
            .serial_number(sn)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(ca_key, _hash_algorithm(hash_alg))
        )

        return cert.public_bytes(_serialization.Encoding.PEM).decode("utf-8")

    def verify_chain(self, cert_chain_str_list, cert_str):
        """

        :param cert_chain_str_list: Must be a list of certificate strings,
        where the first certificate to be validate
        is in the beginning and the root certificate is last.
        :param cert_str: The certificate to be validated.
        :return:
        """
        for tmp_cert_str in cert_chain_str_list:
            valid, message = self.verify(tmp_cert_str, cert_str)
            if not valid:
                return False, message
            else:
                cert_str = tmp_cert_str
            return (True, "Signed certificate is valid and correctly signed by CA " "certificate.")

    def verify(self, signing_cert_str, cert_str):
        """
        Verifies if a certificate is valid and signed by a given certificate.

        :param signing_cert_str: This certificate will be used to verify the
                                  signature. Must be a string representation
                                 of the certificate. If you only have a file
                                 use the method read_str_from_file to
                                 get a string representation.
        :param cert_str:         This certificate will be verified if it is
                                  correct. Must be a string representation
                                 of the certificate. If you only have a file
                                 use the method read_str_from_file to
                                 get a string representation.
        :return:                 Valid, Message
                                 Valid = True if the certificate is valid,
                                 otherwise false.
                                 Message = Why the validation failed.
        """
        try:
            cert_str_bytes = cert_str if isinstance(cert_str, bytes) else cert_str.encode("ascii")
            signing_cert_bytes = (
                signing_cert_str if isinstance(signing_cert_str, bytes) else signing_cert_str.encode("ascii")
            )

            cert_crypto = saml2.cryptography.pki.load_pem_x509_certificate(cert_str_bytes)
            ca_cert_crypto = saml2.cryptography.pki.load_pem_x509_certificate(signing_cert_bytes)

            now = datetime.now(timezone.utc)

            if now < ca_cert_crypto.not_valid_before_utc:
                return False, "CA certificate is not valid yet."

            if now >= ca_cert_crypto.not_valid_after_utc:
                return False, "CA certificate is expired."

            if now >= cert_crypto.not_valid_after_utc:
                return False, "The signed certificate is expired."

            if now < cert_crypto.not_valid_before_utc:
                return False, "The signed certificate is not valid yet."

            ca_cn = ca_cert_crypto.subject.get_attributes_for_oid(_x509.NameOID.COMMON_NAME)
            cert_cn = cert_crypto.subject.get_attributes_for_oid(_x509.NameOID.COMMON_NAME)
            if ca_cn and cert_cn and ca_cn[0].value == cert_cn[0].value:
                return False, "CN may not be equal for CA certificate and the signed certificate."

            if cert_crypto.signature_hash_algorithm is None:
                return False, "Unsupported signature algorithm (no hash algorithm present)."

            ca_public_key = ca_cert_crypto.public_key()

            try:
                if isinstance(ca_public_key, _rsa.RSAPublicKey):
                    ca_public_key.verify(
                        cert_crypto.signature,
                        cert_crypto.tbs_certificate_bytes,
                        _padding.PKCS1v15(),
                        cert_crypto.signature_hash_algorithm,
                    )
                elif isinstance(ca_public_key, _ec.EllipticCurvePublicKey):
                    ca_public_key.verify(
                        cert_crypto.signature,
                        cert_crypto.tbs_certificate_bytes,
                        _ec.ECDSA(cert_crypto.signature_hash_algorithm),
                    )
                else:
                    return False, f"Unsupported public key type: {type(ca_public_key)}"
                return True, "Signed certificate is valid and correctly signed by CA certificate."
            except InvalidSignature as e:
                return False, f"Certificate is incorrectly signed: {str(e)}"
        except Exception as e:
            return False, f"Certificate is not valid for an unknown reason. {str(e)}"


def read_cert_from_file(cert_file, cert_type="pem"):
    """Read a certificate from a file.

    If there are multiple certificates in the file, the first is returned.

    :param cert_file: The name of the file
    :param cert_type: The certificate type
    :return: A base64 encoded certificate as a string or the empty string
    """
    if not cert_file:
        return ""

    with open(cert_file, "rb") as fp:
        data = fp.read()

    try:
        cert = saml2.cryptography.pki.load_x509_certificate(data, cert_type)
        pem_data = saml2.cryptography.pki.get_public_bytes_from_cert(cert)
    except Exception as e:
        raise CertificateError(e)

    pem_data_no_headers = "".join(pem_data.splitlines()[1:-1])
    return pem_data_no_headers
