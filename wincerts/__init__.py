import asn1crypto.x509
from ctypes import cast, c_void_p, pointer, POINTER, string_at, WinDLL
from ctypes.wintypes import BOOL, BYTE, DWORD, LPWSTR, PULONG
from enum import Enum
from typing import List, Tuple, Generator, Set
import OpenSSL.crypto
import OpenSSL.SSL
import pyasn1.codec.der.encoder
import pyasn1.type.univ
import wincertstore
from wincertstore import PCCERT_CONTEXT


__all__ = [
    'KeyUsage',
    'PKCS12Ext',
    'CertStore',
]

# load DLLs
crypt32 = WinDLL('crypt32.dll')
advapi32 = WinDLL('advapi32.dll')


# Values for dword constant found here:
# https://referencesource.microsoft.com/#System/security
# /system/security/cryptography/cryptoapi.cs

# C constants
AT_KEYEXCHANGE = DWORD(1)
AT_SIGNATURE = DWORD(2)
CERT_FRIENDLY_NAME_PROP_ID = DWORD(11)
CRYPT_ACQUIRE_CACHE_FLAG = DWORD(1)
CRYPT_ACQUIRE_COMPARE_KEY_FLAG = DWORD(4)
CRYPT_BOTH_FLAG = DWORD(5)
PRIVATEKEYBLOB = DWORD(7)

# C Types
HCRYPTKEY = PULONG
HCRYPTPROV = PULONG

# C Functions
CryptGetUserKey = advapi32.CryptGetUserKey
CryptGetUserKey.restype = BOOL
CryptGetUserKey.argtypes = [
    HCRYPTPROV, DWORD, POINTER(HCRYPTKEY),
]

CryptExportKey = advapi32.CryptExportKey
CryptExportKey.restype = BOOL
CryptExportKey.argtypes = [
    HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, POINTER(BYTE), POINTER(DWORD),
]

CryptAcquireCertPrivKey = crypt32.CryptAcquireCertificatePrivateKey
CryptAcquireCertPrivKey.restype = BOOL
CryptAcquireCertPrivKey.argtypes = [
    PCCERT_CONTEXT, DWORD, c_void_p, POINTER(HCRYPTPROV), POINTER(DWORD), POINTER(BOOL),
]

CertGetCertCtxProp = crypt32.CertGetCertificateContextProperty
CertGetCertCtxProp.restype = BOOL
CertGetCertCtxProp.argtypes = [
    PCCERT_CONTEXT, DWORD, c_void_p, POINTER(DWORD),
]

CertGetNameStringW = crypt32.CertGetNameStringW
CertGetNameStringW.restype = DWORD
CertGetNameStringW.argtypes = [
    PCCERT_CONTEXT, DWORD, DWORD, c_void_p, LPWSTR, DWORD,
]


class KeyUsage(Enum):
    digital_signature = 'digitalSignature'
    content_commitment = 'nonRepudiation'
    key_encipherment = 'keyEncipherment'
    data_encipherment = 'dataEncipherment'
    key_agreement = 'keyAgreement'
    key_cert_sign = 'keyCertSign'
    crl_sign = 'cRLSign'
    encipher_only = 'encipherOnly'
    decipher_only = 'decipherOnly'



class PKCS12Ext(OpenSSL.crypto.PKCS12):
    """
    Extension of the OpenSSL PKCS12 class with helper methods.
    """
    def __init__(self,
                 public_key_cert: bytes,
                 private_key: bytes = b'',
                 friendly_name: str = '',
                 ) -> None:
        """
        Creates a PKCS12 archive using a public key certificate and optional
        private key and friendly name.

        args:
            public_key_cert - (bytes) the bytes of ASN.1 public key certificate.
            private_key - (bytes) the bytes of the ASN.1 private key.
            friendly_name - (str) friendly name for the public key certificate.
        """
        super().__init__()
        if friendly_name:
            self.set_friendlyname(friendly_name.encode('utf8'))
        if public_key_cert:
            x509_cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_ASN1,
                public_key_cert
            )
            self.set_certificate(x509_cert)
        if private_key:
            pkey_object = OpenSSL.crypto.load_privatekey(
                OpenSSL.crypto.FILETYPE_ASN1,
                private_key
            )
            self.set_privatekey(pkey_object)

    def __repr__(self) -> str:
        n = self.__class__.__name__
        fn = self.get_friendlyname()
        i = self.cert_issuer
        e = self.cert_expired
        k = self.has_private_key
        repr_ = (
            f'<{n} friendly_name={fn!r}, expired={e}, '
            f'has_private_key={k}, cert_issuer={i!r}>'
        )
        return repr_

    @property
    def cert_expired(self) -> bool:
        return self.get_certificate().has_expired()

    @property
    def cert_issuer(self) -> str:
        """
        Returns the common name of the issuer of the certificate.
        """
        for k, v in self.get_certificate().get_issuer().get_components():
            if k == b'CN':
                return v.decode('utf-8')
        return '<issuer-name-missing>'

    @property
    def cert_subject(self) -> str:
        # components are stored in reverse in the windows store compared to
        # they typically appear.  compensate by reversing the order
        components = [
            (k.decode('utf-8'), v.decode('utf-8')) for k, v in
            reversed(self.get_certificate().get_subject().get_components())
        ]
        return ','.join(f'{k}={v}' for k, v in components)

    @property
    def has_private_key(self) -> bool:
        return bool(self.get_privatekey())

    def cert_keyusages(self) -> Set[str]:
        """
        Returns a set of key usage flags for the certificate.
        """
        cert = self.get_certificate()
        for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            if ext.get_short_name() == b'keyUsage':
                break
        else:
            return set()
        flags = asn1crypto.x509.KeyUsage.load(ext.get_data()).native
        return {KeyUsage(f).value for f in flags}

    def create_ssl_context(self,
                           tls_method: int = OpenSSL.SSL.TLS_CLIENT_METHOD,
                           ) -> OpenSSL.SSL.Context:
        """
        Create an OpenSSL SSL/TLS context using the public key certificate
        and private key.

        args:
            tls_method: (int) one of OpenSSL.SSL.TLS_CLIENT_METHOD,
                OpenSSL.SSL.TLS_SERVER_METHOD, or OpenSSL.SSL.TLS_METHOD.
        """
        if not self.has_private_key:
            raise ValueError('Private key required to create an SSL Context.')

        ssl_ctx = OpenSSL.SSL.Context(tls_method)
        ssl_ctx.use_certificate(self.get_certificate())
        ssl_ctx.use_privatekey(self.get_privatekey())
        return ssl_ctx


class CertStore(wincertstore.CertSystemStore):
    """
    Subclass of the wincertstore.CertSystemStore that provides additional
    methods.
    """

    def __init__(self, storename: str):
        self.certs: List[Tuple[str]]
        super().__init__(storename)

    def iter_store_certs(self) -> Generator[PKCS12Ext, None, None]:
        """
        Iterates over all certificate objects in this Windows Certificates
        Store.
        """
        cert_ctx_pointer = wincertstore.CertEnumCertificatesInStore(self._hStore, None)

        while cert_ctx_pointer:
            cert_ctx = cert_ctx_pointer[0]
            # name = self._get_display_name(cert_ctx)
            friendly_name = self._get_friendly_name(cert_ctx)
            public_key_cert = cert_ctx.get_encoded()
            private_key = self._get_private_key(cert_ctx)

            yield PKCS12Ext(public_key_cert, private_key, friendly_name)

            cert_ctx_pointer = wincertstore.CertEnumCertificatesInStore(
                self._hStore,
                cert_ctx_pointer,
            )

    @staticmethod
    def _get_display_name(cert_ctx) -> str:
        """
        Returns the dispaly name of a certificate context.
        """
        type_ = wincertstore.CERT_NAME_SIMPLE_DIPLAY_TYPE
        cbsize = CertGetNameStringW(cert_ctx, type_, 0, None, None, 0)
        buf = wincertstore.create_unicode_buffer(cbsize)
        cbsize = CertGetNameStringW(cert_ctx, type_, 0, None, buf, cbsize)
        return buf.value

    @staticmethod
    def _get_friendly_name(cert_ctx) -> str:
        """
        Returns the friendly name of a certificate context.
        """
        size = pointer(DWORD())
        # update the size
        CertGetCertCtxProp(cert_ctx, CERT_FRIENDLY_NAME_PROP_ID, None, size)
        # push the utf16 friendly name to the buffer
        buf = cast(pointer((BYTE * size[0])()), c_void_p)
        CertGetCertCtxProp(cert_ctx, CERT_FRIENDLY_NAME_PROP_ID, buf, size)
        name = string_at(buf, size[0]).decode('utf16')
        return name

    def _get_private_key(self, cert_ctx) -> bytes:
        """
        Retrieves the private key from the certificate context if it is
        available.

        Returns the bytes to the PKCS#8 private key.
        """
        h_prov = HCRYPTPROV()
        h_key = pointer(HCRYPTKEY())
        key_size = pointer(DWORD())
        key_spec = AT_KEYEXCHANGE

        # update the crypographic provider handle
        CryptAcquireCertPrivKey(
            cert_ctx,
            CRYPT_BOTH_FLAG,
            None,
            h_prov,
            key_spec,
            None
        )

        # update the handle to the key
        CryptGetUserKey(h_prov, key_spec, h_key)

        # update the size
        CryptExportKey(h_key[0], None, PRIVATEKEYBLOB, DWORD(), None, key_size)

        # push to the private key blob buffer
        privkey_blob = cast(pointer((BYTE * key_size[0])()), POINTER(BYTE))
        CryptExportKey(
            h_key[0],
            None,
            PRIVATEKEYBLOB,
            DWORD(),
            privkey_blob,
            key_size
        )

        privkey_blob_bytes = string_at(privkey_blob, key_size[0])

        # this always has a leading 8 bytes of b'\x07\x02\x00\x00\x00\xa4\x00\x00'
        # might be an OID tag?
        pkcs8_bytes = self._win_privkeyblob_to_pkcs8(privkey_blob_bytes)
        return pkcs8_bytes

    @staticmethod
    def _win_privkeyblob_to_pkcs8(private_key_blob: bytes, rsa_size: int=2048) -> bytes:
        """
        Converts a private key bytes stored using Windows PRIVATEKEYBLOB format to
        PKCS#8 format.
        """
        # Windows PRIVATEKEYBLOB using RSA 2048-bit encoding have the following
        # indices: (0, 4, 8, 12, 268, 396, 524, 652, 780, 908, 1164)
        # associated to the following values:
        #   [   0:    4 ] rsa2 - the bytes b'RSA2'
        #   [   4:    8 ] s    - RSA size
        #   [   8:   12 ] pe   - public exponent
        #   [  12:  268 ] m    - modulus
        #   [ 268:  396 ] p1   - prime factor 1
        #   [ 396:  524 ] p2   - prime factor 2
        #   [ 524:  652 ] e1   - exponent 1
        #   [ 652:  780 ] e2   - exponent 2
        #   [ 780:  908 ] c    - coefficient
        #   [ 908: 1164 ] e    - private exponent

        if rsa_size == 2048:
            indices = (0, 4, 8, 12, 268, 396, 524, 652, 780, 908, 1164)
        else:
            raise NotImplementedError('Only RSA 2048 is currently available.')

        _, _, pe, m, p1, p2, e1, e2, c, e = [
            private_key_blob[ix1: ix2] for ix1, ix2 in zip(indices, indices[1:])
        ]

        if not m:
            return b''

        der_components = [
            int(bytes(reversed(b)).hex(), 16)
            for b in (b'\x00', m, pe, e, p1, p2, e1, e2, c)
        ]

        seq = pyasn1.type.univ.Sequence()
        for i, component in enumerate(der_components):
            seq.setComponentByPosition(i, pyasn1.type.univ.Integer(component))

        der_bytes = pyasn1.codec.der.encoder.encode(seq)
        return der_bytes
