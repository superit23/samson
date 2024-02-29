from samson.encoding.openssh.core import PrivateKeyContainer, OpenSSHPrivateHeader, OpenSSHPrivateKey, KDFParams, S, optional_kdf_params, PublicPrivatePair, PublicKey
from samson.encoding.pem import pem_encode
from samson.encoding.general import PKIEncoding
from samson.utilities.bytes import Bytes
import base64
from types import FunctionType


def check_decrypt(params: bytes, decryptor: FunctionType) -> (bytes, bytes):
    """
    Performs an optional decryption and checks the "check bytes" to ensure the key is valid.

    Parameters:
        params   (bytes): Current encoded parameter buffer.
        decryptor (func): Function to decrypt the private key.

    Returns:
        (bytes, bytes): Formatted as (check bytes, left over bytes).
    """
    if decryptor:
        params = decryptor(params)

    key = PrivateKeyContainer.deserialize(params)

    if key.check_1 != key.check_2:
        raise ValueError(f'Private key check bytes incorrect. Is it encrypted? check1: {key.check_1}, check2: {key.check_2}')

    return bytes(key.check_1) + bytes(key.check_2), params



def generate_openssh_private_key(public_key: object, private_key: object, encode_pem: bool=True, marker: str=None, encryption: str=None, iv: bytes=None, passphrase: bytes=None, header=None) -> bytes:
    """
    Internal function. Generates OpenSSH private keys for various PKI.

    Parameters:
        public_key           (object): OpenSSH public key object.
        private_key          (object): OpenSSH private key object.
        encode_pem             (bool): Whether or not to PEM encode.
        marker                  (str): PEM markers.
        encryption              (str): Encryption algorithm to use.
        iv                    (bytes): IV for encryption algorithm.
        passphrase            (bytes): Passphrase for KDF.
        header (OpenSSHPrivateHeader): Header to use.

    Returns:
        bytes: OpenSSH encoded PKI object.
    """
    encryption = encryption or (header.encryption if header else None) or b'none'

    if encryption and type(encryption) is str:
        encryption = encryption.encode('utf-8')

    if encryption != b'none':
        if iv or not header:
            kdf_params = KDFParams(salt=iv or Bytes.random(16), rounds=header.kdf_params.rounds if header else 16)
        elif header:
            kdf_params = header.kdf_params.val.val
        else:
            kdf_params = S.Null()
    else:
        kdf_params = S.Null()


    header = OpenSSHPrivateHeader(
        encryption=encryption,
        kdf=b'bcrypt' if encryption != b'none' else ((header.kdf if header else None) or b'none'),
        kdf_params=S.Opaque[S.Selector[optional_kdf_params]]((kdf_params))
    )

    ppp = PublicPrivatePair(public_key, private_key)
    
    encryptor, padding_size = None, 8
    if passphrase:
        encryptor, padding_size = header.generate_encryptor(passphrase)
        ppp = ppp.encrypt(encryptor, padding_size)

    encoded = OpenSSHPrivateKey(header, OpenSSHPrivateKey.__annotations__['keypairs'](S.SizedList[type(ppp)]([ppp]))).serialize()
    if encode_pem:
        encoded = pem_encode(encoded, marker or 'OPENSSH PRIVATE KEY')

    return encoded



def generate_openssh_public_key_params(encoding: PKIEncoding, ssh_header: bytes, public_key: object, user: bytes=None) -> (bytes, bool, str, bool):
    """
    Internal function. Generates OpenSSH public key parameters for various PKI.

    Parameters:
        encoding (PKIEncoding): Encoding to use. Currently supports 'OpenSSH' and 'SSH2'.
        ssh_header     (bytes): PKI-specific SSH header.
        public_key    (object): OpenSSH public key object.

    Returns:
        (bytes, bool, str, bool): PKI public key parameters formatted as (encoded, default_pem, default_marker, use_rfc_4716).
    """
    if encoding in (PKIEncoding.OpenSSH, PKIEncoding.OpenSSH_CERT):
        if user and type(user) is str:
            user = user.encode('utf-8')

        encoded = ssh_header + b' ' + base64.b64encode(public_key.serialize()) + b' ' + (user or b'nohost@localhost')

    elif encoding == PKIEncoding.SSH2:
        encoded = public_key.serialize()[4:]

    else:
        raise ValueError(f'Unsupported encoding "{encoding}"')

    return encoded



def parse_openssh_key(buffer: bytes, ssh_header: bytes, passphrase: bytes) -> (object, object):
    """
    Internal function. Parses various PKI keys.

    Parameters:
        buffer     (bytes): Byte-encoded OpenSSH key.
        ssh_header (bytes): PKI-specific SSH header.
        passphrase (bytes): Passphrase for KDF.

    Returns:
        (object, object): Parsed private and public key objects formatted as (private key, public key).
    """
    priv = None

    # SSH private key?
    if OpenSSHPrivateHeader.magic in buffer:
        _, key = OpenSSHPrivateKey.deserialize(buffer)

        decryptor = None
        if passphrase:
            decryptor      = key.header.generate_decryptor(passphrase)
            priv_container = key.keypairs.val[0].decrypt(decryptor).private.val.val
        else:
            priv_container = key.keypairs.val[0].private.val.val

        pub     = key.keypairs.val[0].public.val.key.val
        user    = priv_container.host.val
        priv    = priv_container.key.key.val
        check_1 = priv_container.check_1.val
        check_2 = priv_container.check_2.val
        header  = key.header

    else:
        if buffer.split(b' ')[0][:len(ssh_header)] == ssh_header:
            _header, body, user = buffer.split(b' ')
            body = base64.b64decode(body)

        else:
            body = buffer
            user = None

        _, pub  = PublicKey.deserialize(body)
        pub     = pub.key.val
        check_1 = None
        check_2 = None
        header  = None

    return priv, pub, Bytes(user) if user else user, check_1, check_2, header
