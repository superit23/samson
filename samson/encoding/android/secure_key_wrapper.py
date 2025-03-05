from samson.encoding.android.key_description import KeyDescriptionASN1, KeyDescription
from samson.encoding.android.transformations import Transformation
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.gcm import GCM
from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject
from pyasn1.type.univ import Sequence, Integer, OctetString
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.codec.der import encoder, decoder

# https://developer.android.com/privacy-and-security/keystore#ImportingEncryptedKeys
class SecureKeyWrapperASN1(Sequence):
    # SecureKeyWrapper ::= SEQUENCE(
    #     version INTEGER,                     # Contains value 0
    #     encryptedTransportKey OCTET_STRING,
    #     initializationVector OCTET_STRING,
    #     keyDescription KeyDescription,
    #     encryptedKey OCTET_STRING,
    #     tag OCTET_STRING
    # )
    componentType = NamedTypes(
        NamedType('version', Integer()),
        NamedType('encryptedTransportKey', OctetString()),
        NamedType('initializationVector', OctetString()),
        NamedType('keyDescription', KeyDescriptionASN1()),
        NamedType('encryptedKey', OctetString()),
        NamedType('tag', OctetString()),
    )


class SecureKeyWrapper(BaseObject):
    def __init__(self, encrypted_transport_key: bytes, iv: bytes, key_description: KeyDescription, encrypted_key: bytes, tag: bytes, version: int=0) -> None:
        self.version                 = version
        self.encrypted_transport_key = encrypted_transport_key
        self.iv                      = iv
        self.key_description         = key_description
        self.encrypted_key           = encrypted_key
        self.tag                     = tag


    @staticmethod
    def create(key_material: bytes, transformation: Transformation, key_description: KeyDescription, ephemeral_key: bytes=None, iv: bytes=None):
        eph_key     = ephemeral_key or Bytes.random(32)
        enc_eph_key = transformation.transform(eph_key)

        key_desc    = key_description.build()
        iv          = iv or Bytes.random(12)
        gcm         = GCM(Rijndael(eph_key))
        enc_sec_key = gcm.encrypt(nonce=iv, data=encoder.encode(key_desc), plaintext=key_material)
        enc_sec_key, tag = enc_sec_key[:-16], enc_sec_key[-16:]

        return SecureKeyWrapper(
            version=0,
            encrypted_transport_key=enc_eph_key,
            iv=iv,
            key_description=key_description,
            encrypted_key=enc_sec_key,
            tag=tag
        )


    @staticmethod
    def parse(data: bytes):
        key_wrapper, _ = decoder.decode(data, asn1Spec=SecureKeyWrapperASN1())
        version        = int(key_wrapper['version'])
        enc_eph_key    = bytes(key_wrapper['encryptedTransportKey'])
        iv             = bytes(key_wrapper['initializationVector'])
        key_desc       = KeyDescription.parse(key_wrapper['keyDescription'])
        enc_sec_key    = bytes(key_wrapper['encryptedKey'])
        tag            = bytes(key_wrapper['tag'])

        return SecureKeyWrapper(
            version=version,
            encrypted_transport_key=enc_eph_key,
            iv=iv,
            key_description=key_desc,
            encrypted_key=enc_sec_key,
            tag=tag
        )



    def build(self) -> 'SecureKeyWrapper':
        key_wrapper = SecureKeyWrapperASN1()
        key_wrapper['version'] = self.version
        key_wrapper['encryptedTransportKey'] = bytes(self.encrypted_transport_key)
        key_wrapper['initializationVector'] = bytes(self.iv)
        key_wrapper['keyDescription'] = self.key_description.build()
        key_wrapper['encryptedKey'] = bytes(self.encrypted_key)
        key_wrapper['tag'] = bytes(self.tag)

        return key_wrapper
