from samson.encoding.android.key_description import KeyDescriptionASN1
from samson.encoding.android.transformations import Transformation
from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.gcm import GCM
from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject
from pyasn1.type.univ import Sequence, Integer, OctetString
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.codec.der import encoder

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
    def __init__(self, key_material: bytes, key_description: 'KeyDescription', transformation: Transformation) -> None:
        self.key_material    = key_material
        self.key_description = key_description
        self.transformation  = transformation
    

    def build(self, iv: bytes=None, ephemeral_key: bytes=None) -> 'SecureKeyWrapper':
        eph_key     = ephemeral_key or Bytes.random(32)
        enc_eph_key = self.transformation.transform(eph_key)

        key_desc    = self.key_description.build()
        iv          = iv or Bytes.random(12)
        gcm         = GCM(Rijndael(eph_key))
        enc_sec_key = gcm.encrypt(nonce=iv, data=encoder.encode(key_desc), plaintext=self.key_material)
        enc_sec_key, tag = enc_sec_key[:-16], enc_sec_key[-16:]

        key_wrapper = SecureKeyWrapperASN1()
        key_wrapper['version'] = 0
        key_wrapper['encryptedTransportKey'] = enc_eph_key
        key_wrapper['initializationVector'] = bytes(iv)
        key_wrapper['keyDescription'] = key_desc
        key_wrapper['encryptedKey'] = bytes(enc_sec_key)
        key_wrapper['tag'] = bytes(tag)

        return key_wrapper
