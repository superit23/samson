from samson.core.pki_parser_base import PKIParserBase
from samson.encoding.android.core.secure_key_wrapper import SecureKeyWrapper
from samson.encoding.android.core.key_description import KeyDescription
from samson.encoding.android.core.authorization_list import AuthorizationList
from samson.encoding.android.core.keymaster_def import KMTag, KMAlgorithm, KMKeyFormat, KMPurpose, KMDigest, KMPadding
from samson.encoding.general import PKIEncoding
from pyasn1.codec.der import encoder

class AndroidKeyWrapPrivateKey(PKIParserBase):
    ALGORITHM              = None
    DEFAULT_AUTHORIZATIONS = None

    def __init__(self, secure_wrapper: SecureKeyWrapper):
        self.secure_wrapper = secure_wrapper


    @classmethod
    def check(cls, buffer: bytes, **kwargs) -> bool:
        try:
            skw = SecureKeyWrapper.parse(buffer)
            return skw.key_description.key_params[KMTag.KM_TAG_ALGORITHM] == cls.ALGORITHM
        except Exception:
            return False


    @staticmethod
    def calculate_key_size(key: 'PrivateKey'):
        raise NotImplementedError


    @classmethod
    def create(cls, key: 'PrivateKey', wrapping_key: 'PublicKey'=None, transformation: 'Transformation'=None, auth_list: AuthorizationList=None, ephemeral_key: bytes=None, iv: bytes=None, **kwargs):
        if not transformation:
            if not wrapping_key:
                raise RuntimeError('Either the "transformation" or "wrapping_key" argument must be specified')
            
            transformation = wrapping_key.ANDROID_KW_DEFAULT_TRANSFORMATION(wrapping_key)

        skw = SecureKeyWrapper.create(
            key_material=key.export_private_key(PKIEncoding.PKCS8).encode(encode_pem=False),
            transformation=transformation,
            key_description=KeyDescription(
                KMKeyFormat.KM_KEY_FORMAT_PKCS8,
                auth_list or AuthorizationList([
                    (KMTag.KM_TAG_ALGORITHM, cls.ALGORITHM),
                    (KMTag.KM_TAG_KEY_SIZE, cls.calculate_key_size(key))
                ] + cls.DEFAULT_AUTHORIZATIONS)
            ),
            ephemeral_key=ephemeral_key,
            iv=iv
        )

        return cls(skw)


    def encode(self, **kwargs) -> bytes:
        return encoder.encode(self.secure_wrapper.build())


    @classmethod
    def decode(cls, buffer: bytes, **kwargs) -> 'AndroidKeyWrapPrivateKey':
        return cls(SecureKeyWrapper.parse(buffer))


class AndroidKeyWrapECPrivateKey(AndroidKeyWrapPrivateKey):
    ALGORITHM              = KMAlgorithm.KM_ALGORITHM_EC
    DEFAULT_AUTHORIZATIONS = [
        (KMTag.KM_TAG_PURPOSE, [
            KMPurpose.KM_PURPOSE_SIGN,
            KMPurpose.KM_PURPOSE_VERIFY
        ]),
        (KMTag.KM_TAG_DIGEST, [
            KMDigest.KM_DIGEST_SHA_2_224,
            KMDigest.KM_DIGEST_SHA_2_256,
            KMDigest.KM_DIGEST_SHA_2_384,
            KMDigest.KM_DIGEST_SHA_2_512,
        ])
    ]

    @staticmethod
    def calculate_key_size(key: 'PrivateKey'):
        return key.q.bit_length()


class AndroidKeyWrapRSAPrivateKey(AndroidKeyWrapPrivateKey):
    ALGORITHM              = KMAlgorithm.KM_ALGORITHM_RSA
    DEFAULT_AUTHORIZATIONS = [
        (KMTag.KM_TAG_PURPOSE, [
            KMPurpose.KM_PURPOSE_ENCRYPT,
            KMPurpose.KM_PURPOSE_DECRYPT,
            KMPurpose.KM_PURPOSE_SIGN,
            KMPurpose.KM_PURPOSE_VERIFY
        ]),
        (KMTag.KM_TAG_PADDING, [
            KMPadding.KM_PAD_RSA_OAEP,
            KMPadding.KM_PAD_RSA_PKCS1_1_5_ENCRYPT,
            KMPadding.KM_PAD_RSA_PKCS1_1_5_SIGN,
            KMPadding.KM_PAD_RSA_PSS
        ])
    ]

    @staticmethod
    def calculate_key_size(key: 'PrivateKey'):
        return key.n.bit_length()
