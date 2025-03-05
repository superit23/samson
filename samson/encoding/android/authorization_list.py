from samson.encoding.android.authorizations import Authorization, AlgorithmAuthorization, PurposeAuthorization, BlockModeAuthorization, PaddingAuthorization, KeySizeAuthorization, DigestAuthorization
from samson.encoding.android.keymaster_def import KMKeyFormat
from samson.core.base_object import BaseObject
from pyasn1.type.univ import Sequence

# https://android.googlesource.com/platform/cts/+/master/tests/security/src/android/keystore/cts/AuthorizationList.java
class AuthorizationList(BaseObject):
    KEY_FORMAT = None

    @classmethod
    def parse(cls, key_format: KMKeyFormat, sequence):
        for subclass in cls.__subclasses__():
            if subclass.KEY_FORMAT == key_format:
                return subclass.parse(sequence)
        
        raise ValueError(f'No registered subclass for {key_format}')


    @staticmethod
    def parse(sequence: Sequence) -> 'SymmetricAuthorizationList':
        type_dict = {}
        for idx in sequence:
            authorization = Authorization.parse(sequence[idx])
            type_dict[authorization.__class__] = authorization
        
        return SymmetricAuthorizationList(
            algorithm=type_dict.get(AlgorithmAuthorization),
            purposes=type_dict.get(PurposeAuthorization),
            key_size=type_dict.get(KeySizeAuthorization),
            block_modes=type_dict.get(BlockModeAuthorization),
            paddings=type_dict.get(PaddingAuthorization)
        )


    def build(self):
        auth_list = Sequence()

        i = 0
        for obj in (self.purposes, self.algorithm, self.key_size, self.block_modes, self.paddings):
            if obj:
                auth_list[i] = obj.build()
                i += 1

        return auth_list



# These items MUST be in this order to be accepted by the KeyStore
class SymmetricAuthorizationList(AuthorizationList):
    KEY_FORMAT = KMKeyFormat.KM_KEY_FORMAT_RAW

    def __init__(self, algorithm: AlgorithmAuthorization, purposes: PurposeAuthorization=None, key_size: KeySizeAuthorization=None, block_modes: BlockModeAuthorization=None, paddings: PaddingAuthorization=None) -> None:
        self.algorithm   = Authorization.check_or_instantiate(algorithm)
        self.purposes    = Authorization.check_or_instantiate(purposes)
        self.key_size    = Authorization.check_or_instantiate(key_size)
        self.block_modes = Authorization.check_or_instantiate(block_modes)
        self.paddings    = Authorization.check_or_instantiate(paddings)
    

    @staticmethod
    def parse(sequence: Sequence) -> 'SymmetricAuthorizationList':
        type_dict = {}
        for idx in sequence:
            authorization = Authorization.parse(sequence[idx])
            type_dict[authorization.__class__] = authorization
        
        return SymmetricAuthorizationList(
            algorithm=type_dict.get(AlgorithmAuthorization),
            purposes=type_dict.get(PurposeAuthorization),
            key_size=type_dict.get(KeySizeAuthorization),
            block_modes=type_dict.get(BlockModeAuthorization),
            paddings=type_dict.get(PaddingAuthorization)
        )
        
    

    def build(self):
        auth_list = Sequence()

        i = 0
        for obj in (self.purposes, self.algorithm, self.key_size, self.block_modes, self.paddings):
            if obj:
                auth_list[i] = obj.build()
                i += 1

        return auth_list


# These items MUST be in this order to be accepted by the KeyStore
class AsymmetricAuthorizationList(AuthorizationList):
    KEY_FORMAT = KMKeyFormat.KM_KEY_FORMAT_PKCS8

    def __init__(self, algorithm: AlgorithmAuthorization, purposes: PurposeAuthorization=None, key_size: KeySizeAuthorization=None, digests: DigestAuthorization=None, paddings: PaddingAuthorization=None) -> None:
        self.algorithm = Authorization.check_or_instantiate(algorithm) if algorithm else None
        self.purposes  = Authorization.check_or_instantiate(purposes) if purposes else None
        self.key_size  = Authorization.check_or_instantiate(key_size) if key_size else None
        self.digests   = Authorization.check_or_instantiate(digests) if digests else None
        self.paddings  = Authorization.check_or_instantiate(paddings) if paddings else None
    

    @staticmethod
    def parse(sequence: Sequence) -> 'AsymmetricAuthorizationList':

        type_dict = {}
        for idx in sequence:
            authorization = Authorization.parse(sequence[idx])
            type_dict[authorization.__class__] = authorization
        
        return AsymmetricAuthorizationList(
            algorithm=type_dict.get(AlgorithmAuthorization),
            purposes=type_dict.get(PurposeAuthorization),
            key_size=type_dict.get(KeySizeAuthorization),
            digests=type_dict.get(DigestAuthorization),
            paddings=type_dict.get(PaddingAuthorization)
        )
        
    

    def build(self):
        auth_list = Sequence()

        i = 0
        for obj in (self.purposes, self.algorithm, self.key_size, self.digests, self.paddings):
            if obj:
                auth_list[i] = obj.build()
                i += 1

        return auth_list
