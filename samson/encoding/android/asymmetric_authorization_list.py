from samson.encoding.android.authorizations import Authorization, AlgorithmAuthorization, PurposeAuthorization, DigestAuthorization, PaddingAuthorization, KeySizeAuthorization, AuthorizationList
from samson.encoding.android.keymaster_def import KMKeyFormat
from pyasn1.type.univ import Sequence

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
