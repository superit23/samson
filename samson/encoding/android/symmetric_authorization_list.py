from samson.encoding.android.authorizations import AlgorithmAuthorization, PurposeAuthorization, BlockModeAuthorization, PaddingAuthorization, KeySizeAuthorization, AuthorizationList
from pyasn1.type.univ import Sequence

class SymmetricAuthorizationList(AuthorizationList):
    def __init__(self, algorithm: AlgorithmAuthorization, purposes: PurposeAuthorization=None, key_size: KeySizeAuthorization=None, block_modes: BlockModeAuthorization=None, paddings: PaddingAuthorization=None) -> None:
        self.algorithm   = algorithm
        self.purposes    = purposes
        self.key_size    = key_size
        self.block_modes = block_modes
        self.paddings    = paddings
    

    def build(self):
        auth_list = Sequence()

        i = 0
        for obj in (self.purposes, self.algorithm, self.key_size, self.block_modes, self.paddings):
            auth_list[i] = obj.build()
            i += 1

        return auth_list
