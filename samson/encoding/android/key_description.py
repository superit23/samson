from pyasn1.type.univ import Sequence, Integer
from pyasn1.type.namedtype import NamedTypes, NamedType
from samson.encoding.android.keymaster_def import KMKeyFormat
from samson.encoding.android.symmetric_authorization_list import AuthorizationList
from samson.core.base_object import BaseObject

class KeyDescriptionASN1(Sequence):
    # KeyDescription ::= SEQUENCE(
    #     keyFormat INTEGER,                   # Values from KeyFormat enum.
    #     keyParams AuthorizationList,
    # )
    componentType = NamedTypes(
        NamedType('keyFormat', Integer()),
        NamedType('keyParams', Sequence()),
    )


class KeyDescription(BaseObject):
    def __init__(self, key_format: KMKeyFormat, key_params: AuthorizationList) -> None:
        self.key_format = key_format
        self.key_params = key_params


    def build(self):
        key_desc = KeyDescriptionASN1()
        key_desc['keyFormat'] = self.key_format.value
        key_desc['keyParams'] = self.key_params.build()

        return key_desc
