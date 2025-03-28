from samson.encoding.android.core.authorizations import Authorization
from samson.encoding.android.core.keymaster_def import remove_tag_type
from samson.core.base_object import BaseObject
from pyasn1.type.univ import Sequence

# https://android.googlesource.com/platform/cts/+/master/tests/security/src/android/keystore/cts/AuthorizationList.java
class AuthorizationList(BaseObject):

    def __init__(self, authorizations: list) -> None:
        self.authorizations = sorted([Authorization.check_or_instantiate(auth) for auth in authorizations], key=lambda auth: remove_tag_type(auth.TAG.value))


    def __getitem__(self, idx):
        return [auth for auth in self.authorizations if auth.TAG == idx][0]


    @staticmethod
    def parse(sequence: Sequence) -> 'AuthorizationList':
        authorizations = []
        for idx in sequence:
            authorizations.append(Authorization.parse(sequence[idx]))
        
        return AuthorizationList(authorizations)


    def build(self):
        auth_list = Sequence()

        i = 0
        for obj in self.authorizations:
            if obj:
                auth_list[i] = obj.build()
                i += 1

        return auth_list
