from samson.encoding.android.keymaster_def import KMAlgorithm, KMPurpose, KMBlockMode, KMPadding, KMTag, remove_tag_type
from samson.core.base_object import BaseObject
from pyasn1.type.univ import  Integer, Set
from pyasn1.type import tag

class AuthorizationList(BaseObject):
    def build(self):
        pass


class IntegerAuthorization(BaseObject):
    TAG = None

    def __int__(self):
        raise NotImplementedError()

    def build(self):
        return Integer(int(self)).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, remove_tag_type(self.TAG.value)))


class KeySizeAuthorization(IntegerAuthorization):
    TAG = KMTag.KM_TAG_KEY_SIZE

    def __init__(self, key_size: int) -> None:
        self.key_size = key_size

    def __int__(self):
        return self.key_size


class AlgorithmAuthorization(IntegerAuthorization):
    TAG = KMTag.KM_TAG_ALGORITHM

    def __init__(self, algorithm: KMAlgorithm) -> None:
        self.algorithm = algorithm

    def __int__(self):
        return self.algorithm.value


class SetAuthorization(BaseObject):
    TAG  = None
    TYPE = None

    def __init__(self, val) -> None:
        self.val = sorted(val, key=lambda v: v.value)

    def append(self, obj: object):
        self.val.append(obj)
    
    def __delitem__(self, idx):
        del self.val[idx]

    def __getitem__(self, idx):
        return self.val[idx]

    def __setitem__(self, idx, value):
        self.val[idx] = value

    def __iter__(self):
        for v in self.val:
            yield v

    def build(self):
        set_obj = Set().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, remove_tag_type(self.TAG.value)))
        
        for i, sub_obj in enumerate(self):
            set_obj[i] = Integer(sub_obj.value)
        
        return set_obj


class PurposeAuthorization(SetAuthorization):
        TAG  = KMTag.KM_TAG_PURPOSE
        TYPE = KMPurpose


class BlockModeAuthorization(SetAuthorization):
        TAG  = KMTag.KM_TAG_BLOCK_MODE
        TYPE = KMBlockMode


class PaddingAuthorization(SetAuthorization):
        TAG  = KMTag.KM_TAG_PADDING
        TYPE = KMPadding
