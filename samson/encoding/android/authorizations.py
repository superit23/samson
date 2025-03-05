from samson.encoding.android.keymaster_def import KMAlgorithm, KMPurpose, KMBlockMode, KMPadding, KMTag, KMKeyFormat, KMECCurve, KMDigest, KMOrigin, remove_tag_type
from samson.core.base_object import BaseObject
from pyasn1.type.univ import  Integer, Set, Null, OctetString
from pyasn1.type import tag

# https://android.googlesource.com/platform/cts/+/master/tests/security/src/android/keystore/cts/AuthorizationList.java
class AuthorizationList(BaseObject):
    KEY_FORMAT = None

    @classmethod
    def parse(cls, key_format: KMKeyFormat, sequence):
        for subclass in cls.__subclasses__():
            if subclass.KEY_FORMAT == key_format:
                return subclass.parse(sequence)
        
        raise ValueError(f'No registered subclass for {key_format}')


    def build(self):
        pass


class Authorization(BaseObject):
    TAG = None

    @staticmethod
    def check_or_instantiate(authorization):
        if issubclass(authorization.__class__, Authorization):
            return authorization
        else:
            return Authorization.instantiate(*authorization)


    @classmethod
    def instantiate(cls, tag, *args, **kwargs):
        if cls.TAG == tag:
            return cls(*args, **kwargs)

        for subclass in cls.__subclasses__():
            try:
                return subclass.instantiate(tag, *args, **kwargs)
            except ValueError:
                pass

        raise ValueError(f'No registered subclass for tag {tag}')


    @classmethod
    def parse(cls, item: object) -> 'Authorization':
        if cls.TAG and remove_tag_type(cls.TAG.value) == item.tagSet.superTags[1].tagId:
            return cls._parse(item)

        for subclass in cls.__subclasses__():
            try:
                return subclass.parse(item)
            except ValueError:
                pass
        
        raise ValueError(f'No registered subclass for tagId {item.tagSet.superTags[1].tagId}')



class NullAuthorization(Authorization):
    @classmethod
    def _parse(cls, item: object) -> 'NullAuthorization':
        return cls()


    def build(self):
        return Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, remove_tag_type(self.TAG.value)))



class SetAuthorization(Authorization):
    TYPE = None

    def __init__(self, val) -> None:
        # Items MUST be sorted or it will cause a signature mismatch (KeyStore must sort internally and then check MAC)
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

    @classmethod
    def _parse(cls, item: object) -> 'SetAuthorization':
        return cls([cls.TYPE(int(item[i])) for i in item])


    def build(self):
        set_obj = Set().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, remove_tag_type(self.TAG.value)))
        
        for i, sub_obj in enumerate(self):
            set_obj[i] = Integer(sub_obj.value)
        
        return set_obj


class IntegerAuthorization(Authorization):
    def __init__(self, val: int) -> None:
        self.val = val

    def __int__(self):
        return self.val

    @classmethod
    def _parse(cls, item: object) -> 'IntegerAuthorization':
        return cls(int(item))


    def build(self):
        return Integer(int(self)).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, remove_tag_type(self.TAG.value)))


class OctectStringAuthorization(Authorization):
    def __init__(self, val: str) -> None:
        self.val = val

    def __str__(self):
        return self.val

    @classmethod
    def _parse(cls, item: object) -> 'OctectStringAuthorization':
        return cls(str(item))


    def build(self):
        return OctetString(str(self)).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, remove_tag_type(self.TAG.value)))


class NamedConstantAuthorization(IntegerAuthorization):
    TYPE = None

    def __init__(self, val: int) -> None:
        self.val = self.TYPE(val)

    def __int__(self):
        return self.val.value


class KeySizeAuthorization(IntegerAuthorization):
    TAG = KMTag.KM_TAG_KEY_SIZE


class AlgorithmAuthorization(NamedConstantAuthorization):
    TAG  = KMTag.KM_TAG_ALGORITHM
    TYPE = KMAlgorithm

class PurposeAuthorization(SetAuthorization):
    TAG  = KMTag.KM_TAG_PURPOSE
    TYPE = KMPurpose

class BlockModeAuthorization(SetAuthorization):
    TAG  = KMTag.KM_TAG_BLOCK_MODE
    TYPE = KMBlockMode

class PaddingAuthorization(SetAuthorization):
    TAG  = KMTag.KM_TAG_PADDING
    TYPE = KMPadding

class DigestAuthorization(SetAuthorization):
    TAG  = KMTag.KM_TAG_DIGEST
    TYPE = KMDigest

class OriginAuthorization(SetAuthorization):
    TAG  = KMTag.KM_TAG_ORIGIN
    TYPE = KMOrigin

class OSVersionAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_OS_VERSION

class OSPatchLevelAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_OS_PATCHLEVEL

class VendorPatchLevelAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_VENDOR_PATCHLEVEL

class BootPatchLevelAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_BOOT_PATCHLEVEL

class ECCurveAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_EC_CURVE
    TYPE = KMECCurve

class NoAuthRequiredAuthorization(NullAuthorization):
    TAG  = KMTag.KM_TAG_NO_AUTH_REQUIRED

class RollbackResistanceAuthorization(NullAuthorization):
    TAG  = KMTag.KM_TAG_ROLLBACK_RESISTANCE

class RollbackResistantAuthorization(NullAuthorization):
    TAG  = KMTag.KM_TAG_ROLLBACK_RESISTANT

class RSAOAEPMGFDigestAuthorization(SetAuthorization):
    TAG  = KMTag.KM_TAG_RSA_OAEP_MGF_DIGEST
    TYPE = KMDigest

class AllowWhileOnBodyAuthorization(NullAuthorization):
    TAG  = KMTag.KM_TAG_ALLOW_WHILE_ON_BODY

class AllApplicationsAuthorization(NullAuthorization):
    TAG  = KMTag.KM_TAG_ALL_APPLICATIONS

class TrustedUserPresenceRequiredAuthorization(NullAuthorization):
    TAG  = KMTag.KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED

class TrustedConfirmationRequiredAuthorization(NullAuthorization):
    TAG  = KMTag.KM_TAG_TRUSTED_CONFIRMATION_REQUIRED

class RSAPublicExponentAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_RSA_PUBLIC_EXPONENT

class CreationDateAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_CREATION_DATETIME

class ActiveDateAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_ACTIVE_DATETIME

class UsageExpireAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_USAGE_EXPIRE_DATETIME

class OriginationExpireAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_ORIGINATION_EXPIRE_DATETIME

class AuthTimeoutAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_AUTH_TIMEOUT

class UserAuthTypeAuthorization(IntegerAuthorization):
    TAG  = KMTag.KM_TAG_USER_AUTH_TYPE

class AttestationIDBrandAuthorization(OctetString):
    TAG  = KMTag.KM_TAG_ATTESTATION_ID_BRAND

class AttestationIDDeviceAuthorization(OctetString):
    TAG  = KMTag.KM_TAG_ATTESTATION_ID_DEVICE

class AttestationIDProductAuthorization(OctetString):
    TAG  = KMTag.KM_TAG_ATTESTATION_ID_PRODUCT

class AttestationIDSerialAuthorization(OctetString):
    TAG  = KMTag.KM_TAG_ATTESTATION_ID_SERIAL

class AttestationIDIMEIAuthorization(OctetString):
    TAG  = KMTag.KM_TAG_ATTESTATION_ID_IMEI

class AttestationIDBrandAuthorization(OctetString):
    TAG  = KMTag.KM_TAG_ATTESTATION_ID_BRAND
