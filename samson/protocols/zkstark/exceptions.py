from samson.utilities.exceptions import InvalidSignatureException

class LowPolyViolation(InvalidSignatureException):
    pass

class CollinearityViolation(InvalidSignatureException):
    pass

class MerkleVerificationFailure(InvalidSignatureException):
    pass