from samson.core.pki_parser_base import PKIParserBase

class JWKBase(PKIParserBase):
    DEFAULT_MARKER = None
    DEFAULT_PEM    = False
    USE_RFC_4716   = False

    def __init__(self, key, **kwargs):
        self.key = key
