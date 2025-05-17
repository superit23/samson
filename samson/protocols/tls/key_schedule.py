from samson.core.base_object import BaseObject

# https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
class KeySchedule(BaseObject):
    BINDER_KEY                     = b"ext binder"
    CLIENT_EARLY_TRAFFIC_SECRET    = b"c e traffic"
    EARLY_EXPORTER_MASTER_SECRET   = b"e exp master"

    CLIENT_HANDSHAKE_TRAFFIC_SECRET = b"c hs traffic"
    SERVER_HANDSHAKE_TRAFFIC_SECRET = b"s hs traffic"

    CLIENT_APPLICATION_TRAFFIC_SECRET_0 = b"c ap traffic"
    SERVER_APPLICATION_TRAFFIC_SECRET_0 = b"s ap traffic"
    EXPORTER_MASTER_SECRET   = b"exp master"
    RESUMPTION_MASTER_SECRET = b"res master"

    EARLY_SECRET     = b"early secret"
    HANDSHAKE_SECRET = b"handshake secret"
    MASTER_SECRET    = b"master secret"

    CLIENT_APPLICATION_TRAFFIC_SECRET = b"client application secret"
    SERVER_APPLICATION_TRAFFIC_SECRET = b"server application secret"


    def __init__(self, ciphersuite: 'Ciphersuite', psk: bytes=b'\x00'):
        self.psk         = psk
        self.ciphersuite = ciphersuite
        self.keys        = {}
    

    def __getitem__(self, idx):
        return self.keys[idx]


    def process_keys(self, entropy: bytes, keys: list, transcript_hash: bytes):
        for key in keys:
            derived_key = self.ciphersuite.derive_secret(
                secret=entropy,
                label=key,
                transcript_hash=transcript_hash
            )

            self.keys[key] = derived_key


    def create_key(self, key_name, salt, ikm, order, transcript_hash):
        entropy = self.ciphersuite.hkdf.extract(salt, ikm)
        self.keys[key_name]  = entropy

        self.process_keys(entropy, order, transcript_hash)

    
    def process_psk(self, transcript_hash: bytes):
        order = [
            KeySchedule.BINDER_KEY,
            KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET,
            KeySchedule.EARLY_EXPORTER_MASTER_SECRET
        ]

        self.create_key(
            key_name=KeySchedule.EARLY_SECRET,
            salt=b'\x00',
            ikm=self.psk,
            order=order,
            transcript_hash=transcript_hash
        )



    def process_shared_secret(self, shared_secret: bytes, transcript_hash: bytes):
        # Compute handshake secrets
        order = [
            KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET,
            KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET
        ]

        salt = self.ciphersuite.derive_secret(
            secret=self.psk,
            label=b'derived',
            transcript_hash=transcript_hash
        )


        self.create_key(
            key_name=KeySchedule.HANDSHAKE_SECRET,
            salt=salt,
            ikm=shared_secret,
            order=order,
            transcript_hash=transcript_hash
        )


        # Compute application traffic secrets
        order = [
            KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0,
            KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0,
            KeySchedule.EXPORTER_MASTER_SECRET,
            KeySchedule.RESUMPTION_MASTER_SECRET
        ]


        salt = self.ciphersuite.derive_secret(
            secret=salt,
            label=b'derived',
            transcript_hash=transcript_hash
        )

        self.create_key(
            key_name=KeySchedule.MASTER_SECRET,
            salt=salt,
            ikm=b'\x00',
            order=order,
            transcript_hash=transcript_hash
        )

        # Create application key update arrays
        self.keys[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET] = [self.keys[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0]]
        self.keys[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET] = [self.keys[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0]]
