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
    RESUMPTION               = b'resumption'

    EARLY_SECRET     = b"early secret"
    HANDSHAKE_SECRET = b"handshake secret"
    MASTER_SECRET    = b"master secret"

    CLIENT_APPLICATION_TRAFFIC_SECRET = b"client application secret"
    SERVER_APPLICATION_TRAFFIC_SECRET = b"server application secret"

    FINISHED = b'finished'


    def __init__(self, ciphersuite: 'Ciphersuite', psk: bytes=None):
        self.psk         = psk
        self.ciphersuite = ciphersuite
        self.keys        = {}
    

    def __getitem__(self, idx):
        return self.keys[idx]


    def __setitem__(self, idx, val):
        self.keys[idx] = val


    def process_keys(self, entropy: bytes, keys: list, transcript_hash: bytes):
        for key in keys:
            derived_key = self.ciphersuite.derive_secret(
                secret=entropy,
                label=key,
                transcript_hash=transcript_hash
            )

            self[key] = derived_key



    def create_key(self, key_name, salt, ikm, order, transcript_hash):
        entropy = self.ciphersuite.hkdf.extract(salt, ikm)
        self[key_name] = entropy

        self.process_keys(entropy, order, transcript_hash)



    def process_binder_secret(self):
        entropy = self.ciphersuite.hkdf.extract(b'\x00'*self.ciphersuite.length, self.psk)
        self[KeySchedule.EARLY_SECRET] = entropy

        empty_hash = self.ciphersuite.hash_obj.hash(b'')

        # TODO: Handle external binder keys
        # "ext binder" | "res binder"
        derived_key = self.ciphersuite.derive_secret(
            secret=entropy,
            label=b"res binder",
            transcript_hash=empty_hash
        )

        self[KeySchedule.BINDER_KEY] = derived_key



    
    def process_early_secret(self, transcript_hash: bytes):
        order = [
            KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET,
            KeySchedule.EARLY_EXPORTER_MASTER_SECRET
        ]

        self.create_key(
            key_name=KeySchedule.EARLY_SECRET,
            salt=b'\x00'*len(transcript_hash),
            ikm=self.psk,
            order=order,
            transcript_hash=transcript_hash
        )



    def process_handshake_secret(self, shared_secret: bytes, transcript_hash: bytes):
        empty_hash = self.ciphersuite.hash_obj.hash(b'')

        # Compute handshake secrets
        order = [
            KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET,
            KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET
        ]

        salt = self.ciphersuite.derive_secret(
            secret=self[KeySchedule.EARLY_SECRET],
            label=b'derived',
            transcript_hash=empty_hash
        )


        self.create_key(
            key_name=KeySchedule.HANDSHAKE_SECRET,
            salt=salt,
            ikm=shared_secret,
            order=order,
            transcript_hash=transcript_hash
        )

        self.keys[KeySchedule.FINISHED] = self.ciphersuite.derive_secret(self[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET], b'finished', b'')



    def process_master_secret(self, transcript_hash: bytes):
        empty_hash = self.ciphersuite.hash_obj.hash(b'')

        # Compute application traffic secrets
        order = [
            KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0,
            KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0,
            KeySchedule.EXPORTER_MASTER_SECRET
        ]


        salt = self.ciphersuite.derive_secret(
            secret=self[KeySchedule.HANDSHAKE_SECRET],
            label=b'derived',
            transcript_hash=empty_hash
        )

        self.create_key(
            key_name=KeySchedule.MASTER_SECRET,
            salt=salt,
            ikm=b'\x00'*len(transcript_hash),
            order=order,
            transcript_hash=transcript_hash
        )

        # Create application key update arrays
        self[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET] = [self[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0]]
        self[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET] = [self[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0]]



    def process_resumption_secret(self, transcript_hash: bytes):
        self.process_keys(self[KeySchedule.MASTER_SECRET], [KeySchedule.RESUMPTION_MASTER_SECRET], transcript_hash)


        derived_key = self.ciphersuite.derive_secret(
            secret=self[KeySchedule.RESUMPTION_MASTER_SECRET],
            label=KeySchedule.RESUMPTION,
            transcript_hash=b'\x00\x00'
        )

        self[KeySchedule.RESUMPTION] = derived_key
