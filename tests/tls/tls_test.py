from samson.core.base_object import BaseObject
from samson.protocols.tls.messages import *
from samson.protocols.tls.tls_client import TLSState, TLSConfiguration
from samson.protocols.tls.ciphersuite import Ciphersuite
from samson.protocols.tls.key_schedule import KeySchedule
from samson.block_ciphers.rijndael import Rijndael
from samson.hashes.sha2 import SHA256
from samson.protocols.ecdhe import ECDHE
from samson.math.algebra.curves.named import P256


class TLSTest(BaseObject):
    def build_state(self, kex=None, aead=None, hash=None):
        kex = kex or ECDHE(G=P256.G)

        def aes_gcm(key):
            rij = Rijndael(key)
            gcm = GCM(rij)
            return gcm


        cs           = Ciphersuite(aead or aes_gcm, hash or SHA256())
        config       = TLSConfiguration(kex, cs)
        self.server_state = TLSState(config)
        self.client_state = TLSState(config)



    def process_messages(self, state, messages, raw=False):
        for msg_data in messages:
            if raw:
                msg = Handshake.deserialize(msg_data)[1]
                assert msg.serialize() == msg_data
                state.transcript.append(msg)

            else:
                msg = TLSPlaintext.deserialize(msg_data)[1]
                assert msg.serialize() == msg_data
                state.transcript.append(msg.fragment.val.val)


    def test_finished(self, state, key_name, expected):
        finished = state.finished(state.key_schedule[key_name])
        assert finished.serialize() == expected
        return finished


    def test_key_schedule(self, state, expected_keyschedule):
        for key_name, value in expected_keyschedule.items():
            assert state.key_schedule[key_name] == value


    def test_encryption_keys(self, state, expected_keyschedule):
        for key_name, value in expected_keyschedule.items():
            assert state.get_traffic_key(state.key_schedule[key_name]) == value


    def process_early_secret(self, state):
        state.key_schedule.process_early_secret(state.transcript.hash())


    def process_handshake_secret(self, state, shared_key):
        state.key_schedule.process_handshake_secret(shared_key, state.transcript.hash())


    def process_master_secret(self, state):
        state.key_schedule.process_master_secret(state.transcript.hash())


    def process_resumption_secret(self, state):
        state.key_schedule.process_resumption_secret(state.transcript.hash())


    def process_encrypted_messages(self, state, key_name, message, expected_content):
        msg = TLSPlaintext.deserialize(message)[1]
        assert msg.serialize() == message, "Failed initial deserialization"

        decrypted   = state.decrypt_application_data(state.key_schedule[key_name], msg)
        reencrypted = state.encrypt_application_data(state.key_schedule[key_name], decrypted)

        assert reencrypted.serialize() == msg.serialize(), "Failed re-encryption"
        assert [content.serialize() for content in decrypted.content] == expected_content, "Failed internal content"
        return decrypted.content
