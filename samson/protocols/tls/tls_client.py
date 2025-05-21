from enum import Enum, auto
from queue import Queue
from samson.protocols.tls.fsm import FSM
from samson.protocols.tls.messages import HandshakeType, AlertDescription, ClientHello, ProtocolVersion, TLSCipherSuite, ExtensionType, EXT, NamedGroup, ECPointFormat, KeyShareEntry, SignatureScheme, NameType, ServerName, Extension, TLSPlaintext, ContentType, Handshake, HandshakeType, S1, S2, S3, TLSInnerPlaintext, TLSCiphertext, ContentType, Finished
from samson.protocols.tls.channel import Channel
from samson.protocols.tls.key_schedule import KeySchedule
from samson.core.base_object import BaseObject
from samson.utilities.bytes import Bytes
from samson.macs.hmac import HMAC

import logging
log = logging.getLogger(__name__)


HELLO_RETRY_MAGIC = b'\xcf!\xadt\xe5\x9aa\x11\xbe\x1d\x8c\x02\x1ee\xb8\x91\xc2\xa2\x11\x16z\xbb\x8c^\x07\x9e\t\xe2\xc8\xa83\x9c'

class TLSProtocolError(Exception):
    pass

class TLSHSCState(Enum):
    START = auto()
    WAIT_FOR_HELLO = auto()
    WAIT_FOR_REPLY = auto()
    RECV_DATA      = auto()


class TLSServerReply(Enum):
    SERVER_HELLO = auto()
    HELLO_RETRY  = auto()



def _build_extension(ext_type, value):
    return Extension(ext_type, EXT[ext_type](value))



class TLSConfiguration(BaseObject):
    def __init__(self, kex, ciphersuite: 'Ciphersuite', psk: bytes=None):
        self.kex         = kex
        self.psk         = psk or Bytes().zfill(ciphersuite.length)
        self.ciphersuite = ciphersuite


class TLSState(BaseObject):
    def __init__(self, config: TLSConfiguration):
        self.config        = config
        self.sent_messages = []
        self.key_schedule  = KeySchedule(self.config.ciphersuite, self.config.psk)

        self.read_seq_num  = 0
        self.write_seq_num = 0

    
    def get_kex_public(self):
        return bytes(self.config.kex.pub.serialize_uncompressed())
    


    def process_key_share(self, ext_data: bytes):
        server_key  = self.config.kex.G.curve.decode_point(ext_data)
        derived_key = self.config.kex.derive_key(server_key)
        self.key_schedule.process_shared_secret(derived_key, self.calculate_transcript_hash())



    def calculate_transcript_hash(self):
        # https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
        to_hash = b''.join([msg.serialize() for msg in self.sent_messages])
        return self.config.ciphersuite.hash_obj.hash(to_hash)
    


    def update_traffic_keys(self):
        # https://datatracker.ietf.org/doc/html/rfc8446#section-7.2
        for secret_name in (KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET, KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET):
            latest_traffic_secret = self.key_schedule[secret_name][-1]

            new_client_key = self.config.ciphersuite.hkdf_expand_label(
                secret=latest_traffic_secret,
                label=b"traffic upd",
                context=b'',
                length=self.config.ciphersuite.length
            )
            self.key_schedule[secret_name].append(new_client_key)
    


    def get_traffic_key(self, secret: bytes):
        traffic_write_key = self.config.ciphersuite.hkdf_expand_label(
            secret=secret,
            label=b"key",
            context=b'',
            length=16
        )

        traffic_write_iv = self.config.ciphersuite.hkdf_expand_label(
            secret=secret,
            label=b"iv",
            context=b'',
            length=12
        )

        return traffic_write_key, traffic_write_iv



    def client_hello(self):
        client_hello = ClientHello(
            legacy_version=ProtocolVersion.TLSv12,
            random=bytes(Bytes.random(32)),
            legacy_session_id=bytes(Bytes.random(32)),
            cipher_suites=[
                TLSCipherSuite.TLS_AES_128_GCM_SHA256
                #TLSCipherSuite.TLS_CHACHA20_POLY1305_SHA256
            ],
            legacy_compression_methods=b'\x00',
            extensions=[
                _build_extension(ExtensionType.server_name, [ServerName(NameType.host_name, b'www.google.com')]),
                _build_extension(ExtensionType.supported_groups, [
                    NamedGroup.secp256r1
                ]),
                _build_extension(ExtensionType.ec_points_format, [ECPointFormat.uncompressed]),
                _build_extension(ExtensionType.application_layer_protocol_negotiation, [b'h2', b'http/1.1']),
                _build_extension(ExtensionType.supported_versions, [ProtocolVersion.TLSv13]),
                _build_extension(ExtensionType.key_share, [
                    KeyShareEntry(NamedGroup.secp256r1, self.get_kex_public())
                ]),
                _build_extension(ExtensionType.record_size_limit, 16385),
                _build_extension(ExtensionType.signature_algorithms, [
                    SignatureScheme.ecdsa_secp256r1_sha256
                ])
            ]
        )

        handshake = Handshake(
            msg_type=HandshakeType.client_hello,
            message=S3.Bytes(client_hello)
        )

        tls_record = TLSPlaintext(
            type=ContentType.handshake,
            legacy_record_version=ProtocolVersion.TLSv12,
            fragment=S2.Bytes(handshake)
        )

        self.sent_messages.append(handshake)
        self.write_seq_num += 1
        self.key_schedule.process_psk(self.calculate_transcript_hash())

        return tls_record
    


    def create_application_data(self, content_type: ContentType, data: bytes):
        inner_plaintext = TLSInnerPlaintext(
            content=data,
            type=content_type,
            zeros=[]
        )

        tls_data = inner_plaintext.serialize()

        client_write_key, client_write_iv = self.get_traffic_key(KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET)

        # TODO: How to calculate this for all ciphersuites?
        additional_data = ContentType.application_data.serialize() + ProtocolVersion.TLSv12.serialize() + Bytes(len(tls_data) + 16).zfill(2)

        encrypted_record = self.config.ciphersuite.encrypt(
            key=client_write_key,
            nonce=client_write_iv ^ Bytes(self.write_seq_num).zfill(12),
            data=tls_data,
            aad=additional_data
        )

        ciphertext = TLSCiphertext(
            opaque_type=ContentType.application_data,
            legacy_record_version=ProtocolVersion.TLSv12,
            encrypted_record=encrypted_record
        )

        return ciphertext



    def finished(self):
        hmac = HMAC(self.key_schedule[KeySchedule.FINISHED], self.config.ciphersuite.hash_obj)
        verify_data = hmac.generate(self.calculate_transcript_hash())

        handshake = Handshake(
            msg_type=HandshakeType.finished,
            message=S3.Bytes(Finished(verify_data))
        )
        return handshake


    def decrypt_server_application_data(self, ciphertext: TLSPlaintext):
        server_write_key, server_write_iv = self.get_traffic_key(self.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET])

        encrypted_data  = ciphertext.fragment.val.val
        additional_data = ContentType.application_data.serialize() + ProtocolVersion.TLSv12.serialize() + Bytes(len(encrypted_data)).zfill(2)

        decrypted_record = self.config.ciphersuite.decrypt(
            key=server_write_key,
            nonce=server_write_iv ^ Bytes(self.read_seq_num).zfill(12),
            data=encrypted_data,
            aad=additional_data
        )

        return decrypted_record



class TLSHandshakeClientFSM(FSM):
    def __init__(self, config: TLSConfiguration, channel: Channel):
        super().__init__()
        self.state         = TLSState(config)
        self.reply_queue   = Queue()
        self.sent_messages = []
        self.channel       = channel



    @FSM.transition(TLSHSCState.START)
    def initiate(self):
        log.info("START: Sending hello")

        tls_record = self.state.client_hello()
        print(bytes(tls_record))
        self.channel.send(bytes(tls_record))
        
        return (TLSHSCState.WAIT_FOR_HELLO, (), {})



    @FSM.transition(TLSHSCState.WAIT_FOR_HELLO)
    def wait_for_hello(self):
        reply     = self.reply_queue.get()
        handshake = reply.fragment.val.val

        self.state.sent_messages.append(handshake)
        self.state.read_seq_num += 1

        log.info(f"WAIT_FOR_HELLO: Received reply of {handshake.msg_type}")

        match handshake.msg_type:
            case HandshakeType.server_hello:
                server_hello = handshake.message.val.val

                if server_hello.legacy_session_id_echo == HELLO_RETRY_MAGIC:
                    raise TLSProtocolError(AlertDescription.illegal_parameter)
                else:
                    extensions = server_hello.extensions.val.val
                    for ext in extensions:
                        if ext.extension_type == ExtensionType.key_share:
                            log.info("WAIT_FOR_HELLO: Processing server key share")
                            self.state.process_key_share(ext.extension_data.val.val.server_share.key_exchange.val)
            
                return (TLSHSCState.RECV_DATA, (), {})

            case _:
                raise TLSProtocolError(AlertDescription.unexpected_message, reply)



    @FSM.transition(TLSHSCState.RECV_DATA)
    def recv_data(self):
        reply = self.reply_queue.get()
        self.sent_messages.append(reply)
        self.state.read_seq_num += 1

        log.info(f"RECV_DATA: Received reply of {reply.type}")

        match reply.type:
            case ContentType.change_cipher_spec:
                return (TLSHSCState.RECV_DATA, (), {})
            
            case ContentType.application_data:
                log.info(f"RECV_DATA: Processing application data")
                self.state.decrypt_server_application_data(reply)
                return (TLSHSCState.RECV_DATA, (), {})

            case _:
                raise TLSProtocolError(AlertDescription.unexpected_message, reply)

