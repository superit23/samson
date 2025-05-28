from enum import Enum, auto
from queue import Queue
from samson.protocols.tls.fsm import FSM
from samson.protocols.tls.messages import HandshakeType, AlertDescription, ClientHello, ProtocolVersion, TLSCipherSuite, ExtensionType, EXT, NamedGroup, ECPointFormat, KeyShareEntry, SignatureScheme, NameType, ServerName, Extension, TLSPlaintext, ContentType, Handshake, HandshakeType, S1, S2, S3, TLSInnerPlaintext, TLSCiphertext, ContentType, Finished, PskIdentity, PreSharedKeyExtensionClient, OfferedPsks, HELLO_RETRY_MAGIC, TLSPlaintextHeader
from samson.protocols.tls.channel import Channel
from samson.protocols.tls.key_schedule import KeySchedule
from samson.protocols.tls.transcript import Transcript
from samson.core.base_object import BaseObject
from samson.utilities.bytes import Bytes
from samson.utilities.runtime import RUNTIME
from samson.utilities.exceptions import InvalidMACException
from samson.macs.hmac import HMAC


class TLSProtocolError(Exception):
    pass

class TLSHSCState(Enum):
    START         = auto()
    WAIT_SH       = auto()
    WAIT_EE       = auto()
    WAIT_CERT_CR  = auto()
    WAIT_CERT     = auto()
    WAIT_CV       = auto()
    WAIT_FINISHED = auto()
    CONNECTED     = auto()


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
        self.transcript    = Transcript(config.ciphersuite.hash_obj)
        self.key_schedule  = KeySchedule(self.config.ciphersuite, self.config.psk)

        self.key_schedule.process_binder_secret()

        self.read_seq_num  = 0
        self.write_seq_num = 0

    
    def get_kex_public(self):
        return bytes(self.config.kex.pub.serialize_uncompressed())
    


    def process_key_share(self, ext_data: bytes):
        server_key  = self.config.kex.G.curve.decode_point(ext_data)
        derived_key = self.config.kex.derive_key(server_key)
        self.key_schedule.process_handshake_secret(derived_key, self.transcript.hash())



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
            message=S3.Opaque[ClientHello](client_hello)
        )

        tls_record = TLSPlaintext(
            type=ContentType.handshake,
            legacy_record_version=ProtocolVersion.TLSv12,
            fragment=S2.Opaque[Handshake](handshake)
        )

        return tls_record



    def encrypt_application_data(self, secret: bytes, inner_plaintext: TLSInnerPlaintext):
        client_write_key, client_write_iv = self.get_traffic_key(secret)

        # TODO: How to calculate this for all ciphersuites?
        additional_data = ContentType.application_data.serialize() + ProtocolVersion.TLSv12.serialize() + Bytes(inner_plaintext.get_data_length() + 17).zfill(2)

        encrypted_record = self.config.ciphersuite.encrypt(
            key=client_write_key,
            nonce=client_write_iv ^ Bytes(self.write_seq_num).zfill(12),
            data=inner_plaintext.serialize(),
            aad=additional_data
        )

        ciphertext = TLSCiphertext(
            opaque_type=ContentType.application_data,
            legacy_record_version=ProtocolVersion.TLSv12,
            encrypted_record=encrypted_record
        )

        return ciphertext



    def psk_client_hello(self, client_hello: ClientHello, psk_identities: 'List[PSKIdentity]'):
        # We create a new ClientHello from a template and add our PSK with a canary
        psk_hello    = client_hello.deepcopy()
        psk_ext_data = PreSharedKeyExtensionClient(
            offered_psks=OfferedPsks(
                identities=psk_identities,
                binders=[
                    b'\xff'*self.config.ciphersuite.length for _ in range(len(psk_identities))
                ]
            )
        )

        psk_ext = Extension(extension_type=ExtensionType.pre_shared_key, extension_data=S2.Opaque[PreSharedKeyExtensionClient](psk_ext_data))

        psk_hello.extensions.val.val.append(psk_ext)
        psk_total_length = self.config.ciphersuite.length * len(psk_identities)

        handshake = Handshake(
            msg_type=HandshakeType.client_hello,
            message=S3.Opaque[ClientHello](psk_hello)
        )


        # Truncate and check
        hello_prefix        = handshake.serialize()
        hello_prefix, check = hello_prefix[:-(psk_total_length+3)], hello_prefix[-psk_total_length:]
        assert check == b'\xff'*psk_total_length

        key         = self.config.ciphersuite.derive_secret(self.key_schedule[KeySchedule.BINDER_KEY], b'finished', b'')
        hmac        = HMAC(key, self.config.ciphersuite.hash_obj)
        verify_data = hmac.generate(self.config.ciphersuite.hash_obj.hash(hello_prefix))

        # Rebuild it with the binder
        psk_hello = client_hello.deepcopy()
        psk_ext_data.offered_psks.binders.val.val = [S1.Bytes(bytes(verify_data))]
        psk_ext = Extension(extension_type=ExtensionType.pre_shared_key, extension_data=S2.Opaque[PreSharedKeyExtensionClient](psk_ext_data))
        psk_hello.extensions.val.val.append(psk_ext)

        handshake = Handshake(
            msg_type=HandshakeType.client_hello,
            message=S3.Opaque[ClientHello](psk_hello)
        )

        return handshake



    def finished(self, finished_key: bytes):
        hmac = HMAC(finished_key, self.config.ciphersuite.hash_obj)
        verify_data = hmac.generate(self.transcript.hash())

        handshake = Handshake(
            msg_type=HandshakeType.finished,
            message=S3.Opaque[Finished](Finished(verify_data))
        )
        return handshake



    def verify_finished(self, finished_key: bytes, finished: Finished):
        hmac = HMAC(finished_key, self.config.ciphersuite.hash_obj)
        calculated_hash = hmac.generate(self.transcript.hash())

        if not RUNTIME.compare_bytes(calculated_hash, finished.verify_data.val):
            raise InvalidMACException



    def get_psk_from_ticket(self, ticket: 'NewSessionTicket'):
        return self.config.ciphersuite.hkdf_expand_label(
            secret=self.key_schedule[KeySchedule.RESUMPTION_MASTER_SECRET],
            label=b'resumption',
            context=ticket.ticket_nonce.val,
            length=self.config.ciphersuite.length
        )



    def decrypt_application_data(self, secret: bytes, ciphertext: TLSPlaintext):
        server_write_key, server_write_iv = self.get_traffic_key(secret)

        encrypted_data, header = TLSPlaintextHeader.deserialize(ciphertext.serialize())

        decrypted_record = self.config.ciphersuite.decrypt(
            key=server_write_key,
            nonce=server_write_iv ^ Bytes(self.read_seq_num).zfill(12),
            data=encrypted_data,
            aad=header.serialize()
        )

        return TLSInnerPlaintext._deserialize(decrypted_record)[1]




# A.1.  Client

#                               START <----+
#                Send ClientHello |        | Recv HelloRetryRequest
#           [K_send = early data] |        |
#                                 v        |
#            /                 WAIT_SH ----+
#            |                    | Recv ServerHello
#            |                    | K_recv = handshake
#        Can |                    V
#       send |                 WAIT_EE
#      early |                    | Recv EncryptedExtensions
#       data |           +--------+--------+
#            |     Using |                 | Using certificate
#            |       PSK |                 v
#            |           |            WAIT_CERT_CR
#            |           |        Recv |       | Recv CertificateRequest
#            |           | Certificate |       v
#            |           |             |    WAIT_CERT
#            |           |             |       | Recv Certificate
#            |           |             v       v
#            |           |              WAIT_CV
#            |           |                 | Recv CertificateVerify
#            |           +> WAIT_FINISHED <+
#            |                  | Recv Finished
#            \                  | [Send EndOfEarlyData]
#                               | K_send = handshake
#                               | [Send Certificate [+ CertificateVerify]]
#     Can send                  | Send Finished
#     app data   -->            | K_send = K_recv = application
#     after here                v
#                           CONNECTED



class TLSHandshakeClientFSM(FSM):
    def __init__(self, config: TLSConfiguration, channel: Channel):
        super().__init__()
        self.state       = TLSState(config)
        self.reply_queue = Queue()
        self.channel     = channel
        self.read_key    = None
        self.write_key   = None

        self.application_data_queue = Queue()


    def _recv_message(self):
        reply = self.reply_queue.get()

        if reply.type == ContentType.application_data:
            tls_inner = self.state.decrypt_application_data(self.read_key, reply)

            for content in tls_inner.content:
                self.reply_queue.put(TLSPlaintext(
                    type=tls_inner.type,
                    legacy_record_version=reply.legacy_record_version,
                    fragment=S2.Opaque[type(content)](content)
                ))
            
            return self._recv_message()
        
        else:
            return reply



    def _recv_handshake(self, *expected_types, frame_idx=3):
        reply     = self._recv_message()
        handshake = reply.fragment.val.val

        # TODO: Handle ChangeCipherSpec
        if reply.type == ContentType.change_cipher_spec:
            return self._recv_handshake(*expected_types, frame_idx=4)


        if reply.type != ContentType.handshake:
            raise TLSProtocolError(AlertDescription.unexpected_message, reply)

        self.log_info(f"Received handshake reply of type {handshake.msg_type}", frame_idx=frame_idx)

        if handshake.msg_type not in expected_types:
            raise TLSProtocolError(AlertDescription.unexpected_message, handshake)


        self.state.transcript.append(handshake)
        self.log_debug(f'Transcript hash: {bytes(self.state.transcript.hash().hex())}', frame_idx=frame_idx)
        return handshake
    


    def send_encrypted(self, tls_inner_plaintext):
        tls_ciphertext = self.state.encrypt_application_data(self.write_key, tls_inner_plaintext)
        self.channel.send(tls_ciphertext)


    @FSM.transition(TLSHSCState.START)
    def start(self):
        self.log_info("Sending hello")

        tls_record = self.state.client_hello()
        self.channel.send(tls_record)

        self.state.transcript.append(tls_record.fragment.val.val)
        self.state.key_schedule.process_early_secret(self.state.transcript.hash())

        
        return (TLSHSCState.WAIT_SH, (), {})



    @FSM.transition(TLSHSCState.WAIT_SH)
    def wait_sh(self):
        handshake    = self._recv_handshake(HandshakeType.server_hello)
        server_hello = handshake.message.val.val

        if server_hello.legacy_session_id_echo == HELLO_RETRY_MAGIC:
            # TODO: Handle required changes
            return (TLSHSCState.START, (), {})

        else:
            extensions = server_hello.extensions.val.val
            for ext in extensions:
                if ext.extension_type == ExtensionType.key_share:
                    server_public  = ext.extension_data.val.val.server_share.key_exchange.val
                    self.log_info(f"Processing server key share {bytes(Bytes(server_public).hex())}")
                    self.state.process_key_share(server_public)
                    self.read_key  = self.state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET]
                    self.write_key = self.state.key_schedule[KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET]

            return (TLSHSCState.WAIT_EE, (), {})



    @FSM.transition(TLSHSCState.WAIT_EE)
    def wait_ee(self):
        handshake = self._recv_handshake(HandshakeType.encrypted_extensions)
        return (TLSHSCState.WAIT_CERT_CR, (), {})


    @FSM.transition(TLSHSCState.WAIT_CERT_CR)
    def wait_cert_cr(self):
        handshake = self._recv_handshake(HandshakeType.certificate_request, HandshakeType.certificate)

        if handshake.msg_type == HandshakeType.certificate:
            self.log_info("Received certificate instead; skipping")
            return (TLSHSCState.WAIT_CV, (), {})
        
        return (TLSHSCState.WAIT_CERT, (), {})


    @FSM.transition(TLSHSCState.WAIT_CERT)
    def wait_cert(self):
        handshake = self._recv_handshake(HandshakeType.certificate)
        return (TLSHSCState.WAIT_CV, (), {})


    @FSM.transition(TLSHSCState.WAIT_CV)
    def wait_cv(self):
        handshake = self._recv_handshake(HandshakeType.certificate_verify)
        return (TLSHSCState.WAIT_FINISHED, (), {})


    @FSM.transition(TLSHSCState.WAIT_FINISHED)
    def wait_finished(self):
        handshake = self._recv_handshake(HandshakeType.finished)
        finished  = self.state.finished(self.state.key_schedule[KeySchedule.CLIENT_FINISHED])

        # TODO: MOD REMOVE
        # finished.message.val.val.verify_data = S2.GreedyBytes(bytes(Bytes(finished.message.val.val.verify_data.val) ^ Bytes(0x01).zfill(32)))
        tls_inner = TLSInnerPlaintext(
                        content=[finished],
                        type=ContentType.handshake,
                        pad_len=0
                    )
        
        self.log_info("Sending client FINISHED")
        self.send_encrypted(tls_inner)

        self.state.key_schedule.process_master_secret(self.state.transcript.hash())
        self.read_key  = self.state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0]
        self.write_key = self.state.key_schedule[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0]

        self.state.transcript.append(finished)
        self.state.key_schedule.process_resumption_secret(self.state.transcript.hash())


        return (TLSHSCState.CONNECTED, (), {})


    @FSM.transition(TLSHSCState.CONNECTED)
    def connected(self):
        reply = self.reply_queue.get()

        self.log_info(f"Received reply of type {reply.type}")

        match reply.type:
            case ContentType.change_cipher_spec:
                return (TLSHSCState.CONNECTED, (), {})
            
            case ContentType.application_data:
                tls_inner = self.state.decrypt_application_data(self.read_key, reply)
                self.state.read_seq_num += 1
                self.log_info(f"Decrypted application data ({tls_inner.content})")
                self.application_data_queue.put(tls_inner)
                return (TLSHSCState.CONNECTED, (), {})

            case _:
                raise TLSProtocolError(AlertDescription.unexpected_message, reply)
