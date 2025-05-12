from samson.auxiliary.serialization import Serializable
from samson.core.base_object import BaseObject

# https://datatracker.ietf.org/doc/html/rfc8446#section-4
S1 = Serializable[1]
S2 = Serializable[2]
S3 = Serializable[3]

def _make_tls_list(S):
    def make_tls_list_inner(type):
        return S.Opaque[S.GreedyList[type]]
    
    return make_tls_list_inner


S1_make_tls_list = _make_tls_list(S1)
S2_make_tls_list = _make_tls_list(S2)
S3_make_tls_list = _make_tls_list(S3)



class TypeSelector(BaseObject):
    def __init__(self, wrapper_cls, state_key, default=S2.Bytes):
        self.type_lut    = {}
        self.wrapper_cls = wrapper_cls
        self.state_key   = state_key
        self.default     = default


    def register(self, type_spec):
        def _wrapper(ext):
            self.type_lut[type_spec] = self.wrapper_cls[ext]
            return ext

        return _wrapper


    def selector(self, cls, state):
        return self.type_lut.get(state[self.state_key], self.default)



EXT = TypeSelector(S2.Opaque, 'extension_type')
REC = TypeSelector(S2.Opaque, 'type')
HS  = TypeSelector(S3.Opaque, 'msg_type', default=S3.Bytes)


#########################
# B.1.  Record Protocol #
#########################

# enum {
#     invalid(0),
#     change_cipher_spec(20),
#     alert(21),
#     handshake(22),
#     application_data(23),
#     heartbeat(24),  /* RFC 6520 */
#     (255)
# } ContentType;

# struct {
#     ContentType type;
#     ProtocolVersion legacy_record_version;
#     uint16 length;
#     opaque fragment[TLSPlaintext.length];
# } TLSPlaintext;

# struct {
#     opaque content[TLSPlaintext.length];
#     ContentType type;
#     uint8 zeros[length_of_padding];
# } TLSInnerPlaintext;

# struct {
#     ContentType opaque_type = application_data; /* 23 */
#     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
#     uint16 length;
#     opaque encrypted_record[TLSCiphertext.length];
# } TLSCiphertext;

class ProtocolVersion(S2.Enum[S2.UInt16]):
    TLSv10 = 0x0301
    TLSv12 = 0x0303
    TLSv13 = 0x0304


class ContentType(S2.Enum[S2.UInt8]):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23
    heartbeat = 24


class TLSPlaintext(S2):
    type: ContentType
    legacy_record_version: ProtocolVersion
    fragment: S2.Selector[REC.selector]


class TLSInnerPlaintext(S2):
    content: S2.Bytes
    type: ContentType
    zeros: S1_make_tls_list(S1.UInt8)


class TLSCiphertext(S2):
    opaque_type: ContentType
    legacy_record_version: ProtocolVersion
    encrypted_record: S2.Bytes


######################
# B.2. Alert Messages #
#######################

# enum { warning(1), fatal(2), (255) } AlertLevel;

# enum {
#     close_notify(0),
#     unexpected_message(10),
#     bad_record_mac(20),
#     decryption_failed_RESERVED(21),
#     record_overflow(22),
#     decompression_failure_RESERVED(30),
#     handshake_failure(40),
#     no_certificate_RESERVED(41),
#     bad_certificate(42),
#     unsupported_certificate(43),
#     certificate_revoked(44),
#     certificate_expired(45),
#     certificate_unknown(46),
#     illegal_parameter(47),
#     unknown_ca(48),
#     access_denied(49),
#     decode_error(50),
#     decrypt_error(51),
#     export_restriction_RESERVED(60),
#     protocol_version(70),
#     insufficient_security(71),
#     internal_error(80),
#     inappropriate_fallback(86),
#     user_canceled(90),
#     no_renegotiation_RESERVED(100),
#     missing_extension(109),
#     unsupported_extension(110),
#     certificate_unobtainable_RESERVED(111),
#     unrecognized_name(112),
#     bad_certificate_status_response(113),
#     bad_certificate_hash_value_RESERVED(114),
#     unknown_psk_identity(115),
#     certificate_required(116),
#     no_application_protocol(120),
#     (255)
# } AlertDescription;

# struct {
#     AlertLevel level;
#     AlertDescription description;
# } Alert;

class AlertLevel(S1.Enum[S1.UInt8]):
    warning = 1
    fatal = 2


class AlertDescription(S1.Enum[S1.UInt8]):
    close_notify = 0
    unexpected_message = 10
    bad_record_mac = 20
    decryption_failed_RESERVED = 21
    record_overflow = 22
    decompression_failure_RESERVED = 30
    handshake_failure = 40
    no_certificate_RESERVED = 41
    bad_certificate = 42
    unsupported_certificate = 43
    certificate_revoked = 44
    certificate_expired = 45
    certificate_unknown = 46
    illegal_parameter = 47
    unknown_ca = 48
    access_denied = 49
    decode_error = 50
    decrypt_error = 51
    export_restriction_RESERVED = 60
    protocol_version = 70
    insufficient_security = 71
    internal_error = 80
    inappropriate_fallback = 86
    user_canceled = 90
    no_renegotiation_RESERVED = 100
    missing_extension = 109
    unsupported_extension = 110
    certificate_unobtainable_RESERVED = 111
    unrecognized_name = 112
    bad_certificate_status_response = 113
    bad_certificate_hash_value_RESERVED = 114
    unknown_psk_identity = 115
    certificate_required = 116
    no_application_protocol = 120


@REC.register(ContentType.alert)
class Alert(S2):
    level: AlertLevel
    description: AlertDescription




############################
# B.3.  Handshake Protocol #
############################

# enum {
#     client_hello(1),
#     server_hello(2),
#     new_session_ticket(4),
#     end_of_early_data(5),
#     encrypted_extensions(8),
#     certificate(11),
#     certificate_request(13),
#     certificate_verify(15),
#     finished(20),
#     key_update(24),
#     message_hash(254),
#     (255)
# } HandshakeType;

class HandshakeType(S1.Enum[S1.UInt8]):
    client_hello = 1
    server_hello = 2
    new_session_ticket = 4
    end_of_early_data = 5
    encrypted_extensions = 8
    certificate = 11
    certificate_request = 13
    certificate_verify = 15
    finished = 20
    key_update = 24
    message_hash = 254

# struct {
#     HandshakeType msg_type;    /* handshake type */
#     uint24 length;             /* remaining bytes in message */
#     select (Handshake.msg_type) {
#         case client_hello:          ClientHello;
#         case server_hello:          ServerHello;
#         case end_of_early_data:     EndOfEarlyData;
#         case encrypted_extensions:  EncryptedExtensions;
#         case certificate_request:   CertificateRequest;
#         case certificate:           Certificate;
#         case certificate_verify:    CertificateVerify;
#         case finished:              Finished;
#         case new_session_ticket:    NewSessionTicket;
#         case key_update:            KeyUpdate;
#     };
# } Handshake;

@REC.register(ContentType.handshake)
class Handshake(S3):
    msg_type: HandshakeType
    message: S3.Selector[HS.selector]



#################################
# B.3.1.  Key Exchange Messages #
#################################

# struct {
#     ExtensionType extension_type;
#     opaque extension_data<0..2^16-1>;
# } Extension;

# enum {
#     server_name(0),                             /* RFC 6066 */
#     max_fragment_length(1),                     /* RFC 6066 */
#     status_request(5),                          /* RFC 6066 */
#     supported_groups(10),                       /* RFC 8422, 7919 */
#     signature_algorithms(13),                   /* RFC 8446 */
#     use_srtp(14),                               /* RFC 5764 */
#     heartbeat(15),                              /* RFC 6520 */
#     application_layer_protocol_negotiation(16), /* RFC 7301 */
#     signed_certificate_timestamp(18),           /* RFC 6962 */
#     client_certificate_type(19),                /* RFC 7250 */
#     server_certificate_type(20),                /* RFC 7250 */
#     padding(21),                                /* RFC 7685 */
#     pre_shared_key(41),                         /* RFC 8446 */
#     early_data(42),                             /* RFC 8446 */
#     supported_versions(43),                     /* RFC 8446 */
#     cookie(44),                                 /* RFC 8446 */
#     psk_key_exchange_modes(45),                 /* RFC 8446 */
#     certificate_authorities(47),                /* RFC 8446 */
#     oid_filters(48),                            /* RFC 8446 */
#     post_handshake_auth(49),                    /* RFC 8446 */
#     signature_algorithms_cert(50),              /* RFC 8446 */
#     key_share(51),                              /* RFC 8446 */
#     (65535)
# } ExtensionType;

class ExtensionType(S2.Enum[S2.UInt16]):
    server_name = 0
    max_fragment_length = 1
    status_request = 5
    supported_groups = 10
    ec_points_format = 11
    signature_algorithms = 13
    use_srtp = 14
    heartbeat = 15
    application_layer_protocol_negotiation = 16
    signed_certificate_timestamp = 18
    client_certificate_type = 19
    server_certificate_type = 20
    padding = 21
    extended_master_secret = 23
    compress_certificate = 27
    record_size_limit = 28
    delegated_credentials = 34
    pre_shared_key = 41
    early_data = 42
    supported_versions = 43
    cookie = 44
    psk_key_exchange_modes = 45
    certificate_authorities = 47
    oid_filters = 48
    post_handshake_auth = 49
    signature_algorithms_cert = 50
    key_share = 51
    encrypted_client_hello = 65037
    renegotiation_info = 65281




class Extension(S2):
    extension_type: ExtensionType
    extension_data: S2.Selector[EXT.selector]



########################################
# B.3.1.4.  Supported Groups Extension #
########################################

# enum {

#     /* Elliptic Curve Groups (ECDHE) */
#     secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
#     x25519(0x001D), x448(0x001E),

#     /* Finite Field Groups (DHE) */
#     ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
#     ffdhe6144(0x0103), ffdhe8192(0x0104),

#     /* Reserved Code Points */
#     ffdhe_private_use(0x01FC..0x01FF),
#     ecdhe_private_use(0xFE00..0xFEFF),
#     (0xFFFF)
# } NamedGroup;

# struct {
#     NamedGroup named_group_list<2..2^16-1>;
# } NamedGroupList;

class NamedGroup(S2.Enum[S2.UInt16]):
    # Elliptic Curve Groups  = ECDHE
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519 = 0x001D
    x448 = 0x001E

    # Finite Field Groups  = DHE
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    ffdhe6144 = 0x0103
    ffdhe8192 = 0x0104

    X25519MLKEM768 = 0x11EC # https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/

    # Reserved Code Points
    ffdhe_private_use = 0x01FC
    ecdhe_private_use = 0xFE00


@EXT.register(ExtensionType.supported_groups)
class NamedGroupList(S2):
    named_group_list: S2_make_tls_list(NamedGroup)




# uint16 ProtocolVersion;
# opaque Random[32];

# uint8 CipherSuite[2];    /* Cryptographic suite selector */

# struct {
#     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
#     Random random;
#     opaque legacy_session_id<0..32>;
#     CipherSuite cipher_suites<2..2^16-2>;
#     opaque legacy_compression_methods<1..2^8-1>;
#     Extension extensions<8..2^16-1>;
# } ClientHello;



# class CipherSuite(S1):
#     a: S1.UInt8
#     b: S1.UInt8

@HS.register(HandshakeType.client_hello)
class ClientHello(S1):
    legacy_version: ProtocolVersion
    random: S1.Bytes[32]
    legacy_session_id: S1.Bytes
    cipher_suites: S2_make_tls_list(S1.UInt16)
    legacy_compression_methods: S1.Opaque[S1.Bytes]
    extensions: S2_make_tls_list(Extension)


# struct {
#     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
#     Random random;
#     opaque legacy_session_id_echo<0..32>;
#     CipherSuite cipher_suite;
#     uint8 legacy_compression_method = 0;
#     Extension extensions<6..2^16-1>;
# } ServerHello;

@HS.register(HandshakeType.server_hello)
class ServerHello(S1):
    legacy_version: ProtocolVersion
    random: S1.Bytes[32]
    legacy_session_id_echo: S1.Opaque[S1.Bytes]
    cipher_suite: S2.UInt16
    legacy_compression_methods: S1.UInt8=0
    extension: S2_make_tls_list(Extension)



# struct {
#     NamedGroup group;
#     opaque key_exchange<1..2^16-1>;
# } KeyShareEntry;

class KeyShareEntry(S2):
    group: NamedGroup
    key_exchange: S2.Bytes


# struct {
#     KeyShareEntry client_shares<0..2^16-1>;
# } KeyShareClientHello;

# @register_extension(ExtensionType.key_share)
@EXT.register(ExtensionType.key_share)
class KeyShareClientHello(S2):
    client_shares: S2_make_tls_list(KeyShareEntry)



# struct {
#     NamedGroup selected_group;
# } KeyShareHelloRetryRequest;

class KeyShareHelloRetryRequest(S2):
    selected_group: NamedGroup


# struct {
#     KeyShareEntry server_share;
# } KeyShareServerHello;

class KeyShareServerHello(S2):
    server_share: KeyShareEntry



# struct {
#     uint8 legacy_form = 4;
#     opaque X[coordinate_length];
#     opaque Y[coordinate_length];
# } UncompressedPointRepresentation;

class UncompressedPointRepresentation(S2):
    legacy_form: S2.UInt8 = 4
    X: S2.Bytes
    Y: S2.Bytes



# enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;

# struct {
#     PskKeyExchangeMode ke_modes<1..255>;
# } PskKeyExchangeModes;


class PskKeyExchangeMode(S2.Enum[S2.UInt8]):
    psk_ke = 0
    psk_dhe_ke = 1

@EXT.register(ExtensionType.psk_key_exchange_modes)
class PskKeyExchangeModes(S2):
    ke_modes: S1_make_tls_list(PskKeyExchangeMode)


# struct {} Empty;

# struct {
#     select (Handshake.msg_type) {
#         case new_session_ticket:   uint32 max_early_data_size;
#         case client_hello:         Empty;
#         case encrypted_extensions: Empty;
#     };
# } EarlyDataIndication;

@EXT.register(ExtensionType.early_data)
class EarlyDataIndication(S2):
    max_early_data_size: S2.Depends[S2.UInt16, lambda context: True, S2.Null()]


# struct {
#     opaque identity<1..2^16-1>;
#     uint32 obfuscated_ticket_age;
# } PskIdentity;

# opaque PskBinderEntry<32..255>;


class PskIdentity(S2):
    identity: S2.Bytes
    obfuscated_ticket_age: S2.UInt32


# struct {
#     PskIdentity identities<7..2^16-1>;
#     PskBinderEntry binders<33..2^16-1>;
# } OfferedPsks;


class OfferedPsks(S2):
    identities: S2_make_tls_list(PskIdentity)
    binders: S2_make_tls_list(S1.Bytes)


# struct {
#     select (Handshake.msg_type) {
#         case client_hello: OfferedPsks;
#         case server_hello: uint16 selected_identity;
#     };
# } PreSharedKeyExtension;


@EXT.register(ExtensionType.pre_shared_key)
class PreSharedKeyExtensionClient(S2):
    offered_psks: OfferedPsks


class PreSharedKeyExtensionServer(S2):
    selected_identity: S2.UInt16



###############################
# B.3.1.1.  Version Extension #
###############################

# struct {
#     select (Handshake.msg_type) {
#         case client_hello:
#             ProtocolVersion versions<2..254>;

#         case server_hello: /* and HelloRetryRequest */
#             ProtocolVersion selected_version;
#     };
# } SupportedVersions;

@EXT.register(ExtensionType.supported_versions)
class SupportedVersionsClient(S1):
    versions: S1_make_tls_list(ProtocolVersion)

class SupportedVersionsServer(S1):
    selected_version: ProtocolVersion


##############################
# B.3.1.2.  Cookie Extension #
##############################

# struct {
#     opaque cookie<1..2^16-1>;
# } Cookie;

@EXT.register(ExtensionType.cookie)
class Cookie(S2):
    cookie: S2.Opaque[S2.Bytes]


###########################################
# B.3.1.3.  Signature Algorithm Extension #
###########################################

# enum {
#     /* RSASSA-PKCS1-v1_5 algorithms */
#     rsa_pkcs1_sha256(0x0401),
#     rsa_pkcs1_sha384(0x0501),
#     rsa_pkcs1_sha512(0x0601),

#     /* ECDSA algorithms */
#     ecdsa_secp256r1_sha256(0x0403),
#     ecdsa_secp384r1_sha384(0x0503),
#     ecdsa_secp521r1_sha512(0x0603),

#     /* RSASSA-PSS algorithms with public key OID rsaEncryption */
#     rsa_pss_rsae_sha256(0x0804),
#     rsa_pss_rsae_sha384(0x0805),
#     rsa_pss_rsae_sha512(0x0806),

#     /* EdDSA algorithms */
#     ed25519(0x0807),
#     ed448(0x0808),

#     /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
#     rsa_pss_pss_sha256(0x0809),
#     rsa_pss_pss_sha384(0x080a),
#     rsa_pss_pss_sha512(0x080b),

#     /* Legacy algorithms */
#     rsa_pkcs1_sha1(0x0201),
#     ecdsa_sha1(0x0203),

#     /* Reserved Code Points */
#     private_use(0xFE00..0xFFFF),
#     (0xFFFF)
# } SignatureScheme;

# struct {
#     SignatureScheme supported_signature_algorithms<2..2^16-2>;
# } SignatureSchemeList;

class SignatureScheme(S2.Enum[S2.UInt16]):
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601

    # ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806

    # EdDSA algorithms
    ed25519 = 0x0807
    ed448 = 0x0808

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809
    rsa_pss_pss_sha384 = 0x080a
    rsa_pss_pss_sha512 = 0x080b

    # Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201
    ecdsa_sha1 = 0x0203

    # Reserved Code Points
    private_use = 0xFE00


@EXT.register(ExtensionType.signature_algorithms)
class SignatureSchemeList(S2):
    supported_signature_algorithms: S2_make_tls_list(SignatureScheme)



######################################
# B.3.2.  Server Parameters Messages #
######################################


# struct {
#     Extension extensions<0..2^16-1>;
# } EncryptedExtensions;

class EncryptedExtensions(S2):
    extensions: S2_make_tls_list(Extension)


# struct {
#     opaque certificate_request_context<0..2^8-1>;
#     Extension extensions<2..2^16-1>;
# } CertificateRequest;

class CertificateRequest(S2):
    certificate_request_context: S1.Bytes
    extensions: S2_make_tls_list(Extension)



# struct {} EndOfEarlyData;
class EndOfEarlyData(S2.Null):
    pass



# opaque DistinguishedName<1..2^16-1>;

# struct {
#     DistinguishedName authorities<3..2^16-1>;
# } CertificateAuthoritiesExtension;

@EXT.register(ExtensionType.certificate_authorities)
class CertificateAuthoritiesExtension(S2):
    authorities: S2_make_tls_list(S2.Bytes)



# struct {
#     opaque certificate_extension_oid<1..2^8-1>;
#     opaque certificate_extension_values<0..2^16-1>;
# } OIDFilter;

# struct {
#     OIDFilter filters<0..2^16-1>;
# } OIDFilterExtension;

class OIDFilter(S2):
    certificate_extension_oid: S1.Bytes
    certificate_extension_values: S2.Bytes


@EXT.register(ExtensionType.oid_filters)
class OIDFilterExtension(S2):
    filters: S2_make_tls_list(OIDFilter)



###################################
# B.3.3.  Authentication Messages #
###################################



# enum {
#     X509(0),
#     RawPublicKey(2),
#     (255)
# } CertificateType;



class CertificateType(S1.Enum[S1.UInt8]):
    X509 = 0
    RawPublicKey = 2


# struct {
#     select (certificate_type) {
#         case RawPublicKey:
#         /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
#         opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

#         case X509:
#         opaque cert_data<1..2^24-1>;
#     };
#     Extension extensions<0..2^16-1>;
# } CertificateEntry;


class CertificateEntry(S2):
    certificate: S2.Bytes
    extensions: S2_make_tls_list(Extension)


# struct {
#     opaque certificate_request_context<0..2^8-1>;
#     CertificateEntry certificate_list<0..2^24-1>;
# } Certificate;

class Certificate(S2):
    certificate_request_context: S1.Bytes
    certificate_list: S3_make_tls_list(CertificateEntry)


# struct {
#     SignatureScheme algorithm;
#     opaque signature<0..2^16-1>;
# } CertificateVerify;

class CertificateVerify(S2):
    algorithm: SignatureScheme
    signature: S2.Bytes


# struct {
#     opaque verify_data[Hash.length];
# } Finished;

class Finished(S2):
    verify_data: S2.GreedyBytes



################################
# B.3.4.  Ticket Establishment #
################################

# struct {
#     uint32 ticket_lifetime;
#     uint32 ticket_age_add;
#     opaque ticket_nonce<0..255>;
#     opaque ticket<1..2^16-1>;
#     Extension extensions<0..2^16-2>;
# } NewSessionTicket;

class NewSessionTicket(S2):
    ticket_lifetime: S2.UInt32
    ticket_age_add: S2.UInt32
    ticket_nonce: S1.Bytes
    ticket: S2.Bytes
    extensions: S2_make_tls_list(Extension)


#########################
# B.3.5.  Updating Keys #
#########################

# struct {} EndOfEarlyData;

# enum {
#     update_not_requested(0), update_requested(1), (255)
# } KeyUpdateRequest;

# struct {
#     KeyUpdateRequest request_update;
# } KeyUpdate;


class KeyUpdateRequest(S2.Enum[S2.UInt8]):
    update_not_requested = 0
    update_requested = 1


class KeyUpdate(S2):
    request_update: KeyUpdateRequest



#######################
# B.4.  Cipher Suites #
#######################

# +------------------------------+-------------+
# | Description                  | Value       |
# +------------------------------+-------------+
# | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
# |                              |             |
# | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
# |                              |             |
# | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
# |                              |             |
# | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
# |                              |             |
# | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
# +------------------------------+-------------+



# https://datatracker.ietf.org/doc/html/rfc8447#section-8

# Cipher Suite Name                             | Value
# ----------------------------------------------+------------
# TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           | {0x00,0x9E}
# TLS_DHE_RSA_WITH_AES_256_GCM_SHA384           | {0x00,0x9F}
# TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       | {0xC0,0x2B}
# TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       | {0xC0,0x2C}
# TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         | {0xC0,0x2F}
# TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         | {0xC0,0x30}
# TLS_DHE_RSA_WITH_AES_128_CCM                  | {0xC0,0x9E}
# TLS_DHE_RSA_WITH_AES_256_CCM                  | {0xC0,0x9F}
# TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   | {0xCC,0xA8}
# TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | {0xCC,0xA9}
# TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     | {0xCC,0xAA}
# TLS_DHE_PSK_WITH_AES_128_GCM_SHA256           | {0x00,0xAA}
# TLS_DHE_PSK_WITH_AES_256_GCM_SHA384           | {0x00,0xAB}
# TLS_DHE_PSK_WITH_AES_128_CCM                  | {0xC0,0xA6}
# TLS_DHE_PSK_WITH_AES_256_CCM                  | {0xC0,0xA7}
# TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256         | {0xD0,0x01}
# TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384         | {0xD0,0x02}
# TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256         | {0xD0,0x05}
# TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   | {0xCC,0xAC}
# TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     | {0xCC,0xAD}

class TLSCipherSuites(S2.Enum[S1.UInt16]):
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 0x009e
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 0x009f
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0x0c2f
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xccaa
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00aa
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00ab
    TLS_DHE_PSK_WITH_AES_128_CCM = 0xc0a6
    TLS_DHE_PSK_WITH_AES_256_CCM = 0xc0a7
    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 0xd001
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 0xd002
    TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = 0xd005
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xccac
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 0xccad
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305


#############################################################
#                         RFC6066                           #
# https://www.rfc-editor.org/rfc/inline-errata/rfc6066.html #
#############################################################

# struct {
#     NameType name_type;
#     select (name_type) {
#         case host_name: HostName;
#     } name;
# } ServerName;

# enum {
#     host_name(0), (255)
# } NameType;

# opaque HostName<1..2^16-1>;

# struct {
#     ServerName server_name_list<1..2^16-1>
# } ServerNameList;

class NameType(S2.Enum[S2.UInt8]):
    host_name = 0


class ServerName(S2):
    name_type: NameType
    name: S2.Opaque[S2.Bytes]


@EXT.register(ExtensionType.server_name)
class ServerNameList(S2):
    server_name_list: S2_make_tls_list(ServerName)


# enum{
#     2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
# } MaxFragmentLength;


@EXT.register(ExtensionType.max_fragment_length)
class MaxFragmentLength(S2.Enum[S2.UInt8]):
    TWO_TO_NINETH  = 1
    TWO_TO_TENTH = 2
    TWO_TO_ELEVENTH = 3
    TWO_TO_TWELFTH = 4



# enum {
#     individual_certs(0), pkipath(1), (255)
# } CertChainType;

# struct {
#     CertChainType type;
#     URLAndHash url_and_hash_list<1..2^16-1>;
# } CertificateURL;

# struct {
#     opaque url<1..2^16-1>;
#     unint8 padding;
#     opaque SHA1Hash[20];
# } URLAndHash;


class CertChainType(S2.Enum[S2.UInt8]):
    individual_certs = 0
    pkipath = 1


class URLAndHash(S2):
    url: S2.Bytes
    padding: S2.UInt8
    hash: S2.Bytes[20]


class CertificateURL(S2):
    type: CertChainType
    url_and_hash_list: URLAndHash



# struct {
#     TrustedAuthority trusted_authorities_list<0..2^16-1>;
# } TrustedAuthorities;

# struct {
#     IdentifierType identifier_type;
#     select (identifier_type) {
#         case pre_agreed: struct {};
#         case key_sha1_hash: SHA1Hash;
#         case x509_name: DistinguishedName;
#         case cert_sha1_hash: SHA1Hash;
#     } identifier;
# } TrustedAuthority;

# enum {
#     pre_agreed(0), key_sha1_hash(1), x509_name(2),
#     cert_sha1_hash(3), (255)
# } IdentifierType;

# opaque DistinguishedName<1..2^16-1>;

class IdentifierType(S2.Enum[S2.UInt8]):
    pre_agreed = 0
    key_sha1_hash = 1
    x509_name = 2
    cert_sha1_hash = 3


class TrustedAuthority(S2):
    identifier_type: IdentifierType


class TrustedAuthorities(S2):
    trusted_authorities_list: S2_make_tls_list(TrustedAuthority)



# struct {
#     CertificateStatusType status_type;
#     select (status_type) {
#         case ocsp: OCSPStatusRequest;
#     } request;
# } CertificateStatusRequest;

# enum { ocsp(1), (255) } CertificateStatusType;

# struct {
#     ResponderID responder_id_list<0..2^16-1>;
#     Extensions  request_extensions;
# } OCSPStatusRequest;

# opaque ResponderID<1..2^16-1>;
# opaque Extensions<0..2^16-1>;


class OCSPStatusRequest(S2):
    responder_id_list: S2_make_tls_list(S2.Bytes)
    extensions: S2.Bytes


class CertificateStatusType(S2.Enum[S2.UInt8]):
    ocsp = 1


@EXT.register(ExtensionType.status_request)
class CertificateStatusRequest(S2):
    status_type: CertificateStatusType
    request: OCSPStatusRequest


# struct {
#     CertificateStatusType status_type;
#     select (status_type) {
#         case ocsp: OCSPResponse;
#     } response;
# } CertificateStatus;

# opaque OCSPResponse<1..2^24-1>;

class CertificateStatus(S2):
    status_type: CertificateStatusType
    response: S3.Bytes


########################################
#               RFC8422                #
# https://www.ietf.org/rfc/rfc8422.txt #
########################################


# enum {
#     deprecated(1..22),
#     secp256r1 (23), secp384r1 (24), secp521r1 (25),
#     x25519(29), x448(30),
#     reserved (0xFE00..0xFEFF),
#     deprecated(0xFF01..0xFF02),
#     (0xFFFF)
# } NamedCurve;

# struct {
# NamedCurve named_curve_list<2..2^16-1>
# } NamedCurveList;

class NamedCurve(S2.Enum[S2.UInt16]):
    secp256r1 = 23
    secp384r1 = 24
    secp521r1 = 25
    x25519 = 29
    x448 = 30


class NamedCurveList(S2):
    named_curve_list: S2_make_tls_list(NamedCurve)


# enum {
#     uncompressed (0),
#     deprecated (1..2),
#     reserved (248..255)
# } ECPointFormat;

# struct {
#     ECPointFormat ec_point_format_list<1..2^8-1>
# } ECPointFormatList;

class ECPointFormat(S2.Enum[S2.UInt8]):
    uncompressed = 0


@EXT.register(ExtensionType.ec_points_format)
class ECPointFormatList(S2):
    ec_point_format_list: S1_make_tls_list(ECPointFormat)



# enum {
#     deprecated (1..2),
#     named_curve (3),
#     reserved(248..255)
# } ECCurveType;

# struct {
#     opaque point <1..2^8-1>;
# } ECPoint;

# struct {
#     ECCurveType    curve_type;
#     select (curve_type) {
#         case named_curve:
#             NamedCurve namedcurve;
#     };
# } ECParameters;


class ECCurveType(S2.Enum[S1.UInt8]):
    named_curve = 3


class ECPoint(S2):
    point: S1.Bytes


class ECParameters(S2):
    curve_type: ECCurveType
    namedcurve: NamedCurve


# enum {
#     ecdsa(3),
#     ed25519(7)
#     ed448(8)
# } SignatureAlgorithm;

# select (SignatureAlgorithm) {
#     case ecdsa:
#         digitally-signed struct {
#             opaque sha_hash[sha_size];
#         };
#     case ed25519,ed448:
#         digitally-signed struct {
#             opaque rawdata[rawdata_size];
#         };
# } Signature;

# TODO: What is the actual enum size?
class SignatureAlgorithm(S2.Enum[S2.UInt8]):
    ecdsa = 3
    ed25519 = 7
    ed448 = 8


# TODO: This RFC sucks so hard. Get back to this when you can find it in the wild
# class Signature(S2):



# struct {
#     ECParameters    curve_params;
#     ECPoint         public;
# } ServerECDHParams;

#     enum {
#     ec_diffie_hellman
# } KeyExchangeAlgorithm;


# select (KeyExchangeAlgorithm) {
#     case ec_diffie_hellman:
#         ServerECDHParams    params;
#         Signature           signed_params;
# } ServerKeyExchange;


class ServerECDHParams(S2):
    curve_params: ECParameters
    public: ECPoint


# TODO: Same as above comments omg
# class KeyExchangeAlgorithm(S2.Enum):
#     ec_diffie_hellman


# class ServerKeyExchange(S2):
#     params: ServerECDHParams
#     signed_params: Signature





#########################################################
#                       RFC7301                         #
# https://www.rfc-editor.org/rfc/rfc7301.html#section-3 #
#########################################################


# enum {
#     application_layer_protocol_negotiation(16), (65535)
# } ExtensionType;

# opaque ProtocolName<1..2^8-1>;

# struct {
#     ProtocolName protocol_name_list<2..2^16-1>
# } ProtocolNameList;

@EXT.register(ExtensionType.application_layer_protocol_negotiation)
class ProtocolNameList(S2):
    protocol_name_list: S2_make_tls_list(S1.Bytes)


# enum {
#     no_application_protocol(120),
#     (255)
# } AlertDescription;



###########################################################
#                        RFC8449                          #
# https://datatracker.ietf.org/doc/html/rfc8449#section-4 #
###########################################################

# uint16 RecordSizeLimit;

@EXT.register(ExtensionType.record_size_limit)
class RecordSizeLimit(S2):
    record_size_limit: S2.UInt16



#############################################################
#                         RFC5764                           #
# https://datatracker.ietf.org/doc/html/rfc5764#section-4.1 #
#############################################################

# uint8 SRTPProtectionProfile[2];

# struct {
#     SRTPProtectionProfiles SRTPProtectionProfiles;
#     opaque srtp_mki<0..255>;
# } UseSRTPData;

# SRTPProtectionProfile SRTPProtectionProfiles<2..2^16-1>;

# SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_80 = {0x00, 0x01};
# SRTPProtectionProfile SRTP_AES128_CM_HMAC_SHA1_32 = {0x00, 0x02};
# SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_80      = {0x00, 0x05};
# SRTPProtectionProfile SRTP_NULL_HMAC_SHA1_32      = {0x00, 0x06};


class SRTPProtectionProfile(S2.Enum[S2.UInt16]):
    SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001
    SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002
    SRTP_NULL_HMAC_SHA1_80 = 0x0005
    SRTP_NULL_HMAC_SHA1_32 = 0x0006



@EXT.register(ExtensionType.use_srtp)
class UseSRTPData(S2):
    SRTPProtectionProfiles: S2_make_tls_list(SRTPProtectionProfile)
    srtp_mki: S1.Bytes



###########################################################
#                        RFC6520                          #
# https://datatracker.ietf.org/doc/html/rfc6520#section-2 #
###########################################################

# enum {
#     peer_allowed_to_send(1),
#     peer_not_allowed_to_send(2),
#     (255)
# } HeartbeatMode;

# struct {
#     HeartbeatMode mode;
# } HeartbeatExtension;

class HeartbeatMode(S2.Enum[S2.UInt8]):
    peer_allowed_to_send = 1
    peer_not_allowed_to_send = 2


@EXT.register(ExtensionType.heartbeat)
class HeartbeatExtension(S2):
    mode: HeartbeatMode


# enum {
#     heartbeat_request(1),
#     heartbeat_response(2),
#     (255)
# } HeartbeatMessageType;

class HeartbeatMessageType(S2.Enum[S2.UInt8]):
    heartbeat_request = 1
    heartbeat_response = 2


# struct {
#     HeartbeatMessageType type;
#     uint16 payload_length;
#     opaque payload[HeartbeatMessage.payload_length];
#     opaque padding[padding_length];
# } HeartbeatMessage;

class HeartbeatMessage(S2):
    type: HeartbeatMessageType
    payload: S2.Bytes
    padding: S2.GreedyBytes



###########################################################
#                        RFC8879                          #
# https://datatracker.ietf.org/doc/html/rfc8879#section-3 #
###########################################################

# enum {
#     zlib(1),
#     brotli(2),
#     zstd(3),
#     (65535)
# } CertificateCompressionAlgorithm;

# struct {
#     CertificateCompressionAlgorithm algorithms<2..2^8-2>;
# } CertificateCompressionAlgorithms;

class CertificateCompressionAlgorithm(S2.Enum[S2.UInt16]):
    zlib = 1
    brotli = 2
    zstd = 3


@EXT.register(ExtensionType.compress_certificate)
class CertificateCompressionAlgorithms(S2):
    algorithms: S1_make_tls_list(CertificateCompressionAlgorithm)


# struct {
#         CertificateCompressionAlgorithm algorithm;
#         uint24 uncompressed_length;
#         opaque compressed_certificate_message<1..2^24-1>;
# } CompressedCertificate;

class CompressedCertificate(S2):
    algorithm: CertificateCompressionAlgorithm
    uncompressed_length: S2.UInt24
    compressed_certificate_message: S3.Bytes



#################################################
#                   RFC5746                     #
# https://datatracker.ietf.org/doc/html/rfc5746 #
#################################################

# struct {
#     opaque renegotiated_connection<0..255>;
# } RenegotiationInfo;

@EXT.register(ExtensionType.renegotiation_info)
class RenegotiationInfo(S2):
    renegotiated_connection: S1.Bytes



#########################################################
#              TLS Encrypted Client Hello               #
# https://datatracker.ietf.org/doc/draft-ietf-tls-esni/ #
#########################################################

# opaque HpkePublicKey<1..2^16-1>;
# uint16 HpkeKemId;              // Defined in RFC9180
# uint16 HpkeKdfId;              // Defined in RFC9180
# uint16 HpkeAeadId;             // Defined in RFC9180
# uint16 ECHConfigExtensionType; // Defined in Section 11.3

# struct {
#     HpkeKdfId kdf_id;
#     HpkeAeadId aead_id;
# } HpkeSymmetricCipherSuite;

# struct {
#     uint8 config_id;
#     HpkeKemId kem_id;
#     HpkePublicKey public_key;
#     HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
# } HpkeKeyConfig;

# TODO: Implement HPKE and move these into Enums
class HpkeSymmetricCipherSuite(S2):
    kdf_id: S2.UInt16
    aead_id: S2.UInt16


class HpkeKeyConfig(S2):
    config_id: S2.UInt8
    kem_id: S2.UInt16
    public_key: S2.Bytes
    cipher_suites: S2_make_tls_list(HpkeSymmetricCipherSuite)


# struct {
#     ECHConfigExtensionType type;
#     opaque data<0..2^16-1>;
# } ECHConfigExtension;

# struct {
#     HpkeKeyConfig key_config;
#     uint8 maximum_name_length;
#     opaque public_name<1..255>;
#     ECHConfigExtension extensions<0..2^16-1>;
# } ECHConfigContents;

# struct {
#     uint16 version;
#     uint16 length;
#     select (ECHConfig.version) {
#         case 0xfe0d: ECHConfigContents contents;
#     }
# } ECHConfig;

class ECHConfigExtension(S2):
    type: ExtensionType
    data: S2.Bytes


class ECHConfigContents(S2):
    key_config: HpkeKeyConfig
    maximum_name_length: S2.UInt8
    public_name: S1.Bytes
    extensions: S2_make_tls_list(ECHConfigExtension)


class ECHConfig(S2):
    version: S2.UInt16
    length: S2.UInt16
    contents: ECHConfigContents



# enum {
#     encrypted_client_hello(0xfe0d), (65535)
# } ExtensionType;

# enum { outer(0), inner(1) } ECHClientHelloType;

# struct {
#     ECHClientHelloType type;
#     select (ECHClientHello.type) {
#         case outer:
#             HpkeSymmetricCipherSuite cipher_suite;
#             uint8 config_id;
#             opaque enc<0..2^16-1>;
#             opaque payload<1..2^16-1>;
#         case inner:
#             Empty;
#     };
# } ECHClientHello;


# TODO: Check actual size; spec doesn't say
class ECHClientHelloType(S2.Enum[S2.UInt8]):
    outer = 0
    inner = 1



class ECHOuterCH(S2):
    cipher_suite: HpkeSymmetricCipherSuite
    config_id: S2.UInt8
    enc: S2.Bytes
    payload: S2.Bytes


def ech_ch_selector(cls, ctx):
    if ctx['type'] == ECHClientHelloType.outer:
        return ECHOuterCH
    else:
        return S2.Null


@EXT.register(ExtensionType.encrypted_client_hello)
class ECHClientHello(S2):
    type: ECHClientHelloType
    data: S2.Selector[ech_ch_selector]



# struct {
#     ECHConfigList retry_configs;
# } ECHEncryptedExtensions;


# struct {
#     ClientHello client_hello;
#     uint8 zeros[length_of_padding];
# } EncodedClientHelloInner;


# struct {
#     opaque confirmation[8];
# } ECHHelloRetryRequest;


# enum {
#     ech_outer_extensions(0xfd00), (65535)
# } ExtensionType;

# ExtensionType OuterExtensions<2..254>;


class ECHEncryptedExtensions(S2):
    retry_configs: S2_make_tls_list(ECHConfig)


class EncodedClientHelloInner(S2):
    client_hello: ClientHello
    zeros: S2.GreedyBytes


class ECHHelloRetryRequest(S2):
    confirmation: S2.Bytes[8]



#############################################
#                 RFC9345                   #
# https://datatracker.ietf.org/doc/rfc9345/ #
#############################################

# struct {
#     uint32 valid_time;
#     SignatureScheme dc_cert_verify_algorithm;
#     opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
# } Credential;

class Credential(S2):
    valid_time: S2.UInt32
    dc_cert_verify_algorithm: SignatureScheme
    ASN1_subjectPublicKeyInfo: S3.Bytes


# struct {
#     Credential cred;
#     SignatureScheme algorithm;
#     opaque signature<1..2^16-1>;
# } DelegatedCredential;

class DelegatedCredential(S2):
    cred: Credential
    algorithm: SignatureScheme
    signature: S2.Bytes


# @register_extension(ExtensionType.delegated_credentials)
# class DelegatedCredentialsExtension(S2):
#     credentials: S2_make_tls_list(DelegatedCredential)
