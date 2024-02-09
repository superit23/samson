from samson.auxiliary.serialization import Serializable
from samson.utilities.bytes import Bytes
from samson.hashes.sha2 import SHA256
from samson.macs.hmac import HMAC
from samson.kdfs.hkdf import HKDF
from samson.math.general import random_int, mod_inv
from samson.protocols.opaque.rfc9380 import concat, I2OSP, CreateContextString, OPRFMode
from copy import copy

S2 = Serializable[2]
Npk = 33 # 384
Nsk = 32
Nn  = 32 # TODO
Nm  = 32
Noe = 33
Nh  = 32
Nseed = 32
Nx  = 32
Nok = 32

class CleartextCredentials(S2):
    server_public_key: S2.Bytes[Npk]
    server_identity: S2.Bytes
    client_identity: S2.Bytes


class Envelope(S2):
    nonce: S2.Bytes[Nn]
    auth_tag: S2.Bytes[Nm]


class RegistrationRequest(S2):
    blinded_message: S2.Bytes[Noe]


class RegistrationResponse(S2):
    evaluated_message: S2.Bytes[Noe]
    server_public_key: S2.Bytes[Npk]


class RegistrationRecord(S2):
    client_public_key: S2.Bytes[Npk]
    masking_key: S2.Bytes[Nh]
    envelope: Envelope
    

class AuthRequest(S2):
    client_nonce: S2.Bytes[Nn]
    client_public_keyshare: S2.Bytes[Npk]


class CredentialRequest(S2):
    blinded_message: S2.Bytes[Noe]


class KE1(S2):
    credential_request: CredentialRequest
    auth_request: AuthRequest


class AuthResponse(S2):
    server_nonce: S2.Bytes[Nn]
    server_public_keyshare: S2.Bytes[Npk]
    server_mac: S2.Bytes[Nm]


class CredentialResponse(S2):
    evaluated_message: S2.Bytes[Noe]
    masking_nonce: S2.Bytes[Nn]
    masked_response: S2.Bytes[Npk + Nn + Nm]


class KE2(S2):
    credential_response: CredentialResponse
    auth_response: AuthResponse


class KE3(S2):
    client_mac: S2.Bytes[Nm]


S1 = Serializable[1]

class CustomLabel(S1):
    length: S1.UInt16
    label: S1.Bytes
    context: S1.Bytes


class Preamble(S2):
    version: S2.Bytes[9] = b"OPAQUEv1-"
    context: S2.Bytes
    client_identity: S2.Bytes
    ke1: KE1
    server_identity: S2.Bytes
    credential_response: CredentialResponse
    server_nonce: S2.Bytes[Nn]
    server_public_keyshare: S2.Bytes[Npk]



def random(n):
    return bytes(Bytes.random(n))


def Extract(salt, ikm):
    return HKDF(SHA256(), 0).extract(salt, ikm)


def Expand(prk, info, L):
    return HKDF(SHA256(), L).expand(prk, info, L)


def MAC(key, msg):
    return HMAC(key, SHA256()).generate(msg)


def Hash(msg):
    return SHA256().hash(msg)


def Stretch(msg):
    return msg


def ExpandLabel(Secret, Label, Context, Length):
    label = CustomLabel(length=Length, label=b'OPAQUE-' + Label, context=Context)
    return Expand(Secret, bytes(label), Length)


def DeriveSecret(Secret, Label, TranscriptHash):
    return ExpandLabel(Secret, Label, TranscriptHash, Nx)



class OPRF(object):
    def __init__(self, h2c_ciphersuite_cls) -> None:
        self.contextString        = CreateContextString(OPRFMode.OPRF, b'P256-SHA256')
        self.hash_to_scalar_suite = h2c_ciphersuite_cls(DST=b'HashToScalar-' + self.contextString)
        self.hash_to_group_suite  = h2c_ciphersuite_cls(DST=b'HashToGroup-' + self.contextString)


    def RandomScalar(self):
        return random_int(self.hash_to_group_suite.E.order())

    def Blind(self, input, blind=None):
        blind = blind or self.RandomScalar()
        inputElement = self.HashToGroup(input)

        if inputElement == self.Identity():
            raise InvalidInputError

        blindedElement = blind * inputElement

        return blind, blindedElement


    def BlindEvaluate(self, skS, blindedElement):
        evaluatedElement = skS * blindedElement
        return evaluatedElement


    def HashToScalar(self, x, DST=None):
        if DST:
            suite = copy(self.hash_to_scalar_suite)
            suite.encoding.hash_to_field.DST = DST
        else:
            suite = self.hash_to_scalar_suite

        return suite.encoding.hash_to_field(x, 1)[0][0]

    def HashToGroup(self, x):
        return self.hash_to_group_suite(x)
    
    def ScalarInverse(self, s):
        return mod_inv(s, self.hash_to_group_suite.E.order())
    
    def Generator(self):
        return self.hash_to_group_suite.E.G
    
    def Identity(self):
        return self.hash_to_group_suite.E.zero
    
    def ScalarMultGen(self, x):
        return self.Generator()*x

    def SerializeElement(self, e):
        return e.serialize_compressed()

    def DeserializeElement(self, b):
        return self.hash_to_group_suite.E.decode_point(b)

    def Finalize(self, input, blind, evaluatedElement):
        N = self.ScalarInverse(blind) * evaluatedElement
        unblindedElement = self.SerializeElement(N)

        hashInput = I2OSP(len(input), 2) + input + I2OSP(len(unblindedElement), 2) + unblindedElement + b"Finalize"
        return Hash(hashInput)



class OPAQUE(object):
    def __init__(self, G) -> None:
        self.G = G


    def DeriveKeyPair(self, seed, info):
        deriveInput = seed + I2OSP(len(info), 2) + info
        counter     = 0
        skS         = None

        suite = self.G.hash_to_scalar_suite
        htf   = suite.encoding.hash_to_field

        while not skS:
            if counter > 255:
                raise DeriveKeyPairError("DeriveKeyPair: counter failure")

            # NOTE: In the RFC (https://datatracker.ietf.org/doc/html/rfc9497#name-oprfp-256-sha-256), it DOES NOT use the field
            # order like RFC9380 does. It specifically says to use the GROUP order.
            skS = Bytes(htf.expand_message(deriveInput + I2OSP(counter, 1), b'DeriveKeyPair' + self.G.contextString, htf.L)).int() % suite.E.order()
            counter += 1
        
        pkS = self.G.ScalarMultGen(skS)

        return skS, pkS


    def DeriveDiffieHellmanKeyPair(self, seed):
        skS, pkS = self.DeriveKeyPair(seed, b"OPAQUE-DeriveDiffieHellmanKeyPair")
        return skS, self.G.SerializeElement(pkS)
    

    def DiffieHellman(self, k, B):
        return self.G.SerializeElement(k*self.G.DeserializeElement(B))


    def Store(self, randomized_password, server_public_key, server_identity=None, client_identity=None, envelope_nonce=None):
        envelope_nonce = envelope_nonce or random(Nn)
        masking_key    = Expand(randomized_password, b"MaskingKey", Nh)
        auth_key       = Expand(randomized_password, concat(envelope_nonce, b"AuthKey"), Nh)
        export_key     = Expand(randomized_password, concat(envelope_nonce, b"ExportKey"), Nh)
        seed           = Expand(randomized_password, concat(envelope_nonce, b"PrivateKey"), Nseed)

        (_, client_public_key) = self.DeriveDiffieHellmanKeyPair(seed)

        cleartext_credentials = CreateCleartextCredentials(
            server_public_key,
            client_public_key,
            server_identity,
            client_identity
        )

        auth_tag = MAC(auth_key, concat(envelope_nonce, cleartext_credentials))
        return (Envelope(nonce=envelope_nonce, auth_tag=auth_tag), client_public_key, masking_key, export_key)



class OPAQUEServer(OPAQUE):

    def CreateRegistrationResponse(self, request, server_public_key, credential_identifier, oprf_seed):
        seed = Expand(oprf_seed, concat(credential_identifier, b"OprfKey"), Nok)
        (oprf_key, _) = self.DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")

        blinded_element   = self.G.DeserializeElement(request.blinded_message)
        evaluated_element = self.G.BlindEvaluate(oprf_key, blinded_element)
        evaluated_message = self.G.SerializeElement(evaluated_element)

        response = RegistrationResponse(evaluated_message=evaluated_message, server_public_key=server_public_key)
        return response


    def CreateCredentialResponse(self, request, server_public_key, record, credential_identifier, oprf_seed, masking_nonce=None):
        seed = Expand(oprf_seed, concat(credential_identifier, b"OprfKey"), Nok)
        (oprf_key, _) = self.DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")

        blinded_element   = self.G.DeserializeElement(request.blinded_message)
        evaluated_element = self.G.BlindEvaluate(oprf_key, blinded_element)
        evaluated_message = self.G.SerializeElement(evaluated_element)

        masking_nonce           = masking_nonce or random(Nn)
        credential_response_pad = Expand(record.masking_key, concat(masking_nonce, b"CredentialResponsePad"), Npk + Nn + Nm)
        masked_response         = bytes(Bytes(credential_response_pad) ^ concat(server_public_key, record.envelope))

        response = CredentialResponse(evaluated_message=evaluated_message, masking_nonce=masking_nonce, masked_response=masked_response)
        return response



class OPAQUEClient(OPAQUE):

    def Recover(self, randomized_password, server_public_key, envelope, server_identity=None, client_identity=None):
        auth_key   = Expand(randomized_password, concat(envelope.nonce, b"AuthKey"), Nh)
        export_key = Expand(randomized_password, concat(envelope.nonce, b"ExportKey"), Nh)
        seed       = Expand(randomized_password, concat(envelope.nonce, b"PrivateKey"), Nseed)
        (client_private_key, client_public_key) = self.DeriveDiffieHellmanKeyPair(seed)

        cleartext_credentials = CreateCleartextCredentials(
            server_public_key,
            client_public_key,
            server_identity,
            client_identity
        )
        expected_tag = MAC(auth_key, concat(envelope.nonce, cleartext_credentials))

        if envelope.auth_tag != expected_tag:
            raise EnvelopeRecoveryError

        return (client_private_key, cleartext_credentials, export_key)



    def CreateRegistrationRequest(self, password, blind=None):
        (blind, blinded_element) = self.G.Blind(password, blind)
        blinded_message = self.G.SerializeElement(blinded_element)
        
        request = RegistrationRequest(blinded_message=blinded_message)
        return (request, blind)


    def FinalizeRegistrationRequest(self, password, blind, response, server_identity=None, client_identity=None, envelope_nonce=None):
        evaluated_element = self.G.DeserializeElement(response.evaluated_message)
        oprf_output       = self.G.Finalize(password, blind, evaluated_element)

        stretched_oprf_output = Stretch(oprf_output)
        randomized_password   = Extract(b"", concat(oprf_output, stretched_oprf_output))

        (envelope, client_public_key, masking_key, export_key) = self.Store(randomized_password, response.server_public_key, server_identity, client_identity, envelope_nonce=envelope_nonce)
        record = RegistrationRecord(client_public_key=client_public_key, masking_key=masking_key, envelope=envelope)
        return (record, export_key)


    def CreateCredentialRequest(self, password, blind=None):
        (blind, blinded_element) = self.G.Blind(password, blind)
        blinded_message = self.G.SerializeElement(blinded_element)
        request = CredentialRequest(blinded_message=blinded_message)
        return (request, blind)


    def RecoverCredentials(self, password, blind, response, server_identity=None, client_identity=None):
        evaluated_element = self.G.DeserializeElement(response.evaluated_message)

        oprf_output           = self.G.Finalize(password, blind, evaluated_element)
        stretched_oprf_output = Stretch(oprf_output)
        randomized_password   = Extract(b"", concat(oprf_output, stretched_oprf_output))

        masking_key                 = Expand(randomized_password, b"MaskingKey", Nh)
        credential_response_pad     = Expand(masking_key, concat(response.masking_nonce, b"CredentialResponsePad"), Npk + Nn + Nm)
        result                      = bytes(Bytes(credential_response_pad) ^ Bytes(response.masked_response))
        server_public_key, envelope = result[:Npk], result[Npk:]

        (client_private_key, cleartext_credentials, export_key) = self.Recover(
            randomized_password,
            server_public_key,
            Envelope.deserialize(envelope)[1],
            server_identity,
            client_identity
        )

        return (client_private_key, cleartext_credentials, export_key)


class AKEClient(object):
    def __init__(self, opaque_client) -> None:
        self.opaque_client = opaque_client
        self.password = None
        self.blind    = None


    def GenerateKE1(self, password, blind=None, client_nonce=None, client_keyshare_seed=None):
        request, blind = self.opaque_client.CreateCredentialRequest(password, blind=blind)
        self.password  = password
        self.blind     = blind
        ke1 = self.AuthClientStart(request, client_nonce=client_nonce, client_keyshare_seed=client_keyshare_seed)
        return ke1


    def GenerateKE3(self, client_identity, server_identity, ke2):
        (client_private_key, cleartext_credentials, export_key) = self.opaque_client.RecoverCredentials(
            self.password,
            self.blind,
            ke2.credential_response,
            server_identity,
            client_identity
        )
        (ke3, session_key) = self.AuthClientFinalize(cleartext_credentials, client_private_key, ke2)
        return (ke3, session_key, export_key)


class AKEServer(object):
    def __init__(self, opaque_server) -> None:
        self.opaque_server = opaque_server

    
    def GenerateKE2(self, server_private_key, server_public_key, record, credential_identifier, oprf_seed, ke1, client_identity=None, server_identity=None, masking_nonce=None, server_nonce=None, server_keyshare_seed=None):
        credential_response = self.opaque_server.CreateCredentialResponse(
            ke1.credential_request,
            server_public_key,
            record,
            credential_identifier,
            oprf_seed,
            masking_nonce=masking_nonce
        )

        cleartext_credentials = CreateCleartextCredentials(
            server_public_key,
            record.client_public_key,
            server_identity,
            client_identity
        )

        auth_response = self.AuthServerRespond(
            cleartext_credentials,
            server_private_key,
            record.client_public_key,
            ke1,
            credential_response,
            server_nonce=server_nonce,
            server_keyshare_seed=server_keyshare_seed
        )

        ke2 = KE2(credential_response=credential_response, auth_response=auth_response)
        return ke2


    def ServerFinish(self, ke3):
        return self.AuthServerFinalize(ke3)

    def AuthServerFinalize(self, ke3):
        if ke3.client_mac != self.expected_client_mac:
            raise ClientAuthenticationError

        return self.session_key



class ThreeDH(object):

    def DeriveKeys(self, ikm, preamble):
        prk              = Extract(b"", ikm)
        handshake_secret = DeriveSecret(prk, b"HandshakeSecret", Hash(preamble))
        session_key      = DeriveSecret(prk, b"SessionKey", Hash(preamble))
        Km2              = DeriveSecret(handshake_secret, b"ServerMAC", b"")
        Km3              = DeriveSecret(handshake_secret, b"ClientMAC", b"")
        return (Km2, Km3, session_key)



class ThreeDHAKEClient(AKEClient, ThreeDH):
    def __init__(self, opaque_client, context) -> None:
        super().__init__(opaque_client)
        self.context = context
        self.ke1 = None
        self.client_secret = None


    def AuthClientStart(self, credential_request, client_nonce=None, client_keyshare_seed=None):
        client_nonce         = client_nonce or random(Nn)
        client_keyshare_seed = client_keyshare_seed or random(Nseed)
        (client_secret, client_public_keyshare) = self.opaque_client.DeriveDiffieHellmanKeyPair(client_keyshare_seed)

        auth_request = AuthRequest(client_nonce=client_nonce, client_public_keyshare=client_public_keyshare)
        ke1          = KE1(credential_request=credential_request, auth_request=auth_request)

        self.client_secret = client_secret
        self.ke1 = ke1
        return ke1


    def AuthClientFinalize(self, cleartext_credentials, client_private_key, ke2):
        dh1 = self.opaque_client.DiffieHellman(self.client_secret, ke2.auth_response.server_public_keyshare)
        dh2 = self.opaque_client.DiffieHellman(self.client_secret, cleartext_credentials.server_public_key)
        dh3 = self.opaque_client.DiffieHellman(client_private_key, ke2.auth_response.server_public_keyshare)
        ikm = concat(dh1, dh2, dh3)

        preamble = Preamble(
            context=self.context,
            client_identity=cleartext_credentials.client_identity,
            ke1=self.ke1,
            server_identity=cleartext_credentials.server_identity,
            credential_response=ke2.credential_response,
            server_nonce=ke2.auth_response.server_nonce,
            server_public_keyshare=ke2.auth_response.server_public_keyshare
        )

        Km2, Km3, session_key = self.DeriveKeys(ikm, preamble)
        expected_server_mac   = MAC(Km2, Hash(preamble))

        if ke2.auth_response.server_mac != expected_server_mac:
            raise ServerAuthenticationError

        client_mac = MAC(Km3, Hash(concat(preamble, expected_server_mac)))
        ke3        = KE3(client_mac=client_mac)
        return (ke3, session_key)


class ThreeDHAKEServer(AKEServer, ThreeDH):
    def __init__(self, opaque_server, context) -> None:
        super().__init__(opaque_server)
        self.context = context
        self.expected_client_mac = None
        self.session_key = None


    def AuthServerRespond(self, cleartext_credentials, server_private_key, client_public_key, ke1, credential_response, server_nonce=None, server_keyshare_seed=None):
        server_nonce         = server_nonce or random(Nn)
        server_keyshare_seed = server_keyshare_seed or random(Nseed)

        (server_private_keyshare, server_public_keyshare) = self.opaque_server.DeriveDiffieHellmanKeyPair(server_keyshare_seed)

        preamble = Preamble(
            context=self.context,
            client_identity=cleartext_credentials.client_identity,
            ke1=ke1,
            server_identity=cleartext_credentials.server_identity,
            credential_response=credential_response,
            server_nonce=server_nonce,
            server_public_keyshare=server_public_keyshare
        )

        dh1 = self.opaque_server.DiffieHellman(server_private_keyshare, ke1.auth_request.client_public_keyshare)
        dh2 = self.opaque_server.DiffieHellman(server_private_key, ke1.auth_request.client_public_keyshare)
        dh3 = self.opaque_server.DiffieHellman(server_private_keyshare, client_public_key)
        ikm = concat(dh1, dh2, dh3)

        Km2, Km3, session_key = self.DeriveKeys(ikm, preamble)
        server_mac = MAC(Km2, Hash(preamble))

        self.expected_client_mac = MAC(Km3, Hash(concat(preamble, server_mac)))
        self.session_key = session_key

        auth_response = AuthResponse(server_nonce=server_nonce, server_public_keyshare=server_public_keyshare, server_mac=server_mac)
        return auth_response


def CreateCleartextCredentials(server_public_key, client_public_key, server_identity=None, client_identity=None):
    return CleartextCredentials(
        server_public_key=server_public_key,
        server_identity=server_identity or server_public_key,
        client_identity=client_identity or client_public_key
    )



class ServerAuthenticationError(Exception):
    pass

class EnvelopeRecoveryError(Exception):
    pass

class InvalidInputError(Exception):
    pass

class ClientAuthenticationError(Exception):
    pass

class DeriveKeyPairError(Exception):
    pass
