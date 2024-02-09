from samson.protocols.opaque.exceptions import EnvelopeRecoveryError, ServerAuthenticationError, ClientAuthenticationError
from samson.utilities.bytes import Bytes
from samson.protocols.opaque.rfc9380 import concat
from samson.protocols.opaque.ciphersuite import OPAQUECiphersuite
from samson.protocols.opaque.messages import Messages
from samson.utilities.general import random

class OPAQUEBase(object):
    def __init__(self, ciphersuite: OPAQUECiphersuite) -> None:
        self.ciphersuite = ciphersuite
        self.messages    = Messages(ciphersuite)

    @property
    def G(self):
        return self.ciphersuite.oprf

    def CreateCleartextCredentials(self, server_public_key, client_public_key, server_identity=None, client_identity=None):
        return self.messages.CleartextCredentials(
            server_public_key=server_public_key,
            server_identity=server_identity or server_public_key,
            client_identity=client_identity or client_public_key
        )


class OPAQUERegistrationServer(OPAQUEBase):

    def CreateRegistrationResponse(self, request, server_public_key, credential_identifier, oprf_seed):
        seed = self.ciphersuite.Expand(oprf_seed, concat(credential_identifier, b"OprfKey"), self.ciphersuite.Nok)
        (oprf_key, _) = self.G.DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")

        blinded_element   = self.G.DeserializeElement(request.blinded_message)
        evaluated_element = self.G.BlindEvaluate(oprf_key, blinded_element)
        evaluated_message = self.G.SerializeElement(evaluated_element)

        response = self.messages.RegistrationResponse(evaluated_message=evaluated_message, server_public_key=server_public_key)
        return response


class OPAQUEClient(OPAQUEBase):

    def Store(self, randomized_password, server_public_key, server_identity=None, client_identity=None, envelope_nonce=None):
        envelope_nonce = envelope_nonce or random(self.ciphersuite.Nn)
        masking_key    = self.ciphersuite.Expand(randomized_password, b"MaskingKey", self.ciphersuite.Nh)
        auth_key       = self.ciphersuite.Expand(randomized_password, concat(envelope_nonce, b"AuthKey"), self.ciphersuite.Nh)
        export_key     = self.ciphersuite.Expand(randomized_password, concat(envelope_nonce, b"ExportKey"), self.ciphersuite.Nh)
        seed           = self.ciphersuite.Expand(randomized_password, concat(envelope_nonce, b"PrivateKey"), self.ciphersuite.Nseed)

        (_, client_public_key) = self.G.DeriveDiffieHellmanKeyPair(seed)

        cleartext_credentials = self.CreateCleartextCredentials(
            server_public_key,
            client_public_key,
            server_identity,
            client_identity
        )

        auth_tag = self.ciphersuite.MAC(auth_key, concat(envelope_nonce, cleartext_credentials))
        return (self.messages.Envelope(nonce=envelope_nonce, auth_tag=auth_tag), client_public_key, masking_key, export_key)


    def Recover(self, randomized_password, server_public_key, envelope, server_identity=None, client_identity=None):
        auth_key   = self.ciphersuite.Expand(randomized_password, concat(envelope.nonce, b"AuthKey"), self.ciphersuite.Nh)
        export_key = self.ciphersuite.Expand(randomized_password, concat(envelope.nonce, b"ExportKey"), self.ciphersuite.Nh)
        seed       = self.ciphersuite.Expand(randomized_password, concat(envelope.nonce, b"PrivateKey"), self.ciphersuite.Nseed)
        (client_private_key, client_public_key) = self.G.DeriveDiffieHellmanKeyPair(seed)

        cleartext_credentials = self.CreateCleartextCredentials(
            server_public_key,
            client_public_key,
            server_identity,
            client_identity
        )
        expected_tag = self.ciphersuite.MAC(auth_key, concat(envelope.nonce, cleartext_credentials))

        if envelope.auth_tag != expected_tag:
            raise EnvelopeRecoveryError

        return (client_private_key, cleartext_credentials, export_key)


    def CreateCredentialRequest(self, password, blind=None):
        (blind, blinded_element) = self.G.Blind(password, blind)
        blinded_message = self.G.SerializeElement(blinded_element)
        request = self.messages.CredentialRequest(blinded_message=blinded_message)
        return (request, blind)


    def RecoverCredentials(self, password, blind, response, server_identity=None, client_identity=None):
        evaluated_element = self.G.DeserializeElement(response.evaluated_message)

        oprf_output           = self.G.Finalize(password, blind, evaluated_element)
        stretched_oprf_output = self.ciphersuite.Stretch(oprf_output)
        randomized_password   = self.ciphersuite.Extract(b"", concat(oprf_output, stretched_oprf_output))

        masking_key                 = self.ciphersuite.Expand(randomized_password, b"MaskingKey", self.ciphersuite.Nh)
        credential_response_pad     = self.ciphersuite.Expand(masking_key, concat(response.masking_nonce, b"CredentialResponsePad"), self.ciphersuite.Npk + self.ciphersuite.Nn + self.ciphersuite.Nm)
        result                      = bytes(Bytes(credential_response_pad) ^ Bytes(response.masked_response))
        server_public_key, envelope = result[:self.ciphersuite.Npk], result[self.ciphersuite.Npk:]

        (client_private_key, cleartext_credentials, export_key) = self.Recover(
            randomized_password,
            server_public_key,
            self.messages.Envelope.deserialize(envelope)[1],
            server_identity,
            client_identity
        )

        return (client_private_key, cleartext_credentials, export_key)


class OPAQUERegistrationClient(OPAQUEClient):
    def CreateRegistrationRequest(self, password, blind=None):
        (blind, blinded_element) = self.G.Blind(password, blind)
        blinded_message = self.G.SerializeElement(blinded_element)
        
        request = self.messages.RegistrationRequest(blinded_message=blinded_message)
        return (request, blind)


    def FinalizeRegistrationRequest(self, password, blind, response, server_identity=None, client_identity=None, envelope_nonce=None):
        evaluated_element = self.G.DeserializeElement(response.evaluated_message)
        oprf_output       = self.G.Finalize(password, blind, evaluated_element)

        stretched_oprf_output = self.ciphersuite.Stretch(oprf_output)
        randomized_password   = self.ciphersuite.Extract(b"", concat(oprf_output, stretched_oprf_output))

        (envelope, client_public_key, masking_key, export_key) = self.Store(randomized_password, response.server_public_key, server_identity, client_identity, envelope_nonce=envelope_nonce)
        record = self.messages.RegistrationRecord(client_public_key=client_public_key, masking_key=masking_key, envelope=envelope)
        return (record, export_key)



class AKEClient(OPAQUEClient):
    def __init__(self, ciphersuite) -> None:
        super().__init__(ciphersuite)
        self.password = None
        self.blind    = None


    def GenerateKE1(self, password, blind=None, client_nonce=None, client_keyshare_seed=None):
        request, blind = self.CreateCredentialRequest(password, blind=blind)
        self.password  = password
        self.blind     = blind
        ke1 = self.AuthClientStart(request, client_nonce=client_nonce, client_keyshare_seed=client_keyshare_seed)
        return ke1


    def GenerateKE3(self, client_identity, server_identity, ke2):
        (client_private_key, cleartext_credentials, export_key) = self.RecoverCredentials(
            self.password,
            self.blind,
            ke2.credential_response,
            server_identity,
            client_identity
        )
        (ke3, session_key) = self.AuthClientFinalize(cleartext_credentials, client_private_key, ke2)
        return (ke3, session_key, export_key)


class AKEServer(OPAQUEBase):
    def CreateCredentialResponse(self, request, server_public_key, record, credential_identifier, oprf_seed, masking_nonce=None):
        seed = self.ciphersuite.Expand(oprf_seed, concat(credential_identifier, b"OprfKey"), self.ciphersuite.Nok)
        (oprf_key, _) = self.G.DeriveKeyPair(seed, b"OPAQUE-DeriveKeyPair")

        blinded_element   = self.G.DeserializeElement(request.blinded_message)
        evaluated_element = self.G.BlindEvaluate(oprf_key, blinded_element)
        evaluated_message = self.G.SerializeElement(evaluated_element)

        masking_nonce           = masking_nonce or random(self.ciphersuite.Nn)
        credential_response_pad = self.ciphersuite.Expand(record.masking_key, concat(masking_nonce, b"CredentialResponsePad"), self.ciphersuite.Npk + self.ciphersuite.Nn + self.ciphersuite.Nm)
        masked_response         = bytes(Bytes(credential_response_pad) ^ concat(server_public_key, record.envelope))

        response = self.messages.CredentialResponse(evaluated_message=evaluated_message, masking_nonce=masking_nonce, masked_response=masked_response)
        return response


    def GenerateKE2(self, server_private_key, server_public_key, record, credential_identifier, oprf_seed, ke1, client_identity=None, server_identity=None, masking_nonce=None, server_nonce=None, server_keyshare_seed=None):
        credential_response = self.CreateCredentialResponse(
            ke1.credential_request,
            server_public_key,
            record,
            credential_identifier,
            oprf_seed,
            masking_nonce=masking_nonce
        )

        cleartext_credentials = self.CreateCleartextCredentials(
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

        ke2 = self.messages.KE2(credential_response=credential_response, auth_response=auth_response)
        return ke2


    def ServerFinish(self, ke3):
        return self.AuthServerFinalize(ke3)

    def AuthServerFinalize(self, ke3):
        if ke3.client_mac != self.expected_client_mac:
            raise ClientAuthenticationError

        return self.session_key


class ThreeDHAKEClient(AKEClient):
    def __init__(self, ciphersuite, context) -> None:
        super().__init__(ciphersuite)
        self.context = context
        self.ke1 = None
        self.client_secret = None


    def AuthClientStart(self, credential_request, client_nonce=None, client_keyshare_seed=None):
        client_nonce         = client_nonce or random(self.ciphersuite.Nn)
        client_keyshare_seed = client_keyshare_seed or random(self.ciphersuite.Nseed)
        (client_secret, client_public_keyshare) = self.G.DeriveDiffieHellmanKeyPair(client_keyshare_seed)

        auth_request = self.messages.AuthRequest(client_nonce=client_nonce, client_public_keyshare=client_public_keyshare)
        ke1          = self.messages.KE1(credential_request=credential_request, auth_request=auth_request)

        self.client_secret = client_secret
        self.ke1 = ke1
        return ke1


    def AuthClientFinalize(self, cleartext_credentials, client_private_key, ke2):
        dh1 = self.ciphersuite.ake.DiffieHellman(self.client_secret, ke2.auth_response.server_public_keyshare)
        dh2 = self.ciphersuite.ake.DiffieHellman(self.client_secret, cleartext_credentials.server_public_key)
        dh3 = self.ciphersuite.ake.DiffieHellman(client_private_key, ke2.auth_response.server_public_keyshare)
        ikm = concat(dh1, dh2, dh3)

        preamble = self.messages.Preamble(
            context=self.context,
            client_identity=cleartext_credentials.client_identity,
            ke1=self.ke1,
            server_identity=cleartext_credentials.server_identity,
            credential_response=ke2.credential_response,
            server_nonce=ke2.auth_response.server_nonce,
            server_public_keyshare=ke2.auth_response.server_public_keyshare
        )

        Km2, Km3, session_key = self.ciphersuite.ake.DeriveKeys(ikm, preamble)
        expected_server_mac   = self.ciphersuite.MAC(Km2, self.ciphersuite.Hash(preamble))

        if ke2.auth_response.server_mac != expected_server_mac:
            raise ServerAuthenticationError

        client_mac = self.ciphersuite.MAC(Km3, self.ciphersuite.Hash(concat(preamble, expected_server_mac)))
        ke3        = self.messages.KE3(client_mac=client_mac)
        return (ke3, session_key)


class ThreeDHAKEServer(AKEServer):
    def __init__(self, ciphersuite, context) -> None:
        super().__init__(ciphersuite)
        self.context = context
        self.expected_client_mac = None
        self.session_key = None


    def AuthServerRespond(self, cleartext_credentials, server_private_key, client_public_key, ke1, credential_response, server_nonce=None, server_keyshare_seed=None):
        server_nonce         = server_nonce or random(self.ciphersuite.Nn)
        server_keyshare_seed = server_keyshare_seed or random(self.ciphersuite.Nseed)

        (server_private_keyshare, server_public_keyshare) = self.G.DeriveDiffieHellmanKeyPair(server_keyshare_seed)

        preamble = self.messages.Preamble(
            context=self.context,
            client_identity=cleartext_credentials.client_identity,
            ke1=ke1,
            server_identity=cleartext_credentials.server_identity,
            credential_response=credential_response,
            server_nonce=server_nonce,
            server_public_keyshare=server_public_keyshare
        )

        dh1 = self.ciphersuite.ake.DiffieHellman(server_private_keyshare, ke1.auth_request.client_public_keyshare)
        dh2 = self.ciphersuite.ake.DiffieHellman(server_private_key, ke1.auth_request.client_public_keyshare)
        dh3 = self.ciphersuite.ake.DiffieHellman(server_private_keyshare, client_public_key)
        ikm = concat(dh1, dh2, dh3)

        Km2, Km3, session_key = self.ciphersuite.ake.DeriveKeys(ikm, preamble)
        server_mac = self.ciphersuite.MAC(Km2, self.ciphersuite.Hash(preamble))

        self.expected_client_mac = self.ciphersuite.MAC(Km3, self.ciphersuite.Hash(concat(preamble, server_mac)))
        self.session_key = session_key

        auth_response = self.messages.AuthResponse(server_nonce=server_nonce, server_public_keyshare=server_public_keyshare, server_mac=server_mac)
        return auth_response
