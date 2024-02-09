from samson.auxiliary.serialization import Serializable

S1 = Serializable[1]
S2 = Serializable[2]

class CustomLabel(S1):
    length: S1.UInt16
    label: S1.Bytes
    context: S1.Bytes


class Messages(object):
    def __init__(self, ciphersuite) -> None:

        class CleartextCredentials(S2):
            server_public_key: S2.Bytes[ciphersuite.Npk]
            server_identity: S2.Bytes
            client_identity: S2.Bytes

        self.CleartextCredentials = CleartextCredentials


        class Envelope(S2):
            nonce: S2.Bytes[ciphersuite.Nn]
            auth_tag: S2.Bytes[ciphersuite.Nm]
        
        self.Envelope = Envelope


        class RegistrationRequest(S2):
            blinded_message: S2.Bytes[ciphersuite.Noe]

        self.RegistrationRequest = RegistrationRequest


        class RegistrationResponse(S2):
            evaluated_message: S2.Bytes[ciphersuite.Noe]
            server_public_key: S2.Bytes[ciphersuite.Npk]
        
        self.RegistrationResponse = RegistrationResponse


        class RegistrationRecord(S2):
            client_public_key: S2.Bytes[ciphersuite.Npk]
            masking_key: S2.Bytes[ciphersuite.Nh]
            envelope: Envelope
        
        self.RegistrationRecord = RegistrationRecord
            

        class AuthRequest(S2):
            client_nonce: S2.Bytes[ciphersuite.Nn]
            client_public_keyshare: S2.Bytes[ciphersuite.Npk]
        
        self.AuthRequest = AuthRequest


        class CredentialRequest(S2):
            blinded_message: S2.Bytes[ciphersuite.Noe]
        
        self.CredentialRequest = CredentialRequest


        class KE1(S2):
            credential_request: CredentialRequest
            auth_request: AuthRequest
        
        self.KE1 = KE1


        class AuthResponse(S2):
            server_nonce: S2.Bytes[ciphersuite.Nn]
            server_public_keyshare: S2.Bytes[ciphersuite.Npk]
            server_mac: S2.Bytes[ciphersuite.Nm]
        
        self.AuthResponse = AuthResponse


        class CredentialResponse(S2):
            evaluated_message: S2.Bytes[ciphersuite.Noe]
            masking_nonce: S2.Bytes[ciphersuite.Nn]
            masked_response: S2.Bytes[ciphersuite.Npk + ciphersuite.Nn + ciphersuite.Nm]
        
        self.CredentialResponse = CredentialResponse


        class KE2(S2):
            credential_response: CredentialResponse
            auth_response: AuthResponse
        
        self.KE2 = KE2


        class KE3(S2):
            client_mac: S2.Bytes[ciphersuite.Nm]
        
        self.KE3 = KE3


        class Preamble(S2):
            version: S2.Bytes[9] = b"OPAQUEv1-"
            context: S2.Bytes
            client_identity: S2.Bytes
            ke1: KE1
            server_identity: S2.Bytes
            credential_response: CredentialResponse
            server_nonce: S2.Bytes[ciphersuite.Nn]
            server_public_keyshare: S2.Bytes[ciphersuite.Npk]
        
        self.Preamble = Preamble
