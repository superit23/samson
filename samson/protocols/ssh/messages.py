from samson.auxiliary.serialization import Serializable
S1 = Serializable[1]

# https://datatracker.ietf.org/doc/html/rfc4254

class SSHMessageType(S1.Enum[S1.UInt8]):
    SSH_MSG_GLOBAL_REQUEST            = 80
    SSH_MSG_REQUEST_SUCCESS           = 81
    SSH_MSG_REQUEST_FAILURE           = 82
    SSH_MSG_CHANNEL_OPEN              = 90
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
    SSH_MSG_CHANNEL_OPEN_FAILURE      = 92
    SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93
    SSH_MSG_CHANNEL_DATA              = 94
    SSH_MSG_CHANNEL_EXTENDED_DATA     = 95
    SSH_MSG_CHANNEL_EOF               = 96
    SSH_MSG_CHANNEL_CLOSE             = 97
    SSH_MSG_CHANNEL_REQUEST           = 98
    SSH_MSG_CHANNEL_SUCCESS           = 99
    SSH_MSG_CHANNEL_FAILURE           = 100


class ExitSignal(S1.Enum(S1.Bytes)):
    ABRT = b'ABRT'
    ALRM = b'ALRM'
    FPE  = b'FPE'
    HUP  = b'HUP'
    ILL  = b'ILL'
    INT  = b'INT'
    KILL = b'KILL'
    PIPE = b'PIPE'
    QUIT = b'QUIT'
    SEGV = b'SEGV'
    TERM = b'TERM'
    USR1 = b'USR1'
    USR2 = b'USR2'


class ChannelOpenFailureReason(S1.Enum[S1.UInt8]):
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1
    SSH_OPEN_CONNECT_FAILED              = 2
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE        = 3
    SSH_OPEN_RESOURCE_SHORTAGE           = 4

