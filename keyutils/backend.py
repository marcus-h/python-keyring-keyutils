"""A python-keyring backend for the kernel keyring."""

from keyring.backend import KeyringBackend
from keyring.util import properties
from keyring.errors import PasswordDeleteError

from keyutils.keys import session_keyring


class KeyutilsKeyringBackend(KeyringBackend):
    """A python-keyring backend for the kernel keyring."""
    def __init__(self, keyring_name='python-keyring-keyutils',
                 parent_keyring=session_keyring, key_type='user',
                 payload_encoding='utf-8'):
        super(KeyutilsKeyringBackend, self).__init__()
        self._keyring_name = keyring_name
        self._parent_keyring = parent_keyring
        self._key_type = key_type
        self._payload_encoding = payload_encoding

    @properties.ClassProperty
    @classmethod
    def priority(cls):
        return 1

    def _keyring(self):
        keyring = self._parent_keyring.search('keyring', self._keyring_name,
                                              missing_ok=True)
        if keyring is None:
            # hrm... this is potentially racy
            keyring = self._parent_keyring.create(self._keyring_name)
        return keyring

    def _key_id(self, service, username):
        return (self._key_type, "{}:{}".format(service, username))

    def _encode_payload(self, payload):
        if self._payload_encoding is None:
            return payload
        return payload.encode(self._payload_encoding)

    def _decode_payload(self, payload):
        if self._payload_encoding is None:
            return payload
        return payload.decode(self._payload_encoding)

    def _find_key(self, service, username, missing_ok=True):
        keyring = self._keyring()
        key_id = self._key_id(service, username)
        return keyring.search(*key_id, missing_ok=missing_ok)

    def get_password(self, service, username):
        key = self._find_key(service, username)
        if key is None:
            return None
        return self._decode_payload(key.payload())

    def set_password(self, service, username, password):
        keyring = self._keyring()
        key_id = self._key_id(service, username)
        keyring.add_key(*key_id, payload=password)

    def delete_password(self, service, username):
        key = self._find_key(service, username)
        if key is None:
            msg = "no such password: service={}, username={}".format(service,
                                                                     username)
            raise PasswordDeleteError(msg)
        key.invalidate()
