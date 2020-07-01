from keyring.testing.backend import BackendBasicTests

from keyutils.backend import KeyutilsKeyringBackend
from keyutils.keys import process_keyring


class TestKeyutilsKeyringBackend(BackendBasicTests):
    def init_keyring(self):
        # The 'user' key type does not support an empty payload (== password),
        # This workaround/hack pacifies the testsuite (it uses an empty
        # password several times)
        class EmptyPayloadSubstitutionBackend(KeyutilsKeyringBackend):
            empty_payload_substitute = '\0\0\0empty payload substitute\0\0\0'

            def get_password(self, *args, **kwargs):
                password = super().get_password(*args, **kwargs)
                if password == self.empty_payload_substitute:
                    return ''
                return password

            def set_password(self, service, username, password):
                if not password:
                    password = self.empty_payload_substitute
                return super().set_password(service, username, password)

        # use the process keyring so that we do not mess the "global"
        # session keyring (alternatively, we could also join to new
        # anonymous session keyring...)
        return EmptyPayloadSubstitutionBackend(parent_keyring=process_keyring)

    def test_no_payload_encoding(self):
        """Do not perform any payload encoding/decoding"""
        keyring = KeyutilsKeyringBackend(keyring_name='foobar',
                                         parent_keyring=process_keyring,
                                         payload_encoding=None)
        service = b'ser\xffvice'
        username = b'user\xdcname'
        password = b'\xdc\0\xff\0pass\x7f'
        assert keyring.get_password(service, username) is None
        keyring.set_password(service, username, password)
        actual_password = keyring.get_password(service, username)
        assert password == actual_password
        # zap is possible
        plen = len(actual_password)
        for i in range(plen):
            actual_password[i] = 0
        assert bytes(plen) == actual_password
